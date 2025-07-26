import os
import argparse
from dotenv import load_dotenv
import time
import logging
from datetime import datetime
import re
import shutil
import tiktoken # For embedding token counting
from typing import Dict, List

# Use relative imports within the src package
from .analysis.security_analyzer import SecurityAnalyzer
from .database.vector_db import CodeVectorDatabase
from .processing.code_processor import CodeProcessor
from .reporting.report_generator import ReportGenerator
from .repository.repo_manager import RepositoryManager
from .agent_workflows.finding_verifier.workflow import verify_findings_workflow

# --- Pricing Constants (Update as needed) ---
# OpenAI text-embedding-ada-002
EMBEDDING_COST_PER_1K_TOKENS = 0.0001 
# Google Gemini 2.5 Pro Preview (gemini-2.5-pro-preview-03-25)
# Source: https://ai.google.dev/gemini-api/docs/pricing (as of Apr 2025)
# NOTE: Pricing might vary based on context window size. Using standard rate for now.
ANALYSIS_INPUT_COST_PER_1M_TOKENS_STD = 1.25 # Prompts <= 200k tokens
ANALYSIS_OUTPUT_COST_PER_1M_TOKENS_STD = 10.00 # Prompts <= 200k tokens
ANALYSIS_INPUT_COST_PER_1M_TOKENS_LARGE = 2.50 # Prompts > 200k tokens
ANALYSIS_OUTPUT_COST_PER_1M_TOKENS_LARGE = 15.00 # Prompts > 200k tokens
ANALYSIS_CONTEXT_THRESHOLD_TOKENS = 200000

# Load environment variables
load_dotenv()

class CostCalculator:
    """Helper class to manage cost calculations."""
    def __init__(self):
        self.encoder = tiktoken.get_encoding("cl100k_base") # Encoder for OpenAI embeddings

    def calculate_embedding_cost(self, code_chunks):
        """Calculate the cost of embedding code chunks using OpenAI."""
        total_tokens = 0
        for chunk in code_chunks:
            try:
                # Use page_content as the text to be embedded
                total_tokens += len(self.encoder.encode(chunk.page_content))
            except Exception as e:
                # Log error if encoding fails for a chunk, but continue counting
                logging.debug(f"Could not encode chunk to count tokens: {e} - Skipping chunk for cost calc.") 
        
        cost = (total_tokens / 1000) * EMBEDDING_COST_PER_1K_TOKENS
        logging.debug(f"Calculated embedding cost: ${cost:.4f} for {total_tokens} tokens.")
        return cost, total_tokens

    def calculate_analysis_cost(self, input_tokens, output_tokens):
        """Calculate the cost of a Gemini analysis call."""
        # Determine pricing tier based on input tokens
        if input_tokens <= ANALYSIS_CONTEXT_THRESHOLD_TOKENS:
            input_cost_rate = ANALYSIS_INPUT_COST_PER_1M_TOKENS_STD
            output_cost_rate = ANALYSIS_OUTPUT_COST_PER_1M_TOKENS_STD
        else:
            input_cost_rate = ANALYSIS_INPUT_COST_PER_1M_TOKENS_LARGE
            output_cost_rate = ANALYSIS_OUTPUT_COST_PER_1M_TOKENS_LARGE

        input_cost = (input_tokens / 1_000_000) * input_cost_rate
        output_cost = (output_tokens / 1_000_000) * output_cost_rate
        total_cost = input_cost + output_cost
        logging.debug(f"Calculated analysis cost: ${total_cost:.4f} (Input: {input_tokens} tokens, Output: {output_tokens} tokens)")
        return total_cost

class SecurityAnalysisOrchestrator:
    def __init__(self, api_key=None, track_cost=False, extra_ignore_dirs=None, max_cost=5.0, verify_exploits=False):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") # Updated env var
        if not self.api_key:
            raise ValueError("API key is required. Set GEMINI_API_KEY environment variable or pass explicitly.")
        
        self.track_cost = track_cost
        self.max_cost = max_cost
        self.verify_exploits = verify_exploits
        self.extra_ignore_dirs = extra_ignore_dirs if extra_ignore_dirs else [] # Store extra ignore dirs
        self.total_embedding_cost = 0.0
        self.total_analysis_cost = 0.0
        self.total_embedding_tokens = 0
        self.total_analysis_input_tokens = 0
        self.total_analysis_output_tokens = 0
        self.cost_calculator = CostCalculator() if self.track_cost else None
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"SecurityAnalysisOrchestrator initialized. Cost tracking: {self.track_cost}, Cost Limit: ${max_cost:.2f}, Verify Exploits: {self.verify_exploits}")
        
    def _verify_findings_via_agent(self, category: str, raw_vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Verify a list of raw vulnerabilities for a specific category using an agent workflow.
        """
        self.logger.info(f"--- Verifying LLM Findings for category '{category}' via Agent Workflow ---")
        self.logger.debug(f"Number of raw vulnerabilities received for category '{category}': {len(raw_vulnerabilities)}")

        if not hasattr(self, 'repo_manager') or not self.repo_manager:
            self.logger.error("RepositoryManager not initialized. Cannot run agent verification workflow.")
            return [dict(r, agent_verification_status="skipped_missing_repo_manager") for r in raw_vulnerabilities]
        
        if not hasattr(self, 'vector_db') or not self.vector_db:
            self.logger.error("CodeVectorDatabase not initialized. Cannot run agent verification workflow.")
            return [dict(r, agent_verification_status="skipped_missing_vector_db") for r in raw_vulnerabilities]

        verified_vulnerabilities_list = verify_findings_workflow(
            category_findings=raw_vulnerabilities,
            category_name=category,
            repo_manager=self.repo_manager,
            vector_db=self.vector_db,
            llm_api_key=self.api_key
        )
        
        self.logger.debug(f"Number of vulnerabilities after actual agent verification for category '{category}': {len(verified_vulnerabilities_list)}")
        if len(raw_vulnerabilities) != len(verified_vulnerabilities_list):
             self.logger.info(f"Agent verification for category '{category}' resulted in a change in finding count: {len(raw_vulnerabilities)} -> {len(verified_vulnerabilities_list)}")
        return verified_vulnerabilities_list
        
    def analyze_repository(self, local_path, output_dir="./reports", analyze_attack_paths: bool = False):
        """Run a complete security analysis on a repository"""
        start_time = time.time()
        self.logger.info(f"--- Starting full security analysis for {local_path} ---")
        
        # Reset costs for this run
        self.total_embedding_cost = 0.0
        self.total_analysis_cost = 0.0
        self.total_embedding_tokens = 0
        self.total_analysis_input_tokens = 0
        self.total_analysis_output_tokens = 0
        analysis_stopped_early = False # Flag to track if stopped due to cost

        # Step 1: Setup repository
        self.logger.info("--- Step 1: Setting up repository ---")
        self.repo_manager = RepositoryManager(local_path=local_path, extra_ignore_dirs=self.extra_ignore_dirs)
        try:
            repo_dir = self.repo_manager.prepare_repository()
            repo_name = os.path.basename(repo_dir)
            self.logger.debug(f"Repository ready at: {repo_dir}")
        except Exception as e:
             self.logger.debug(f"Failed to prepare repository: {e}", exc_info=True)
             return {"status": "error", "repo_name": local_path, "error": f"Repository preparation failed: {e}"}

        try:
            # Step 2: Process code into analyzable chunks
            self.logger.info("--- Step 2: Processing code ---")
            code_processor = CodeProcessor(self.repo_manager)
            code_chunks = code_processor.process_codebase()
            if not code_chunks:
                 self.logger.debug("Code processing resulted in zero chunks. Analysis may be incomplete.")
                 # Optionally decide to stop if no chunks?

            # --- Pre-Calculate and Check Embedding Cost --- 
            if self.track_cost and self.cost_calculator and code_chunks:
                # Estimate cost BEFORE making the API call
                estimated_embedding_cost, estimated_embedding_tokens = self.cost_calculator.calculate_embedding_cost(code_chunks)
                if estimated_embedding_cost > self.max_cost:
                    self.logger.debug(f"Estimated embedding cost (${estimated_embedding_cost:.4f}) exceeds the limit (${self.max_cost:.2f}). Stopping analysis before embedding.")
                    analysis_stopped_early = True
                    # Update tracked costs/tokens up to this point (which is just the estimate)
                    self.total_embedding_cost = estimated_embedding_cost
                    self.total_embedding_tokens = estimated_embedding_tokens
                    # Skip subsequent steps, go to reporting/cleanup
                    # Need to structure the try block to handle this exit
                    raise SystemExit(f"Stopping due to exceeding embedding cost limit: Estimated ${estimated_embedding_cost:.4f}")
                else:
                    # Assign the pre-calculated values if within limit
                    self.total_embedding_cost = estimated_embedding_cost
                    self.total_embedding_tokens = estimated_embedding_tokens
            # --- End Embedding Cost Check --- 

            # Step 3: Index code for efficient retrieval
            self.logger.debug("--- Step 2.5: Indexing code chunks ---")

            # --- Create unique DB path and clear if exists --- 
            db_base_dir = "./vector_dbs" # Base directory for all vector DBs
            # Sanitize repo_name to be filesystem-friendly (replace non-alphanumeric)
            safe_repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_name)
            persist_dir = os.path.join(db_base_dir, f"code_db_{safe_repo_name}")
            self.logger.debug(f"Using vector database directory: {persist_dir}")

            # Ensure the base directory exists
            os.makedirs(db_base_dir, exist_ok=True)

            # Clear this specific repo's DB if it exists (ensures fresh analysis)
            if os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Removing existing vector database for this repo: {persist_dir}")
                    shutil.rmtree(persist_dir)
                    self.logger.debug(f"Successfully removed {persist_dir}")
                except OSError as e:
                    self.logger.debug(f"Failed to remove existing vector database at {persist_dir}: {e}")
                    # Decide if we should proceed - perhaps safer to stop?
                    # For now, log error and continue, but results might be mixed.
            # --- End DB Clear --- 

            self.vector_db = CodeVectorDatabase(persist_directory=persist_dir)
            indexed_count = self.vector_db.index_code_chunks(code_chunks)
            self.logger.debug(f"{indexed_count} code chunks indexed in vector database ({persist_dir})")
            
            # Step 3: Analyze code for security issues using LLM (Multi-Step)
            self.logger.info("--- Step 3: Analyzing code with LLM ---")
            security_analyzer = SecurityAnalyzer(api_key=self.api_key)
            
            # Define security categories to analyze
            security_categories = [
                "authentication",
                # "authorization",
                # "injection",
                # "xss",
                # "data_protection",
                # "api_security",
                # "configuration",
                # "cryptography",
                # "client_side",
                # "business_logic"
            ]
            self.logger.info(f"Analyzing for categories: {', '.join(security_categories)}")
            
            # Change structure to store LLM findings per category for the correlator
            llm_findings_by_category: Dict[str, List[Dict]] = {cat: [] for cat in security_categories}
            # --- NEW: Initialize lists for attack path analysis ---
            all_vulnerabilities = []
            unique_analysis_chunks = {} # Use dict for deduplication {chunk_key: chunk_object}
            # --- End NEW ---

            for category in security_categories:
                self.logger.info(f"--- Analyzing category: {category} ---")
                
                # 5b.1: Retrieval (Large Context)
                self.logger.debug(f"Retrieving initial code chunks for {category} (n=200)...") # Increased n_results
                relevant_code_chunks = self.vector_db.retrieve_relevant_code(
                    query=f"code related to {category} implementation or security", 
                    n_results=200 # Increased n_results
                )
                self.logger.debug(f"Retrieved {len(relevant_code_chunks)} chunks for analysis.")

                if not relevant_code_chunks:
                    self.logger.info(f"No relevant code found for analysis in category {category}. Skipping.")
                    continue
                    
                # --- NEW: Add chunks to unique set for attack path analysis ---
                for chunk in relevant_code_chunks:
                    # Create a simple key (consider hashing content for robustness if needed)
                    chunk_key = (chunk.metadata.get('relative_path', ''), chunk.page_content)
                    if chunk_key not in unique_analysis_chunks:
                        # self.logger.info(f"Adding chunk to unique set: {chunk.metadata.get('relative_path', '')}")
                        unique_analysis_chunks[chunk_key] = chunk
                # --- End NEW ---

                files_involved = {chunk.metadata.get('relative_path') for chunk in relevant_code_chunks}
                self.logger.debug(f"Proceeding to analysis for {category} on {len(relevant_code_chunks)} chunks across {len(files_involved)} files.")

                # Pre-computation Check for Analysis Cost
                if self.track_cost and self.cost_calculator and relevant_code_chunks:
                    estimated_next_input_tokens = 0
                    prompt_overhead_estimate = 1000
                    try:
                        for chunk in relevant_code_chunks:
                             estimated_next_input_tokens += len(self.cost_calculator.encoder.encode(chunk.page_content))
                        estimated_next_input_tokens += prompt_overhead_estimate
                        
                        estimated_next_input_cost = self.cost_calculator.calculate_analysis_cost(estimated_next_input_tokens, 0)
                        
                        current_total_cost = self.total_embedding_cost + self.total_analysis_cost
                        projected_cost = current_total_cost + estimated_next_input_cost
                        
                        self.logger.debug(f"Checking cost limit for category '{category}': Current Total=${current_total_cost:.4f}, Est. Next Input Cost=${estimated_next_input_cost:.4f}, Projected Total=${projected_cost:.4f}, Limit=${self.max_cost:.2f}")

                        if projected_cost > self.max_cost:
                            self.logger.debug(f"Projected cost (${projected_cost:.4f}) for analyzing category '{category}' exceeds limit (${self.max_cost:.2f}). Skipping this and remaining categories.")
                            analysis_stopped_early = True
                            break

                    except Exception as e:
                         self.logger.debug(f"Error during pre-cost calculation for category '{category}': {e}. Proceeding without check.")

                if analysis_stopped_early:
                     break 

                vulnerabilities, input_tokens, output_tokens = security_analyzer.analyze_code_for_category(
                    relevant_code_chunks,
                    category
                )
                
                if self.verify_exploits:
                    self.logger.info(f"--- Verifying LLM Findings for category '{category}' via Agent Workflow ---")
                    self.logger.debug(f"Raw vulnerabilities received for category {category}: {vulnerabilities}")
                    verified_vulnerabilities = self._verify_findings_via_agent(category, vulnerabilities)
                else:
                    self.logger.info(f"--- Skipping Agent Verification for category '{category}' (verify-exploits disabled) ---")
                    verified_vulnerabilities = vulnerabilities
                
                llm_findings_by_category[category].extend(verified_vulnerabilities)
                all_vulnerabilities.extend(verified_vulnerabilities)

                if self.track_cost and self.cost_calculator and input_tokens is not None and output_tokens is not None:
                    analysis_cost_for_category = self.cost_calculator.calculate_analysis_cost(input_tokens, output_tokens)
                    self.total_analysis_cost += analysis_cost_for_category
                    self.total_analysis_input_tokens += input_tokens
                    self.total_analysis_output_tokens += output_tokens
                    self.logger.debug(f"Actual cost for category '{category}': ${analysis_cost_for_category:.4f} ({input_tokens} input, {output_tokens} output tokens)")
                elif self.track_cost:
                     self.logger.debug(f"Could not calculate actual cost for category '{category}' due to missing token counts.")

            if analysis_stopped_early:
                 self.logger.debug("LLM analysis stopped early due to projected cost exceeding limit.")
            else:    
                 raw_llm_count = sum(len(v) for v in llm_findings_by_category.values())
                 self.logger.info(f"Completed LLM analysis for all categories. Found {raw_llm_count} raw LLM findings.")
                 
            if self.track_cost:
                ap_cost_msg = ""
                self.logger.debug(f"Total LLM Analysis Cost {ap_cost_msg}: ${self.total_analysis_cost:.4f} ({self.total_analysis_input_tokens} Input / {self.total_analysis_output_tokens} Output tokens)")

            self.logger.info("--- Step 5: Generating final report ---")
            report_generator = ReportGenerator(output_dir=output_dir)
            report_result = report_generator.generate_report(
                repo_name,
                llm_findings_by_category,
            )
            
            duration = time.time() - start_time
            total_cost = self.total_embedding_cost + self.total_analysis_cost 

            # Update total findings count based on raw LLM findings sent to the report generator
            # The report generator now internally creates ConsolidatedFinding objects.
            # For the orchestrator's summary, we use the count of raw findings we sent.
            total_code_vulns = raw_llm_count
            total_all_findings = total_code_vulns

            self.logger.info(f"--- Analysis complete for {local_path} --- Duration: {duration:.2f} seconds ---")
            if analysis_stopped_early:
                 self.logger.debug("NOTE: Analysis was stopped prematurely due to cost limits.")
            self.logger.info(f"Found a total of {total_all_findings} potential security issues (from LLM analysis)")
            if self.track_cost:
                self.logger.debug(f"--- Estimated Costs ---")
                self.logger.debug(f"Embedding Cost : ${self.total_embedding_cost:.4f} ({self.total_embedding_tokens} tokens)")
                self.logger.debug(f"Analysis Cost  : ${self.total_analysis_cost:.4f} ({self.total_analysis_input_tokens} Input / {self.total_analysis_output_tokens} Output tokens)")
                self.logger.debug(f"Total Cost     : ${total_cost:.4f} (Limit: ${self.max_cost:.2f})")
                self.logger.debug(f"---------------------")
            self.logger.info(f"Reports saved to: {report_result['markdown_path']}")
            
            final_result = {
                "status": "success_partial" if analysis_stopped_early else "success",
                "repo_name": repo_name,
                "total_findings": total_all_findings,
                "report_paths": {
                    "markdown": report_result['markdown_path'],
                    "html": report_result['html_path']
                },
                "duration": duration,
                "analysis_stopped_early": analysis_stopped_early,
                "findings": []
            }
            if self.track_cost:
                final_result["total_cost"] = total_cost
                final_result["embedding_cost"] = self.total_embedding_cost
                final_result["analysis_cost"] = self.total_analysis_cost
                final_result["embedding_tokens"] = self.total_embedding_tokens
                final_result["analysis_input_tokens"] = self.total_analysis_input_tokens
                final_result["analysis_output_tokens"] = self.total_analysis_output_tokens
            
            return final_result
            
        except SystemExit as se:
            self.logger.error(f"Analysis stopped prematurely: {se}")
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Cleaning up vector database due to SystemExit: {persist_dir}")
                    shutil.rmtree(persist_dir)
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} during SystemExit: {e_rm}")

            error_result = {
                "status": "error_cost_limit", 
                "repo_name": repo_name if 'repo_name' in locals() else local_path,
                "error": str(se),
                "findings": [],
                "total_embedding_cost": self.total_embedding_cost, 
                "total_analysis_cost": self.total_analysis_cost,
                "report_paths": None, 
                "duration": 0,
                "analysis_stopped_early": True
            }
            return error_result
  
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            self.logger.error(f"Error during security analysis: {e}")
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Cleaning up vector database due to Exception: {persist_dir}")
                    shutil.rmtree(persist_dir)
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} during Exception: {e_rm}")
            
            error_result = {
                "status": "error", 
                "repo_name": repo_name if 'repo_name' in locals() else local_path,
                "error": str(e),
                "findings": [],
                "analysis_duration_seconds": duration,
                "report_paths": None,
                "analysis_stopped_early": analysis_stopped_early
            }
            if self.track_cost:
                error_result["total_embedding_cost"] = self.total_embedding_cost
                error_result["total_analysis_cost"] = self.total_analysis_cost
            return error_result
        finally:
            # Clean up the specific vector database directory for this repo after analysis,
            # UNLESS it was already cleaned up in SystemExit or Exception blocks
            # Note: persist_dir might not be defined if error occurred before its creation
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Final cleanup of vector database: {persist_dir}")
                    shutil.rmtree(persist_dir)
                    self.logger.debug(f"Successfully removed {persist_dir} in finally block")
                except FileNotFoundError:
                    self.logger.debug(f"Vector database {persist_dir} already removed or never created.")
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} in finally block: {e_rm}")

            