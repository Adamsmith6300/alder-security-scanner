#!/usr/bin/env python3

import os
import sys
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv
import tiktoken

# Add the project root to the Python path to allow absolute imports from src
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Use relative import for orchestrator when running as a module
from .orchestrator import SecurityAnalysisOrchestrator
from .repository.repo_manager import RepositoryManager
from .github_integration import create_issues_for_findings

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI-powered security analysis scanner for web applications",
        epilog="Example: python -m src.main --local-path ./my-repository"
    )
    
    parser.add_argument("--local-path", required=True, help="Local repository path to analyze")
    
    parser.add_argument("--output-dir", default="./reports", 
                        help="Directory to save reports (default: ./reports)")
    
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    parser.add_argument("--extra-ignore-dirs", type=str, default="", 
                        help="Comma-separated list of additional directory names to ignore (e.g., 'data,tmp,specific_folder')")
    
    parser.add_argument("--max-tokens", type=int, default=5000000,
                        help="Maximum number of tokens allowed for analysis (default: 5000000)")
    
    parser.add_argument("--max-cost", type=float, default=5.0,
                        help="Maximum total cost allowed for LLM API calls in USD (default: 5.0)")
    
    parser.add_argument("--verify-exploits", action="store_true", default=False,
                        help="Enable Agent Verification workflow to verify and enrich LLM findings (default: False)")
    
    return parser.parse_args()

def count_codebase_tokens(local_path, logger, extra_ignore_dirs=None):
    """
    Count the total number of tokens in the codebase using tiktoken.
    Respects repo_manager exclusions.
    
    Args:
        local_path: Path to the repository to analyze
        logger: Logger instance for output
        extra_ignore_dirs (list, optional): Additional directory names to ignore.
        
    Returns:
        int: Total token count across all files
    """
    logger.info("Counting tokens in codebase...")
    
    try:
        repo_manager = RepositoryManager(local_path=local_path, extra_ignore_dirs=extra_ignore_dirs)
        repo_manager.prepare_repository()
        
        file_paths = repo_manager.get_file_paths()
        encoder = tiktoken.get_encoding("cl100k_base")
        total_tokens = 0
        processed_files = 0
        skipped_files = 0
        
        for file_path in file_paths:
            try:
                if file_path.endswith(".spec.ts") or file_path.endswith(".fixtures.ts"):
                    skipped_files += 1
                    continue
                
                with open(file_path, 'rb') as f:
                    try:
                        content = f.read().decode('utf-8', errors='replace')
                        file_tokens = len(encoder.encode(content))
                        total_tokens += file_tokens
                        processed_files += 1
                        
                        if processed_files % 100 == 0:
                            logger.debug(f"Processed {processed_files} files. Current token count: {total_tokens}")
                            
                    except Exception as e:
                        logger.debug(f"Error processing file {file_path}: {str(e)}")
                        skipped_files += 1
                        
            except Exception as e:
                logger.debug(f"Error opening file {file_path}: {str(e)}")
                skipped_files += 1
                
        logger.info(f"Token counting complete. Total tokens: {total_tokens:,} across {processed_files} files ({skipped_files} files skipped)")
        return total_tokens
        
    except Exception as e:
        logger.error(f"Error counting tokens")
        return -1

def main():
    """Main entry point for the security analysis agent"""
    args = parse_arguments()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)

    logger.info("--- Alder AI Security Scanner Initializing ---")
    load_dotenv()

    github_token = os.getenv("GITHUB_TOKEN")
    github_repository_slug = os.getenv("GITHUB_REPOSITORY")
    create_issues_env = os.getenv("INPUT_CREATE_ISSUES", "false")
    should_create_issues = create_issues_env.lower() == 'true'

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    if not GOOGLE_API_KEY or GOOGLE_API_KEY == "":
        logger.error("GOOGLE_API_KEY environment variable not found.")
        return 1
        
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key or openai_api_key == "":
        logger.error("OPENAI_API_KEY environment variable not found.")
        return 1
    
    try:
        extra_dirs_to_ignore = [d.strip() for d in args.extra_ignore_dirs.split(',') if d.strip()] if args.extra_ignore_dirs else []

        token_count = count_codebase_tokens(args.local_path, logger, extra_ignore_dirs=extra_dirs_to_ignore)
        if token_count < 0: 
            logger.error("Unable to count tokens in the codebase. Analysis cannot proceed.")
            return 1
        elif token_count > args.max_tokens:
            logger.error(f"Analysis rejected: Codebase contains {token_count:,} tokens, which exceeds the limit of {args.max_tokens:,}.")
            return 1
        else: 
            logger.info(f"Codebase contains {token_count:,} tokens, which is within the limit of {args.max_tokens:,}. Proceeding with analysis.")
        
        orchestrator = SecurityAnalysisOrchestrator(
            api_key=GOOGLE_API_KEY, 
            track_cost=args.verbose,
            extra_ignore_dirs=extra_dirs_to_ignore,
            max_cost=args.max_cost,
            verify_exploits=args.verify_exploits
        )
        
        options = {
            "output_dir": args.output_dir
        }
        
        start_time = datetime.now()
        logger.info(f"Starting security analysis at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        output_dir = options.pop("output_dir", "./reports")
        result = orchestrator.analyze_repository(
            local_path=args.local_path,
            output_dir=output_dir,
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        if result["status"] == "success":
            logger.info(f"\n✅ Analysis completed successfully for {result['repo_name']}")
            logger.info(f"Found {result['total_findings']} security issues")
            logger.info(f"Reports saved to:")
            for format, path in result['report_paths'].items():
                logger.info(f"  - {format.capitalize()}: {path}")
            logger.info(f"Analysis took {duration:.2f} seconds")
            if "total_cost" in result: 
                logger.debug(f"Estimated LLM API Cost: ${result['total_cost']:.4f}")

            if should_create_issues:
                logger.info("Create issues feature is enabled. Attempting to create GitHub issues for findings.")
                findings_for_issues = result.get("findings", [])
                if findings_for_issues:
                    if github_token and github_repository_slug:
                        try:
                            logger.info(f"Calling create_issues_for_findings for {len(findings_for_issues)} findings.")
                            create_issues_for_findings(
                                findings_list=findings_for_issues,
                                github_token=github_token,
                                repo_slug=github_repository_slug,
                                logger=logger,
                                gemini_api_key=GOOGLE_API_KEY
                            )
                        except Exception as e:
                            logger.error(f"An unexpected error occurred during the GitHub issue creation process: {e}", exc_info=True)
                    else:
                        logger.warning("Cannot create GitHub issues: GITHUB_TOKEN or GITHUB_REPOSITORY environment variables are missing.")
                else:
                    logger.info("No findings were reported by the analysis, so no GitHub issues to create.")
            else:
                logger.info("Create issues feature is not enabled. Skipping GitHub issue creation.")

            return 0
        else:
            logger.error(f"\n❌ Analysis failed for {result['repo_name']}")
            return 1
            
    except KeyboardInterrupt:
        logger.info("\nAnalysis cancelled by user.")
        return 130
        
    except Exception as e:
        logger.exception(f"An unexpected error occurred during analysis: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
