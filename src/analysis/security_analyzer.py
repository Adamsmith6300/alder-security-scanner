# Remove Anthropic, import google.generativeai
import google.generativeai as genai
import json
import logging
import re
import tiktoken # Added for token counting
import time # Added for retry delay

logger = logging.getLogger(__name__)

from google.generativeai.types import FunctionDeclaration, Tool

# Define the schema for the report_vulnerability tool
report_vulnerability_func = FunctionDeclaration(
    name="report_vulnerability",
    description="Report a security vulnerability found in the code",
    parameters={
        "type": "object",
        "properties": {
            "vulnerability_type": {
                "type": "string",
                "description": "The type of vulnerability found"
            },
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": "The severity of the vulnerability"
            },
            "affected_files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List containing ONLY the relative path(s) to the affected file(s)"
            },
            "line_number": {
                "type": "integer",
                "description": "The primary starting line number within the file where the vulnerability occurs."
            },
            "description": {
                "type": "string",
                "description": "Detailed description of the vulnerability"
            },
            "code_snippet": {
                "type": "string",
                "description": "Relevant **exact** code snippet (max 10 lines) showing the vulnerability, starting from the line_number provided."
            },
            "recommendation": {
                "type": "string", 
                "description": "Detailed recommendation for fixing the vulnerability"
            },
            "cwe_id": {
                "type": "string",
                "description": "CWE ID if applicable (e.g., CWE-79)"
            }
        },
        "required": ["vulnerability_type", "severity", "affected_files", "line_number", "description", "code_snippet", "recommendation"]
    }
)

# Define the schema for the report_attack_path tool
report_attack_path_func = FunctionDeclaration(
    name="report_attack_path",
    description="Report a potential attack path chaining multiple vulnerabilities.",
    parameters={
        "type": "object",
        "properties": {
            "path_name": {
                "type": "string",
                "description": "A concise, descriptive name for the attack path (e.g., 'Unvalidated Redirect to XSS')."
            },
            "description": {
                "type": "string",
                "description": "A step-by-step explanation of how the vulnerabilities are chained together in this attack path."
            },
            "involved_vulnerabilities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List identifying the vulnerabilities involved in the chain (e.g., using 'Type @ File:Line')."
            },
            "overall_severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low", "Informational"],
                "description": "The estimated overall severity of the successfully executed attack path."
            },
            "recommendation": {
                "type": "string",
                "description": "Recommendation for breaking the attack chain (e.g., fixing a specific vulnerability in the path)."
            }
        },
        "required": ["path_name", "description", "involved_vulnerabilities", "overall_severity", "recommendation"]
    }
)


class SecurityAnalyzer:
    TOKENIZER_MODEL_NAME = "cl100k_base"  # Standard tokenizer
    MAX_TOKENS_PER_BATCH = 40000      # Max tokens for the entire prompt in one API call
    MAX_API_RETRIES = 3               # Max number of retries for an API call (total attempts = MAX_API_RETRIES + 1)
    INITIAL_API_BACKOFF_SECONDS = 2.0 # Initial delay for retries

    def __init__(self, api_key, model="models/gemini-2.5-pro-preview-03-25"): 
        genai.configure(api_key=api_key)
        self.model_name = model 
        self.tools = [Tool(function_declarations=[report_vulnerability_func, report_attack_path_func])]
        self.safety_settings = { 
            "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
            "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
            "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
            "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
        }
        self.tool_config = {"function_calling_config": "AUTO"}
        
        self.model = genai.GenerativeModel(
            model_name=self.model_name,
            safety_settings=self.safety_settings,
            tools=self.tools,
            tool_config=self.tool_config
        )
        try:
            self.tokenizer = tiktoken.get_encoding(self.TOKENIZER_MODEL_NAME)
        except Exception as e:
            logger.warning(f"Could not initialize tiktoken tokenizer with {self.TOKENIZER_MODEL_NAME}: {e}. Token counting for batching may be inaccurate. Using fallback.")
            self.tokenizer = None

    def get_token_count(self, text: str) -> int:
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        # Fallback if tokenizer failed - very rough estimate based on characters
        return len(text) // 3 # Adjusted fallback, char count can be misleading

    def _process_api_batch(self, prompt: str, category: str) -> tuple[list, int | None, int | None]:
        """Sends a single batch to the Gemini API and parses the response, with retries."""
        vulnerabilities = []
        input_tokens_for_batch = None
        output_tokens_for_batch = None
        
        actual_tokens_for_this_prompt = self.get_token_count(prompt)
        logger.debug(f"[Analysis] Preparing to send batch for category '{category}'. Actual prompt tokens: {actual_tokens_for_this_prompt}")
        if actual_tokens_for_this_prompt > self.MAX_TOKENS_PER_BATCH * 1.1: # 10% margin
            logger.warning(f"[Analysis] Prompt for category '{category}' with {actual_tokens_for_this_prompt} tokens significantly exceeds MAX_TOKENS_PER_BATCH ({self.MAX_TOKENS_PER_BATCH}). This might lead to errors. Prompt starts: {prompt[:500]}...")
        # else: # Removed this else to always log the truncated prompt for debugging if needed
        # logger.debug(f"[Analysis] Prompt for batch (first 500 chars): {prompt[:500]}...")

        api_response_obj = None # Stores the successful response object from API

        for attempt in range(self.MAX_API_RETRIES + 1):
            try:
                if attempt > 0: # If this is a retry
                    delay = self.INITIAL_API_BACKOFF_SECONDS * (2 ** (attempt - 1)) # Exponential backoff (2^0, 2^1, 2^2 for attempts 1,2,3 after initial fail)
                    logger.info(f"[Analysis] Retrying Gemini API call for category '{category}' (batch). Attempt {attempt + 1}/{self.MAX_API_RETRIES + 1}. Waiting {delay:.1f}s.")
                    time.sleep(delay)
                else:
                    logger.info(f"[Analysis] Attempting Gemini API call for category '{category}' (batch). Attempt {attempt + 1}/{self.MAX_API_RETRIES + 1}.")

                # Log a truncated version of the prompt to avoid overly verbose logs
                truncated_prompt_log = prompt[:1000] + "... (prompt truncated for log)" if len(prompt) > 1000 else prompt
                logger.debug(f"[Analysis] Sending Prompt (length {len(prompt)}, attempt {attempt+1}): {truncated_prompt_log}")
                
                api_response_obj = self.model.generate_content(prompt)
                
                # Log the raw response (user's original logging point)
                # Consider summarizing this if responses are very large and causing log bloat
                logger.debug(f"[Analysis] Response from Gemini (attempt {attempt+1}): {api_response_obj}") 
                logger.debug(f"[Analysis] Gemini API call successful for category: {category} (batch attempt {attempt + 1})")
                break # Success, exit retry loop

            except Exception as e: # Catch a broad exception for retrying API call
                logger.warning(f"[Analysis] Gemini API call failed for category {category} (batch attempt {attempt + 1}/{self.MAX_API_RETRIES + 1}). Error type: {type(e).__name__}, Error: {e}")
                if attempt >= self.MAX_API_RETRIES:
                    logger.error(f"[Analysis] Max retries ({self.MAX_API_RETRIES + 1}) reached for category {category} (batch). API call failed permanently after {type(e).__name__}: {e}")
                    api_response_obj = None # Ensure api_response_obj is None if all retries fail
                    break # Exit loop, all retries failed
                # Loop will continue for the next retry attempt
        
        # Process the api_response_obj if it was successful (i.e., not None)
        if api_response_obj:
            try:
                # Extract Token Counts
                if api_response_obj.usage_metadata:
                    input_tokens_for_batch = api_response_obj.usage_metadata.prompt_token_count
                    output_tokens_for_batch = api_response_obj.usage_metadata.candidates_token_count
                    logger.debug(f"[Analysis] Tokens for category '{category}' (batch): Input={input_tokens_for_batch}, Output={output_tokens_for_batch}")
                else:
                     logger.debug(f"[Analysis] usage_metadata not found in Gemini response for category '{category}' (batch). Token counts unavailable.")
            except AttributeError:
                logger.debug(f"[Analysis] Could not retrieve token usage attributes from usage_metadata for category '{category}' (batch).")
            except Exception as e:
                logger.debug(f"[Analysis] Error extracting token counts for category '{category}' (batch): {e}")

            # Extract tool calls (function calls in Gemini terminology)
            if api_response_obj.candidates and api_response_obj.candidates[0].content.parts:
                logger.debug(f"[Analysis] Processing {len(api_response_obj.candidates[0].content.parts)} parts from Gemini response for category {category} (batch)")
                for part in api_response_obj.candidates[0].content.parts:
                    if part.function_call and part.function_call.name == 'report_vulnerability':
                        logger.debug(f"[Analysis] Found report_vulnerability function call (batch)")
                        try:
                            vulnerability = dict(part.function_call.args)
                            vulnerabilities.append(vulnerability)
                            logger.debug(f"[Analysis] Successfully extracted vulnerability: {vulnerability.get('vulnerability_type', 'N/A')} (batch)")
                        except Exception as e:
                            logger.debug(f"[Analysis] Error processing function call arguments for category {category} (batch): {e}")
                            logger.debug(f"[Analysis] Faulty arguments: {part.function_call.args} (batch)")
            else:
                # Check for finish_reason and text as per original logic if no parts are found
                finish_reason_text = "N/A"
                if api_response_obj.candidates and len(api_response_obj.candidates) > 0:
                    finish_reason_text = api_response_obj.candidates[0].finish_reason
                
                if finish_reason_text != "STOP":
                     logger.debug(f"[Analysis] Gemini response potentially blocked or incomplete for category '{category}' (batch). Finish Reason: {finish_reason_text}")
                else:
                    text_response_content = "N/A"
                    try:
                        text_response_content = api_response_obj.text
                    except Exception: 
                        pass 
                    logger.debug(f"[Analysis] No function calls or valid parts found in Gemini response for category: {category} (batch). Text response: {text_response_content if text_response_content else '(empty or not available)'}")
        
        else: # api_response_obj is None (all retries failed or an immediate non-retriable error)
            logger.error(f"[Analysis] No valid response received from Gemini API after all attempts for category {category} (batch). Vulnerabilities for this batch will be empty.")

        if not vulnerabilities:
             logger.debug(f"[Analysis] No vulnerabilities reported by Gemini for category: {category} (batch after processing response)")
        else:
             logger.debug(f"[Analysis] Extracted {len(vulnerabilities)} vulnerabilities for category: {category} (batch after processing response)")
            
        return vulnerabilities, input_tokens_for_batch, output_tokens_for_batch

    def analyze_code_for_category(self, code_chunks, category):
        """Analyze specific code chunks deeply for vulnerabilities using Gemini, processing in batches."""
        all_vulnerabilities = []
        cumulative_input_tokens = 0
        cumulative_output_tokens = 0

        current_batch_chunks_to_format = []  # List of raw chunk objects for the current batch
        idx = 0
        while idx < len(code_chunks):
            chunk = code_chunks[idx]
            
            potential_batch_chunks = current_batch_chunks_to_format + [chunk]
            potential_context_str = self._format_code_for_analysis(potential_batch_chunks)
            potential_full_prompt_str = self._create_security_prompt(category, potential_context_str)
            potential_batch_total_tokens = self.get_token_count(potential_full_prompt_str)

            process_current_batch = False

            if potential_batch_total_tokens <= self.MAX_TOKENS_PER_BATCH:
                current_batch_chunks_to_format.append(chunk)
                idx += 1
                if idx == len(code_chunks): 
                    process_current_batch = True 
            else: 
                if not current_batch_chunks_to_format:
                    logger.warning(
                        f"Chunk from file {chunk.metadata.get('relative_path', 'N/A')} (content length {len(chunk.page_content)}) "
                        f"with prompt overhead results in {potential_batch_total_tokens} tokens, "
                        f"exceeding MAX_TOKENS_PER_BATCH ({self.MAX_TOKENS_PER_BATCH}). Skipping this chunk."
                    )
                    idx += 1 
                else:
                    process_current_batch = True
            
            if process_current_batch and current_batch_chunks_to_format:
                logger.info(f"Processing batch of {len(current_batch_chunks_to_format)} chunks for category '{category}'.")
                context_for_this_batch = self._format_code_for_analysis(current_batch_chunks_to_format)
                prompt_for_this_batch = self._create_security_prompt(category, context_for_this_batch)
                
                batch_vulns, batch_in_tokens, batch_out_tokens = self._process_api_batch(prompt_for_this_batch, category)
                
                all_vulnerabilities.extend(batch_vulns)
                if batch_in_tokens:
                    cumulative_input_tokens += batch_in_tokens
                if batch_out_tokens:
                    cumulative_output_tokens += batch_out_tokens
                
                current_batch_chunks_to_format = [] 

        logger.info(f"Finished processing all batches for category '{category}'. Total vulnerabilities found: {len(all_vulnerabilities)}. Total input tokens: {cumulative_input_tokens}. Total output tokens: {cumulative_output_tokens}.")
        return all_vulnerabilities, cumulative_input_tokens, cumulative_output_tokens
    
    def _format_code_for_analysis(self, code_chunks):
        """Format code chunks for Gemini analysis."""
        formatted_chunks = []
        
        for i, chunk in enumerate(code_chunks):
            content = chunk.page_content
            metadata = chunk.metadata
            
            formatted_chunk = f"""File: {metadata['relative_path']}
Language: {metadata['language']}
---
{content}
---
"""
            formatted_chunks.append(formatted_chunk)
            
        return "\n\n".join(formatted_chunks)
    
    def _create_security_prompt(self, category, context):
        """Create a specialized prompt for the security analysis using Gemini."""
        category_prompts = {
            "authentication": """
Analyze the provided code for all authentication vulnerabilities. Focus specifically on:
1.  **Weak Authentication:** Are there hardcoded credentials, default passwords, lack of rate limiting on logins, easily guessable secrets, or absence of account lockout mechanisms after repeated failed login attempts?
2.  **Credential Storage:** Are passwords or secrets stored insecurely (e.g., plain text, weak hashing like MD5/SHA1)? Look for hashing implementations. For Java, check for proper use of BCrypt, PBKDF2, or Argon2. For other languages, check for use of modern, salted, adaptive hashing functions (e.g., bcrypt, scrypt, Argon2, PBKDF2 with sufficient iterations).
3.  **Session Management:** Are session tokens generated securely? Are they vulnerable to fixation (e.g., session ID not regenerated after login)? Is logout functionality properly implemented (token invalidation)? Check token storage (localStorage vs secure cookies). Are session cookies configured with `HttpOnly`, `Secure`, and appropriate `SameSite` attributes? Are session timeout mechanisms properly configured and enforced on the server-side? For Java web apps, examine HttpSession usage and JSESSIONID handling.
4.  **Password Reset:** Is the password reset mechanism secure? Does it rely on guessable tokens or leak information?
5.  **MFA/Authorization Checks:** Are critical actions protected by appropriate authorization checks? Is MFA implemented correctly if present? (Note: Authorization aspects will be covered more deeply in the authorization category, but note missing auth immediately following authN here).
6.  **JWT Security:** For Java applications using JWT, check for proper signature verification, algorithm confusion attacks (alg=none), secure key management, use of weak secrets or keys for signing, and missing `exp` (expiration) claims or improper validation of `nbf` (not before) and `iat` (issued at) claims.
7.  **Spring Security Configuration:** If using Spring Security, examine configuration for common misconfigurations like disabled CSRF protection, overly permissive access rules.
8.  **Configuration Files:** Examine security-related configuration files (e.g., `web.xml`, Spring Security configurations, `shiro.ini`) that define authentication policies, as vulnerabilities may stem from misconfigurations described in these files, even if the code chunk itself is application logic.


For EVERY vulnerability found, use the `report_vulnerability` tool. Be precise about the affected file and code.
""",
            "injection": """
Analyze the provided code for injection vulnerabilities. Examine these specific areas carefully:
1.  **SQL Injection:** Look for user-controlled input used directly in SQL queries constructed with string formatting or concatenation. Check ORM usage for potential vulnerabilities (e.g., raw SQL execution with unsanitized input). For Java, examine JDBC PreparedStatement usage, Hibernate HQL/JPQL queries, and MyBatis dynamic SQL.
2.  **Command Injection:** Identify any instances where user input might be passed to shell commands or OS execution functions (e.g., `os.system`, `subprocess.run` with `shell=True`, Java's `Runtime.exec()`, `ProcessBuilder`).
3.  **Cross-Site Scripting (XSS):** Check if user input is reflected in HTML output without proper sanitization or escaping. Look for use of `dangerouslySetInnerHTML` or similar functions in frontend code. Examine template engines for auto-escaping configurations. For Java web apps, check JSP/JSF output without escaping.
4.  **Server-Side Template Injection (SSTI):** If template engines are used (e.g., Jinja2, Handlebars, Freemarker, Velocity), check if user input can influence template structure or execute directives.
5.  **LDAP Injection:** For Java applications, check LDAP query construction with user input.
6.  **XML/XXE Injection:** Look for XML parsing without proper security configurations, especially in Java (DocumentBuilder, SAXParser).
7.  **Untrusted Data Usage:** Scrutinize file operations (read/write), network calls (URLs), or redirects that might use unvalidated user input.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the injection point, the type of injection, and provide a specific recommendation.
""",
            "authorization": """
Analyze the provided code for all authorization and access control vulnerabilities. Focus specifically on:
1.  **Missing Authorization Checks:** Are there critical functions, methods, or API endpoints that handle sensitive data or perform privileged actions without any (or insufficient) checks to verify if the authenticated user has the correct permissions?
2.  **Incorrect Authorization Logic (Logical Flaws):** Even if authorization checks exist, are they implemented correctly? Look for flaws in the logic that might grant unintended access (e.g., incorrect role checks, flawed conditional statements).
3.  **Insecure Direct Object References (IDOR):** Can a user access or modify resources (e.g., files, database records, other users' data) belonging to other users by manipulating identifiers (e.g., IDs in URLs, form parameters) without proper server-side validation of ownership or permission?
4.  **Privilege Escalation:**
    *   **Vertical Privilege Escalation:** Can a user with lower privileges gain access to functionalities or data reserved for higher-privilege users (e.g., an ordinary user accessing admin functions)?
    *   **Horizontal Privilege Escalation:** Can a user access resources or functionalities belonging to another user with the same level of privileges?
5.  **Overly Permissive Access:** Are permissions granted too broadly? For example, do certain roles have more access than necessary for their tasks?
6.  **Function-Level Access Control:** For applications using frameworks (e.g., Spring Security, Java EE), check for:
    *   Correct application of method-level security annotations (e.g., `@PreAuthorize`, `@Secured`, `@RolesAllowed`). Are they missing where needed? Are the expressions within them correct?
    *   Configuration of security interceptors or filters. Are they correctly applied to the intended URL patterns or service methods?
7.  **Path Traversal in Access Control:** Could path traversal vulnerabilities lead to bypassing authorization checks for accessing files or functionalities?
8.  **CWEs to consider:** CWE-285 (Improper Authorization), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-275 (Permission Issues).

For EVERY vulnerability found, use the `report_vulnerability` tool. Be precise about the affected file, code, the nature of the access control weakness, and how it can be exploited.
""",
            "xss": "Analyze for Cross-Site Scripting (XSS) vulnerabilities, including reflected, stored, and DOM-based XSS.",
            "data_protection": "Analyze for sensitive data exposure, insecure storage, or transmission of private information.",
            "api_security": "Analyze API endpoints for issues like insecure design, lack of authentication/authorization, rate limiting, etc.",
            "configuration": "Analyze for security misconfigurations in frameworks, servers, or dependencies.",
            "cryptography": "Analyze for use of weak cryptographic algorithms, improper key management, or insecure random number generation.",
            "client_side": "Analyze client-side code (JavaScript) for vulnerabilities like insecure data storage, logic flaws, or DOM manipulation risks.",
            "business_logic": "Analyze for flaws in the application's business logic that could be exploited (e.g., race conditions, improper validation)."
        }
        
        base_prompt = f"""
# Security Analysis Task: {category.title()}

You are an expert security auditor using the Gemini language model. Your task is to perform a comprehensive security analysis of the provided web application code, focusing specifically on identifying vulnerabilities related to **{category}**.

## Code Context Provided:
This section contains a large context of code chunks relevant to the analysis category. Review it carefully.
{context}

## Your Task:
{category_prompts.get(category.lower(), f'Thoroughly analyze the provided code context for any potential **{category}** security vulnerabilities. For each distinct vulnerability you identify, you MUST use the `report_vulnerability` tool to document it.')}

## Important Guidelines for Analysis and Reporting:
1.  **Comprehensive Review:** Examine the entire provided code context. Consider interactions between different files and components if evident in the context.
2.  **Focus:** Concentrate on identifying vulnerabilities matching the `{category}` category description.
3.  **Tool Usage:** Use the `report_vulnerability` function tool for EVERY vulnerability found. Do not describe vulnerabilities in plain text only.
4.  **Tool Neutrality:** Do not mention specific static analysis tools like Semgrep. Focus only on the vulnerability and its remediation.
5.  **Accuracy:** Provide precise details in the tool arguments: affected file paths, the starting `line_number` of the vulnerability, a clear `description`, `severity` (Critical, High, Medium, Low, Informational), a specific `code_snippet` (max 10 lines starting from the line_number) demonstrating the issue, and actionable `recommendation`s for fixing it.
6.  **CWE ID:** Include the relevant CWE ID if applicable.
7.  **Prioritize:** Focus on clear, demonstrable vulnerabilities over highly speculative ones. If uncertain, note the uncertainty in the description field of the tool call.
8.  **No Chit-chat:** Only respond with tool calls. Do not add introductory or concluding remarks outside of the required tool function calls.
"""
        return base_prompt
