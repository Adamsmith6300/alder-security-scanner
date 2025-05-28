# Remove Anthropic, import google.generativeai
import google.generativeai as genai
import json
import logging
import re

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
        

    def analyze_code_for_category(self, code_chunks, category):
        """Analyze specific code chunks deeply for vulnerabilities using Gemini."""
        logger.debug(f"[Analysis] Preparing context and prompt for category: {category} on {len(code_chunks)} chunks")
        context = self._format_code_for_analysis(code_chunks)
        if not context:
            logger.debug(f"[Analysis] No relevant code chunks provided for category: {category}. Skipping analysis.")
            return [], None, None
        
        prompt = self._create_security_prompt(category, context)
        
        logger.debug(f"[Analysis] Calling Gemini model ({self.model_name}) for category: {category}...")
        vulnerabilities = []
        input_tokens = None
        output_tokens = None

        try:
            response = self.model.generate_content(prompt)
            logger.debug(f"[Analysis] Gemini API call successful for category: {category}")
            
            # Extract Token Counts
            try:
                # Attempt to extract token counts from the response's usage_metadata
                # This structure is common but might need adjustment based on exact Gemini API response
                if response.usage_metadata:
                    input_tokens = response.usage_metadata.prompt_token_count
                    output_tokens = response.usage_metadata.candidates_token_count
                    logger.debug(f"[Analysis] Tokens for category '{category}': Input={input_tokens}, Output={output_tokens}")
                else:
                     logger.debug(f"[Analysis] usage_metadata not found in Gemini response for category '{category}'. Token counts unavailable.")
            except AttributeError:
                logger.debug(f"[Analysis] Could not retrieve token usage attributes (prompt_token_count/candidates_token_count) from usage_metadata for category '{category}'.")
            except Exception as e:
                logger.debug(f"[Analysis] Error extracting token counts for category '{category}': {e}")

            # Extract tool calls (function calls in Gemini terminology)
            if response.candidates and response.candidates[0].content.parts:
                logger.debug(f"[Analysis] Processing {len(response.candidates[0].content.parts)} parts from Gemini response for category {category}")
                for part in response.candidates[0].content.parts:
                    if part.function_call and part.function_call.name == 'report_vulnerability':
                        logger.debug(f"[Analysis] Found report_vulnerability function call")
                        try:
                            vulnerability = dict(part.function_call.args)
                            vulnerabilities.append(vulnerability)
                            logger.debug(f"[Analysis] Successfully extracted vulnerability: {vulnerability.get('vulnerability_type', 'N/A')}")
                        except Exception as e:
                            logger.debug(f"[Analysis] Error processing function call arguments for category {category}: {e}")
                            logger.debug(f"[Analysis] Faulty arguments: {part.function_call.args}")
            else:
                if response.candidates and response.candidates[0].finish_reason != "STOP":
                     logger.debug(f"[Analysis] Gemini response potentially blocked or incomplete for category '{category}'. Finish Reason: {response.candidates[0].finish_reason}")
                else:
                    logger.debug(f"[Analysis] No function calls or valid parts found in Gemini response for category: {category}. Text response: {response.text if hasattr(response, 'text') else 'N/A'}")
                
        except Exception as e:
            logger.debug(f"[Analysis] Gemini API call failed for category {category}: {e}", exc_info=True) 
            return [], None, None

        if not vulnerabilities:
             logger.debug(f"[Analysis] No vulnerabilities reported by Gemini for category: {category}")
        else:
             logger.debug(f"[Analysis] Extracted {len(vulnerabilities)} vulnerabilities for category: {category}")

        return vulnerabilities, input_tokens, output_tokens
    
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
Analyze the provided code for authentication vulnerabilities. Focus specifically on:
1.  **Weak Authentication:** Are there hardcoded credentials, default passwords, lack of rate limiting on logins, or easily guessable secrets?
2.  **Credential Storage:** Are passwords or secrets stored insecurely (e.g., plain text, weak hashing like MD5/SHA1)? Look for hashing implementations.
3.  **Session Management:** Are session tokens generated securely? Are they vulnerable to fixation? Is logout functionality properly implemented (token invalidation)? Check token storage (localStorage vs secure cookies).
4.  **Password Reset:** Is the password reset mechanism secure? Does it rely on guessable tokens or leak information?
5.  **MFA/Authorization Checks:** Are critical actions protected by appropriate authorization checks? Is MFA implemented correctly if present?

For EVERY vulnerability found, use the `report_vulnerability` tool. Be precise about the affected file and code. Assess severity based on potential impact.
""",
            "injection": """
Analyze the provided code for injection vulnerabilities. Examine these specific areas carefully:
1.  **SQL Injection:** Look for user-controlled input used directly in SQL queries constructed with string formatting or concatenation. Check ORM usage for potential vulnerabilities (e.g., raw SQL execution with unsanitized input).
2.  **Command Injection:** Identify any instances where user input might be passed to shell commands or OS execution functions (e.g., `os.system`, `subprocess.run` with `shell=True`).
3.  **Cross-Site Scripting (XSS):** Check if user input is reflected in HTML output without proper sanitization or escaping. Look for use of `dangerouslySetInnerHTML` or similar functions in frontend code. Examine template engines for auto-escaping configurations.
4.  **Server-Side Template Injection (SSTI):** If template engines are used (e.g., Jinja2, Handlebars), check if user input can influence template structure or execute directives.
5.  **Untrusted Data Usage:** Scrutinize file operations (read/write), network calls (URLs), or redirects that might use unvalidated user input.

For EVERY vulnerability identified, use the `report_vulnerability` tool. Clearly describe the injection point, the type of injection, and provide a specific recommendation.
""",
            "authorization": "Analyze for authorization issues like improper access control, missing checks, privilege escalation.",
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
