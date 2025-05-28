import os
import requests
import logging
import json # For parsing LLM response
import re # For regex-based extraction of JSON from LLM response
from typing import List, Dict, Any, Optional
# Use a relative import to get ConsolidatedFinding type
from .processing.finding_types import ConsolidatedFinding
from .llm.client import GeminiClient # Import GeminiClient

# Default headers for GitHub API requests
GH_API_VERSION = "application/vnd.github.v3+json"
GH_ACCEPT_HEADER = "application/vnd.github+json" # Recommended by GitHub for future compatibility

# Define a model name for deduplication (can be configured if needed)
DEDUPLICATION_LLM_MODEL = "models/gemini-2.5-pro-preview-03-25" # Using a faster/cheaper model for this task

def create_issues_for_findings(
    findings_list: List[ConsolidatedFinding],
    github_token: str,
    repo_slug: str, # Expected format: "owner/repository_name"
    logger: logging.Logger,
    gemini_api_key: Optional[str] = None # Added Gemini API key parameter
) -> bool:
    """
    Creates GitHub issues for a list of security findings, using an LLM for deduplication.
    Args:
        findings_list: A list of ConsolidatedFinding objects from the current scan.
        github_token: The GitHub token for authentication.
        repo_slug: The repository slug (e.g., "owner/repo").
        logger: Logger instance for logging.
        gemini_api_key: The API key for the Gemini LLM.

    Returns:
        bool: True if issue creation process was attempted, False if essential prerequisites were missing.
    """
    if not findings_list:
        logger.info("No new findings provided, so no GitHub issues will be created.")
        return True

    if not github_token:
        logger.warning("GITHUB_TOKEN not found. Cannot create GitHub issues.")
        return False
    if not repo_slug or '/' not in repo_slug:
        logger.warning(f"GITHUB_REPOSITORY '{repo_slug}' is invalid. Expected 'owner/repo'. Cannot create GitHub issues.")
        return False

    logger.info(f"Starting GitHub issue creation process for {len(findings_list)} new findings in {repo_slug}.")

    base_api_url = f"https://api.github.com/repos/{repo_slug}/issues"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": GH_ACCEPT_HEADER,
        "X-GitHub-Api-Version": "2022-11-28"
    }

    # 1. Fetch existing 'security-alder' issues
    existing_issues_data = []
    try:
        # Fetch open issues first, can be expanded to closed if needed but adds context for LLM
        list_issues_url = f"{base_api_url}?labels=security-alder&state=open&per_page=100" 
        logger.info(f"Fetching existing open issues with label 'security-alder' from {repo_slug}")
        response = requests.get(list_issues_url, headers=headers, timeout=30)
        response.raise_for_status()
        fetched_issues = response.json()
        for issue in fetched_issues:
            existing_issues_data.append({"title": issue.get('title', ''), "body": issue.get('body', '')})
        logger.info(f"Found {len(existing_issues_data)} existing open 'security-alder' issues.")
    except requests.exceptions.RequestException as e_fetch:
        logger.error(f"Failed to fetch existing GitHub issues: {e_fetch}. Will proceed without deduplication based on existing issues.", exc_info=True)
        # If fetching fails, we can't deduplicate with LLM effectively. Proceed to create all.
        existing_issues_data = [] # Ensure it's empty so LLM isn't called with partial data or fails

    final_findings_to_create = findings_list # Default to creating all if LLM deduplication is skipped or fails

    if existing_issues_data and gemini_api_key: # Only attempt LLM deduplication if we have existing issues and API key
        logger.info("Attempting advanced deduplication of findings...")
        try:
            gemini_client = GeminiClient(api_key=gemini_api_key, model_name=DEDUPLICATION_LLM_MODEL)
            
            new_findings_formatted = []
            for i, f_item in enumerate(findings_list):
                new_findings_formatted.append(f"{i+1}. Description: {f_item.description}, File: {f_item.file_path}, Line: {f_item.line_start}, Severity: {f_item.severity}")
            
            existing_issues_formatted = []
            for i, e_item in enumerate(existing_issues_data):
                existing_issues_formatted.append(f"{i+1}. Title: {e_item['title']}\n   Body: {e_item['body'][:1000]}...") # Truncate body to keep prompt manageable

            prompt = f"""
Assistant, you are an expert at analyzing security findings and deduplicating them against existing GitHub issues.
I have a list of NEW POTENTIAL FINDINGS from a recent security scan, and a list of EXISTING ISSUES from GitHub that are already being tracked.
Your task is to carefully compare each NEW POTENTIAL FINDING with ALL the EXISTING ISSUES.
Identify which of the NEW POTENTIAL FINDINGS are genuinely novel and do not substantially overlap in terms of the specific vulnerability, location (file/function), and core problem described by any of the EXISTING ISSUES.

NEW POTENTIAL FINDINGS:
{chr(10).join(new_findings_formatted)}

EXISTING ISSUES (Title and Body Snippet):
{chr(10).join(existing_issues_formatted)}

Based on your analysis, please return a JSON list containing only the 1-based integer indices of the NEW POTENTIAL FINDINGS that are genuinely new and should have a GitHub issue created for them. Ensure the indices correspond to the numbering in the NEW POTENTIAL FINDINGS list I provided.
For example, if new findings 1 and 3 are truly new, but finding 2 is a duplicate of an existing issue, you should return: [1, 3]
If none are new, return: []
If all are new, return: [{ ", ".join(map(str, range(1, len(new_findings_formatted) + 1))) }]
Return ONLY the JSON list (e.g., [1, 2, 3]) and no other explanatory text or markdown. Ensure the output is valid JSON.
"""
            logger.debug(f"Sending prompt for deduplication analysis.")
            llm_response = gemini_client.generate_content(prompt)
            
            # Attempt to parse the response text as JSON
            # Accessing response text, specific to Gemini API structure
            response_text = llm_response.text if hasattr(llm_response, 'text') else getattr(llm_response.candidates[0].content.parts[0], 'text', None)
            if response_text:
                response_text = response_text.strip() # Strip whitespace
                logger.debug(f"Received response for deduplication analysis (raw): '{response_text}'") # Log raw response
                
                # Attempt to extract JSON if it's embedded in markdown or other text
                # Look for content between the first '[' and last ']' or first '{' and last '}'
                json_match_list = re.search(r"(\[.*?\])", response_text, re.DOTALL)
                json_match_object = re.search(r"(\{.*?\})", response_text, re.DOTALL) # Though we expect a list
                
                extracted_json_str = None
                if json_match_list:
                    extracted_json_str = json_match_list.group(1)
                elif json_match_object: # Less likely for this prompt, but as a fallback
                    extracted_json_str = json_match_object.group(1)
                else:
                    # If no clear JSON delimiters, use the stripped response text as is
                    # but this is more likely to fail if there's surrounding text
                    extracted_json_str = response_text 

                if not extracted_json_str:
                    logger.warning("Could not extract a clear JSON structure from the deduplication analysis response. Raw response was not empty but yielded no structure.")
                    # Fallback: final_findings_to_create remains findings_list
                else:
                    logger.debug(f"Attempting to parse extracted JSON: '{extracted_json_str}'")
                    try:
                        new_finding_indices = json.loads(extracted_json_str)
                        if isinstance(new_finding_indices, list) and all(isinstance(i, int) for i in new_finding_indices):
                            # Convert 1-based indices from LLM to 0-based for list access
                            final_findings_to_create = [findings_list[i-1] for i in new_finding_indices if 0 < i <= len(findings_list)]
                            logger.info(f"Deduplication analysis complete. Identified new findings to report.")
                        else:
                            raise ValueError("Deduplication analysis response is not in the expected format (list of integers).")
                    except (json.JSONDecodeError, ValueError) as e_parse:
                        logger.warning(f"Failed to parse deduplication analysis response. Proceeding to create issues for all new findings.", exc_info=True)
                        # Fallback: final_findings_to_create remains findings_list
            else:
                logger.warning("Deduplication analysis response was empty. Proceeding to create issues for all new findings.")
                # Fallback: final_findings_to_create remains findings_list

        except Exception as e_llm:
            logger.error(f"Error during advanced deduplication. Proceeding to create issues for all new findings.", exc_info=True)
            # Fallback: final_findings_to_create remains findings_list
    elif not gemini_api_key and existing_issues_data:
        logger.warning("API key for advanced deduplication not provided, but existing issues were found. Skipping advanced deduplication. All new findings will be processed.")
    else:
        logger.info("No existing relevant issues found or advanced deduplication not configured. Proceeding to process all new findings.")

    issues_created_count = 0
    issues_failed_count = 0

    if not final_findings_to_create:
        logger.info("After deduplication (or if no findings initially), no issues to create.")
        return True
        
    logger.info(f"Proceeding to create GitHub issues for {len(final_findings_to_create)} findings.")

    for finding in final_findings_to_create:
        issue_title = f"Alder Security: {finding.description.splitlines()[0][:150]}"
        if finding.file_path:
            issue_title += f" in {finding.file_path}"

        max_title_length = 256
        if len(issue_title) > max_title_length:
            issue_title = issue_title[:max_title_length-3] + "..."
            
        body_lines = [
            f"**Vulnerability Details:**",
            f"- **Description:** {finding.description}",
            f"- **File:** `{finding.file_path}`",
            f"- **Line:** {finding.line_start}" + (f"-{finding.line_end}" if finding.line_end and finding.line_end != finding.line_start else ""),
            f"- **Severity:** {finding.severity}",
        ]
        if finding.cwe_id: body_lines.append(f"- **CWE:** {finding.cwe_id}")
        if finding.llm_category: body_lines.append(f"- **LLM Category:** {finding.llm_category}")
        if finding.sast_rule_id: body_lines.append(f"- **SAST Rule ID:** {finding.sast_rule_id}")
        body_lines.append("\n**Recommendation:**")
        body_lines.append(finding.recommendation or "No specific recommendation provided.")
        if finding.code_snippet:
            lang_hint = ""
            if '.' in finding.file_path:
                ext = finding.file_path.split('.')[-1]
                if ext in ['js', 'jsx', 'ts', 'tsx']: lang_hint = 'javascript'
                elif ext == 'py': lang_hint = 'python'
                elif ext in ['java', 'kt']: lang_hint = 'java'
                elif ext in ['rb']: lang_hint = 'ruby'
                elif ext in ['php']: lang_hint = 'php'
                elif ext in ['go']: lang_hint = 'go'
                elif ext in ['c', 'cpp', 'h', 'hpp']: lang_hint = 'c++'
            body_lines.extend(["\n**Code Snippet:**", f"```{lang_hint}", finding.code_snippet.strip(), "```"])
        body_lines.extend(["\n---", "*Reported by Alder AI Security Scanner*"])
        issue_body = "\n".join(body_lines)
        payload = {"title": issue_title, "body": issue_body, "labels": ["security-alder"]}

        try:
            response = requests.post(base_api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            issue_data = response.json()
            logger.info(f"Successfully created GitHub issue #{issue_data['number']} for finding in {finding.file_path}:{finding.line_start}")
            issues_created_count += 1
        except requests.exceptions.HTTPError as http_err:
            error_details = response.json() if response.content else response.text
            logger.error(f"Failed to create GitHub issue for finding in {finding.file_path}:{finding.line_start}. Status: {response.status_code}. Details: {error_details}. Error: {http_err}")
            issues_failed_count += 1
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Failed to create GitHub issue for finding in {finding.file_path}:{finding.line_start} due to a request exception: {req_err}")
            issues_failed_count += 1
        except Exception as e:
            logger.error(f"An unexpected error occurred while creating GitHub issue for finding in {finding.file_path}:{finding.line_start}: {e}", exc_info=True)
            issues_failed_count += 1

    logger.info(f"GitHub issue creation process finished. Issues created: {issues_created_count}, Issues failed: {issues_failed_count}.")
    return True
