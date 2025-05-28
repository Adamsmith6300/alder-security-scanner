import logging
import json
import re # Import re for regex operations
from typing import Dict, Any, Optional, List

from .graph_state import WorkflowState, ExploitabilityAnalysis, ContextAnalysis, ImpactAssessment
from ...llm.client import GeminiClient 
from .tools.code_analysis_tools import CodeAnalysisTools

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG) # User might set this globally

class AgentNode:
    def __init__(self, llm_client: GeminiClient, code_tools: CodeAnalysisTools):
        self.llm_client = llm_client
        self.code_tools = code_tools
        logger.debug(f"{self.__class__.__name__} initialized with LLM client: {type(llm_client).__name__} and CodeTools: {type(code_tools).__name__}")

    def _parse_llm_json_output(self, llm_output: str, expected_keys: List[str]) -> Optional[Dict[str, Any]]:
        logger.debug(f"Attempting to parse LLM JSON output. Expected keys: {expected_keys}. Output (first 100 chars): {llm_output[:100]}...")
        
        # Strip common markdown code block fences and whitespace
        cleaned_output = llm_output.strip()
        if cleaned_output.startswith("```json") and cleaned_output.endswith("```"):
            cleaned_output = cleaned_output[len("```json"):-len("```")].strip()
        elif cleaned_output.startswith("```") and cleaned_output.endswith("```"):
            cleaned_output = cleaned_output[len("```"):-len("```")].strip()
        # Fallback for cases where only one fence is present or other variations might occur
        # This regex aims to extract content between ```json (optional) and ```
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", llm_output, re.DOTALL)
        if match:
            cleaned_output = match.group(1).strip()
        else:
            # If regex doesn't match (e.g. no fences), use the already stripped version
            cleaned_output = llm_output.strip()

        logger.debug(f"Cleaned LLM output for JSON parsing (first 100 chars): {cleaned_output[:100]}...")

        if not cleaned_output:
            logger.error("LLM output was empty after cleaning for JSON parsing.")
            return None

        try:
            data = json.loads(cleaned_output)
            if not all(key in data for key in expected_keys):
                logger.warning(f"LLM JSON output missing expected keys. Expected: {expected_keys}, Got: {list(data.keys())}")
                logger.debug(f"Full invalid JSON output from LLM: {llm_output}")
                return None
            logger.debug("LLM JSON output parsed successfully and all expected keys found.")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON output: {e}. Output was: {llm_output}", exc_info=True)
            return None

class ExploitabilityAgentNode(AgentNode):
    def run(self, state: WorkflowState) -> Dict[str, Any]:
        logger.info("--- Running Exploitability Agent ---")
        finding = state["current_raw_finding"]
        finding_desc_summary = str(finding.get('description', 'N/A'))[:70] + "..."
        logger.debug(f"ExploitabilityAgent processing finding: '{finding_desc_summary}'. Full finding keys: {list(finding.keys())}")

        affected_files_list = finding.get("affected_files", [])
        file_path = affected_files_list[0] if affected_files_list else "UnknownFile.py"
        line_number = finding.get("line_number") if finding.get("line_number") is not None else 1

        logger.debug(f"Calling trace_execution_path for finding: '{finding_desc_summary}'")
        execution_trace_info = self.code_tools.trace_execution_path(finding)
        logger.debug(f"trace_execution_path result (first 100 chars): {str(execution_trace_info)[:100]}...")
        
        logger.debug(f"Calling get_code_context_around_line for {file_path}:{line_number}")
        code_context_near_finding = self.code_tools.get_code_context_around_line(file_path, line_number, finding=finding)
        logger.debug(f"get_code_context_around_line result (first 100 chars): {str(code_context_near_finding)[:100]}...")
        
        logger.debug(f"Calling trace_data_flow_backward for finding: '{finding_desc_summary}'")
        data_flow_info = self.code_tools.trace_data_flow_backward(finding)
        logger.debug(f"trace_data_flow_backward result: {str(data_flow_info)}...")
        
        logger.debug(f"Calling check_for_protections for finding: '{finding_desc_summary}'")
        protection_info = self.code_tools.check_for_protections(finding)
        logger.debug(f"check_for_protections result (first 100 chars): {str(protection_info)[:100]}...")
        
        prompt = f"""
        Analyze the following vulnerability finding for exploitability:
        Finding Description: {finding.get('description')}
        File: {file_path}:{line_number}
        
        Code Context (semantic or line-based) near Finding:
        ```
        {code_context_near_finding}
        ```
        
        Data Flow Analysis:
        ```
        {data_flow_info}
        ```
        
        Execution Path Analysis: {execution_trace_info}
        Existing Protections Analysis (file-wide): {protection_info}

        CRITICAL ANALYSIS POINTS:
        1. **Data Source**: Where does the vulnerable data originate? Is it user-controlled or internally generated?
        2. **User Control**: Can an attacker directly or indirectly influence the vulnerable variable?
        3. **Endpoint Access**: Is the vulnerable code reachable from user-facing endpoints?
        4. **Authentication**: What authentication/authorization is required to reach this code?

        SPECIFIC GUIDANCE:
        - If the Data Flow Analysis shows "LOW RISK" with "internally generated data" or "trusted sources", 
          this is likely NOT EXPLOITABLE unless there's evidence of user control elsewhere.
        - If the Data Flow Analysis shows "HIGH RISK" with "user-controlled sources", 
          this is likely EXPLOITABLE.
        - If the variable is a "function parameter", check if the function is called with user input.
        - Pay special attention to file path vulnerabilities - if file paths are generated internally 
          (not from user input), they are typically not exploitable.

        Based on this comprehensive analysis, is the vulnerability likely exploitable?
        Consider if the vulnerable code is reachable from user input and if any protections mitigate the risk.
        
        Output your analysis as a JSON object with keys: 
        - "status" (string: "Exploitable", "Not Exploitable", or "Uncertain")
        - "confidence" (float: 0.0 to 1.0)
        - "reasoning" (string: your detailed explanation focusing on data flow and user control)
        - "data_source_analysis" (string: summary of where the vulnerable data comes from)
        
        Example: {{"status": "Not Exploitable", "confidence": 0.9, "reasoning": "Data flow analysis shows the file_location variable is populated internally by generate_file_path() function, not from user input. No evidence of user control over this variable.", "data_source_analysis": "Variable populated by internal generation functions, not user-controlled input"}}
        """
        logger.debug(f"ExploitabilityAgent LLM Prompt (first 300 chars): {prompt[:300]}...")
        
        llm_response_str = ""
        try:
            response = self.llm_client.generate_content(prompt=prompt)
            llm_response_str = response.text
            logger.debug(f"ExploitabilityAgent LLM response (first 100 chars): {llm_response_str[:100]}...")
        except Exception as e:
            logger.error(f"GeminiClient API call failed in ExploitabilityAgentNode: {e}", exc_info=True)

        parsed_response = self._parse_llm_json_output(llm_response_str, ["status", "confidence", "reasoning", "data_source_analysis"])
        logger.debug(f"ExploitabilityAgent parsed LLM response: {parsed_response}")

        if parsed_response:
            result: ExploitabilityAnalysis = {
                "status": str(parsed_response.get("status", "Uncertain")),
                "confidence": float(parsed_response.get("confidence", 0.0)),
                "reasoning": str(parsed_response.get("reasoning", "No reasoning provided.")),
                "data_source_analysis": str(parsed_response.get("data_source_analysis", "No data source analysis provided."))
            }
        else:
            logger.warning("Exploitability agent failed to get a valid response from LLM.")
            result: ExploitabilityAnalysis = {"status": "Error", "confidence": 0.0, "reasoning": "LLM analysis failed or produced invalid format.", "data_source_analysis": "LLM analysis failed or produced invalid format."}
        
        logger.debug(f"ExploitabilityAgent final result: {result}")
        return {"exploitability_result": result}

class ContextAnalysisAgentNode(AgentNode):
    def run(self, state: WorkflowState) -> Dict[str, Any]:
        logger.info("--- Running Context Analysis Agent ---")
        finding = state["current_raw_finding"]
        exploitability_info = state.get("exploitability_result", {})
        finding_desc_summary = str(finding.get('description', 'N/A'))[:70] + "..."
        logger.debug(f"ContextAnalysisAgent processing finding: '{finding_desc_summary}'. Exploitability info: {exploitability_info}")

        affected_files_list = finding.get("affected_files", [])
        file_path = affected_files_list[0] if affected_files_list else "UnknownFile.py"
        line_number = finding.get("line_number") if finding.get("line_number") is not None else 1

        logger.debug(f"Calling get_code_context_around_line for {file_path}:{line_number}")
        code_context = self.code_tools.get_code_context_around_line(file_path, line_number, finding=finding)
        logger.debug(f"get_code_context_around_line result (first 100 chars): {str(code_context)[:100]}...")

        related_code_query = f"functions calling or data influencing code near {file_path}:{line_number}"
        logger.debug(f"Calling search_related_code_snippets with query: {related_code_query}")
        related_snippets_raw = self.code_tools.search_related_code_snippets(related_code_query, n_results=3)
        logger.debug(f"search_related_code_snippets raw result: {related_snippets_raw}")
        related_snippets_str = "\n".join([f"Path: {s.get('metadata', {}).get('file_path', 'N/A')}\nSnippet:\n{s.get('content', 'N/A')}\n---" for s in related_snippets_raw]) if related_snippets_raw else "No related code snippets found."
        logger.debug(f"search_related_code_snippets formatted string (first 100 chars): {related_snippets_str[:100]}...")
        
        exploit_status = exploitability_info.get('status', 'N/A')
        exploit_reasoning = exploitability_info.get('reasoning', 'N/A')

        prompt = f"""
        Analyze the context of the following vulnerability:
        Finding Description: {finding.get('description')}
        File: {file_path}:{line_number}
        Exploitability Assessment: {exploit_status} ({exploit_reasoning})
        
        {'Code Context (semantic or line-based) near Finding:'}
        ```
        {code_context}
        ```
        Potentially Related Code Snippets:
        ```
        {related_snippets_str}
        ```

        Based on this, assess the following:
        1. Authentication/Authorization: What auth/authz is required to reach this code?
        2. Data/System Access: What sensitive data or critical systems can this code access if exploited?
        3. Error Handling: Does error handling around this code leak sensitive information?

        Output your analysis as a JSON object with keys: "risk_level" (string: "High", "Medium", or "Low"), 
        and "attack_scenario_description" (string: a plausible attack scenario).
        Example: {{"risk_level": "High", "attack_scenario_description": "An authenticated user with basic privileges could exploit this XSS to steal admin session cookies."}}
        """
        logger.debug(f"ContextAnalysisAgent LLM Prompt (first 300 chars): {prompt[:300]}...")
        
        llm_response_str = ""
        try:
            response = self.llm_client.generate_content(prompt=prompt)
            llm_response_str = response.text
            logger.debug(f"ContextAnalysisAgent LLM response (first 100 chars): {llm_response_str[:100]}...")
        except Exception as e:
            logger.error(f"GeminiClient API call failed in ContextAnalysisAgentNode: {e}", exc_info=True)

        parsed_response = self._parse_llm_json_output(llm_response_str, ["risk_level", "attack_scenario_description"])
        logger.debug(f"ContextAnalysisAgent parsed LLM response: {parsed_response}")

        if parsed_response:
            result: ContextAnalysis = {
                "risk_level": str(parsed_response.get("risk_level", "Unknown")),
                "attack_scenario_description": str(parsed_response.get("attack_scenario_description", "Not described."))
            }
        else:
            logger.warning("Context analysis agent failed to get a valid response from LLM.")
            result: ContextAnalysis = {"risk_level": "Error", "attack_scenario_description": "LLM context analysis failed."}
        
        logger.debug(f"ContextAnalysisAgent final result: {result}")
        return {"context_analysis_result": result}

class ImpactAssessmentAgentNode(AgentNode):
    def run(self, state: WorkflowState) -> Dict[str, Any]:
        logger.info("--- Running Impact Assessment Agent ---")
        finding = state["current_raw_finding"]
        context_info = state.get("context_analysis_result", {}) # Default to empty dict
        exploitability_info = state.get("exploitability_result", {}) # Default to empty dict
        finding_desc_summary = str(finding.get('description', 'N/A'))[:70] + "..."
        logger.debug(f"ImpactAssessmentAgent processing finding: '{finding_desc_summary}'. Context: {context_info}, Exploitability: {exploitability_info}")

        affected_files_list = finding.get("affected_files", [])
        file_path = affected_files_list[0] if affected_files_list else "UnknownFile.py"
        line_number = finding.get("line_number") if finding.get("line_number") is not None else 1
        
        exploit_status = exploitability_info.get('status', 'N/A')
        context_attack_scenario = context_info.get('attack_scenario_description', 'N/A')
        context_risk_level = context_info.get('risk_level', 'N/A')

        prompt = f"""
        Assess the potential business impact of the following vulnerability:
        Finding Description: {finding.get('description')}
        File: {file_path}:{line_number}
        Exploitability: {exploit_status}
        Context/Attack Scenario: {context_attack_scenario}
        Risk Level from Context: {context_risk_level}

        Consider:
        - Data Sensitivity: What kind of data is at risk (PII, financial, credentials, etc.)?
        - System Criticality: How critical is the affected system/application to business operations?
        - Lateral Movement: Could this vulnerability be used to compromise other systems?
        - Detection: How likely is exploitation to be detected by existing monitoring/logging (assume basic logging is in place)?

        Output your analysis as a JSON object with keys: "business_impact_rating" (string: "Critical", "High", "Moderate", "Low", or "Informational"), 
        and "specific_consequences" (list of strings: specific negative outcomes, e.g., ["Unauthorized access to user PII", "Service disruption for X hours"]).
        Example: {{"business_impact_rating": "High", "specific_consequences": ["Theft of customer PII from the database.", "Reputational damage due to public disclosure."]}}
        """
        logger.debug(f"ImpactAssessmentAgent LLM Prompt (first 300 chars): {prompt[:300]}...")
            
        llm_response_str = ""
        try:
            response = self.llm_client.generate_content(prompt=prompt)
            llm_response_str = response.text
            logger.debug(f"ImpactAssessmentAgent LLM response (first 100 chars): {llm_response_str[:100]}...")
        except Exception as e:
            logger.error(f"GeminiClient API call failed in ImpactAssessmentAgentNode: {e}", exc_info=True)
            
        parsed_response = self._parse_llm_json_output(llm_response_str, ["business_impact_rating", "specific_consequences"])
        logger.debug(f"ImpactAssessmentAgent parsed LLM response: {parsed_response}")

        if parsed_response:
            result: ImpactAssessment = {
                "business_impact_rating": str(parsed_response.get("business_impact_rating", "Unknown")),
                "specific_consequences": parsed_response.get("specific_consequences", [])
            }
        else:
            logger.warning("Impact assessment agent failed to get a valid response from LLM.")
            result: ImpactAssessment = {"business_impact_rating": "Error", "specific_consequences": ["LLM impact assessment failed."]}
        
        logger.debug(f"ImpactAssessmentAgent final result: {result}")
        return {"impact_assessment_result": result}

class SynthesisAgentNode(AgentNode):
    def run(self, state: WorkflowState) -> Dict[str, Any]:
        logger.info("--- Running Synthesis Agent ---")
        raw_finding = state["current_raw_finding"]
        exploitability = state.get("exploitability_result", {}) # Default to empty dict
        context = state.get("context_analysis_result", {}) # Default to empty dict
        impact = state.get("impact_assessment_result", {}) # Default to empty dict
        finding_desc_summary = str(raw_finding.get('description', 'N/A'))[:70] + "..."
        logger.debug(f"SynthesisAgent processing finding: '{finding_desc_summary}'. Inputs - Exploitability: {exploitability}, Context: {context}, Impact: {impact}")

        affected_files_list = raw_finding.get("affected_files", [])
        file_path = affected_files_list[0] if affected_files_list else "UnknownFile.py"
        line_number = raw_finding.get("line_number") if raw_finding.get("line_number") is not None else 1

        exploit_status = exploitability.get('status', 'N/A')
        exploit_confidence = exploitability.get('confidence', 'N/A')
        exploit_reasoning = exploitability.get('reasoning', 'N/A')
        data_source_analysis = exploitability.get('data_source_analysis', 'N/A')
        context_risk = context.get('risk_level', 'N/A')
        context_scenario = context.get('attack_scenario_description', 'N/A')
        impact_rating = impact.get('business_impact_rating', 'N/A')
        impact_consequences_list = impact.get('specific_consequences', [])
        impact_consequences = ", ".join(impact_consequences_list) if impact_consequences_list else 'N/A'


        prompt = f"""
        Synthesize the findings from previous analysis stages for the vulnerability:
        Original Finding Description: {raw_finding.get('description')}
        File: {file_path}:{line_number}
        Original Severity: {raw_finding.get('severity', 'N/A')}
        
        Exploitability Analysis:
        Status: {exploit_status}
        Confidence: {exploit_confidence}
        Reasoning: {exploit_reasoning}

        Context Analysis:
        Risk Level: {context_risk}
        Attack Scenario: {context_scenario}

        Impact Assessment:
        Business Impact: {impact_rating}
        Consequences: {impact_consequences}

        Based on all the above, provide a final assessment.
        Resolve any conflicts (e.g., high exploitability but low impact, or vice-versa by explaining the rationale).
        Generate a final priority score (e.g., P0-Critical, P1-High, P2-Medium, P3-Low, P4-Informational).
        Provide concise, actionable remediation steps (2-3 steps).

        Output your synthesis as a JSON object with the following keys:
        - "final_priority": string (e.g., "P1-High")
        - "actionable_remediation_steps": list of strings
        - "overall_reasoning": string (explaining the final priority and how analyses were combined/conflicts resolved)
        - "verified_description": string (potentially a refined description of the vulnerability)
        - "verified_severity": string (the new severity based on the detailed analysis, e.g., "High")
        
        Example: {{"final_priority": "P2-Medium", "actionable_remediation_steps": ["Implement robust input validation for parameter 'X'.", "Apply least privilege principle to database user 'Y'."], "overall_reasoning": "While exploitability is moderate, the potential impact is limited to specific non-critical data. Therefore, priority is Medium.", "verified_description": "Refined SQL injection vulnerability in user profile update.", "verified_severity": "Medium"}}
        """
        logger.debug(f"SynthesisAgent LLM Prompt (first 300 chars): {prompt[:300]}...")
            
        llm_response_str = ""
        try:
            response = self.llm_client.generate_content(prompt=prompt)
            llm_response_str = response.text
            logger.debug(f"SynthesisAgent LLM response (first 100 chars): {llm_response_str[:100]}...")
        except Exception as e:
            logger.error(f"GeminiClient API call failed in SynthesisAgentNode: {e}", exc_info=True)
            
        parsed_response = self._parse_llm_json_output(llm_response_str, ["final_priority", "actionable_remediation_steps", "overall_reasoning", "verified_description", "verified_severity"])
        logger.debug(f"SynthesisAgent parsed LLM response: {parsed_response}")

        if parsed_response:
            final_details = raw_finding.copy()
            final_details.update({
                "verified_exploitability_status": exploit_status,
                "verified_exploitability_confidence": exploit_confidence,
                "verified_exploitability_reasoning": exploit_reasoning,
                "verified_risk_level": context_risk,
                "verified_attack_scenario": context_scenario,
                "verified_business_impact": impact_rating,
                "verified_consequences": impact_consequences_list, # Use the list here
                "final_priority": str(parsed_response.get("final_priority", "P3-Low")),
                "remediation_steps": parsed_response.get("actionable_remediation_steps", []),
                "verification_summary_reasoning": str(parsed_response.get("overall_reasoning", "No overall reasoning provided.")),
                "description": str(parsed_response.get("verified_description", raw_finding.get('description'))), 
                "severity": str(parsed_response.get("verified_severity", raw_finding.get('severity'))),       
                "agent_verification_status": "verified_by_agent_workflow",
                "data_source_analysis": data_source_analysis
            })
        else:
            logger.warning("Synthesis agent failed to get a valid response from LLM.")
            final_details = raw_finding.copy()
            final_details["agent_verification_status"] = "error_in_synthesis"
        
        logger.debug(f"SynthesisAgent final result keys: {list(final_details.keys())}, Final Priority: {final_details.get('final_priority')}")
        return {"final_verified_finding_details": final_details} 
