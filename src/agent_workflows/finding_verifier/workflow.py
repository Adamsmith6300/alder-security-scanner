import logging
from typing import List, Dict, Any, Optional

from langgraph.graph import StateGraph, END

from .graph_state import WorkflowState
from .agents import ExploitabilityAgentNode, ContextAnalysisAgentNode, ImpactAssessmentAgentNode, SynthesisAgentNode
from ...llm.client import GeminiClient
from .tools.code_analysis_tools import CodeAnalysisTools

from ...repository.repo_manager import RepositoryManager
from ...database.vector_db import CodeVectorDatabase 

logger = logging.getLogger(__name__)

# Define a default model for the Gemini Client if not passed explicitly
# You might want to make this configurable
DEFAULT_GEMINI_MODEL_FOR_VERIFIER = "models/gemini-1.5-pro-latest"

def build_finding_verifier_graph(
    llm_client: GeminiClient,
    code_tools: CodeAnalysisTools
    ) -> StateGraph:
    logger.debug("Building finding verifier graph...")
    exploitability_agent = ExploitabilityAgentNode(llm_client, code_tools)
    logger.debug("Instantiated ExploitabilityAgentNode.")
    context_agent = ContextAnalysisAgentNode(llm_client, code_tools)
    logger.debug("Instantiated ContextAnalysisAgentNode.")
    impact_agent = ImpactAssessmentAgentNode(llm_client, code_tools)
    logger.debug("Instantiated ImpactAssessmentAgentNode.")
    synthesis_agent = SynthesisAgentNode(llm_client, code_tools)
    logger.debug("Instantiated SynthesisAgentNode.")

    graph = StateGraph(WorkflowState)
    logger.debug("StateGraph initialized.")

    graph.add_node("exploitability_analysis", exploitability_agent.run)
    graph.add_node("context_analysis", context_agent.run)
    graph.add_node("impact_assessment", impact_agent.run)
    graph.add_node("synthesis_and_verify", synthesis_agent.run)
    logger.debug("Nodes added to graph.")

    graph.set_entry_point("exploitability_analysis")
    graph.add_edge("exploitability_analysis", "context_analysis")
    graph.add_edge("context_analysis", "impact_assessment")
    graph.add_edge("impact_assessment", "synthesis_and_verify")
    graph.add_edge("synthesis_and_verify", END)
    logger.debug("Edges and entry point set for graph.")
    
    compiled_graph = graph.compile()
    logger.debug("Finding verifier graph compiled successfully.")
    return compiled_graph


def verify_findings_workflow(
    category_findings: List[Dict[str, Any]], 
    category_name: str,
    repo_manager: RepositoryManager,
    vector_db: CodeVectorDatabase,
    llm_api_key: str,
    llm_model_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
    logger.debug(f"Entering verify_findings_workflow for category: '{category_name}' with {len(category_findings)} findings.")
    
    active_model_name = llm_model_name or DEFAULT_GEMINI_MODEL_FOR_VERIFIER
    logger.debug(f"Using LLM model: {active_model_name}")
    try:
        llm_client = GeminiClient(api_key=llm_api_key, model_name=active_model_name)
        logger.debug("GeminiClient initialized successfully for agent workflow.")
    except Exception as e:
        logger.error(f"Failed to initialize GeminiClient for agent workflow: {e}", exc_info=True)
        return [dict(f, agent_verification_status="error_llm_client_initialization") for f in category_findings]

    code_tools = CodeAnalysisTools(repo_manager=repo_manager, vector_db=vector_db)
    logger.debug("CodeAnalysisTools initialized.")

    compiled_graph = build_finding_verifier_graph(llm_client, code_tools)
    logger.debug("LangGraph compiled for workflow execution.")

    processed_findings_for_category = []

    for i, raw_finding in enumerate(category_findings):
        description_summary = raw_finding.get('description', 'Unknown finding')[:70] + "..." if raw_finding.get('description') else "Unknown finding"
        logger.debug(f"Processing finding {i+1}/{len(category_findings)} for category '{category_name}': {description_summary}")
        
        initial_state: WorkflowState = {
            "current_finding_category": category_name,
            "current_raw_finding": raw_finding,
            "exploitability_result": None,
            "context_analysis_result": None,
            "impact_assessment_result": None,
            "final_verified_finding_details": None
        }
        logger.debug(f"Initial state for finding {description_summary}: {initial_state}")
        
        try:
            logger.debug(f"Invoking graph for finding: {description_summary}")
            final_graph_state = compiled_graph.invoke(initial_state)
            logger.debug(f"Graph invocation completed. Final state keys: {final_graph_state.keys() if final_graph_state else 'None'}")
            
            verified_finding_output = final_graph_state.get("final_verified_finding_details") if final_graph_state else None
            
            if verified_finding_output:
                processed_findings_for_category.append(verified_finding_output)
                logger.debug(f"Successfully verified finding. New severity: {verified_finding_output.get('severity')}, Priority: {verified_finding_output.get('final_priority')}")
            else:
                logger.warning(f"Verification workflow for finding {description_summary} did not produce final details. Appending original with error status.")
                error_finding = raw_finding.copy()
                error_finding["agent_verification_status"] = "workflow_did_not_complete_fully"
                processed_findings_for_category.append(error_finding)
                logger.debug(f"Appended finding with status 'workflow_did_not_complete_fully'.")

        except Exception as e:
            logger.error(f"Error invoking LangGraph workflow for finding {description_summary}: {e}", exc_info=True)
            error_finding = raw_finding.copy()
            error_finding["agent_verification_status"] = "workflow_invocation_error"
            processed_findings_for_category.append(error_finding)
            logger.debug(f"Appended finding with status 'workflow_invocation_error' due to exception.")
    
    logger.debug(f"Exiting verify_findings_workflow for category '{category_name}'. Processed {len(processed_findings_for_category)} findings.")
    return processed_findings_for_category
