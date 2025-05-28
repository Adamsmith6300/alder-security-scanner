from typing import TypedDict, List, Dict, Any, Optional

class ExploitabilityAnalysis(TypedDict):
    status: str # "Exploitable" / "Not Exploitable" / "Uncertain"
    confidence: float
    reasoning: str
    data_source_analysis: str # Summary of where the vulnerable data comes from
    # raw_finding: Dict[str, Any] # Reference to the original finding being analyzed

class ContextAnalysis(TypedDict):
    risk_level: str # e.g., "High", "Medium", "Low"
    attack_scenario_description: str
    # exploitability_result: ExploitabilityAnalysis # Reference

class ImpactAssessment(TypedDict):
    business_impact_rating: str # e.g., "Critical", "High", "Moderate", "Low"
    specific_consequences: List[str]
    # context_analysis_result: ContextAnalysis # Reference

class SynthesizedResult(TypedDict):
    original_finding: Dict[str, Any]
    exploitability: ExploitabilityAnalysis
    context: ContextAnalysis
    impact: ImpactAssessment
    final_priority: str # e.g., "P1", "P2", "P3"
    actionable_remediation_steps: List[str]
    overall_reasoning: str

class WorkflowState(TypedDict):
    # Inputs to the workflow for a single finding
    current_finding_category: str
    current_raw_finding: Dict[str, Any]
    
    # Outputs from each agent node for the current finding
    exploitability_result: Optional[ExploitabilityAnalysis]
    context_analysis_result: Optional[ContextAnalysis]
    impact_assessment_result: Optional[ImpactAssessment]
    
    # Final synthesized output for the current finding
    final_verified_finding_details: Optional[Dict[str, Any]] # This will hold the enriched/modified finding
    