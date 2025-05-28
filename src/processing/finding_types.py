from dataclasses import dataclass, field
from typing import List, Optional, Literal

# Define severity levels for sorting and consistency
SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]
FindingSource = Literal["sast", "llm", "both"]

# Map Semgrep severities to standard levels
SEMGREP_SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
    # Add others if Semgrep uses them
}

@dataclass
class ConsolidatedFinding:
    """Represents a single security finding, potentially consolidated from multiple sources."""
    
    file_path: str
    line_start: int
    line_end: Optional[int] = None # Optional end line if available
    description: str = ""
    severity: SeverityLevel = "Informational"
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    code_snippet: Optional[str] = None
    source: FindingSource = "llm" # Default source, can be overridden
    sast_rule_id: Optional[str] = None
    llm_category: Optional[str] = None # The category LLM was checking when found
    
    # New fields from finding_verifier workflow
    verified_exploitability_status: Optional[str] = None # "Exploitable" / "Not Exploitable" / "Uncertain"
    verified_exploitability_confidence: Optional[float] = None
    verified_exploitability_reasoning: Optional[str] = None
    data_source_analysis: Optional[str] = None
    verified_risk_level: Optional[str] = None # "High", "Medium", "Low"
    verified_attack_scenario: Optional[str] = None
    verified_business_impact: Optional[str] = None # "Critical", "High", "Moderate", "Low", "Informational"
    verified_consequences: Optional[List[str]] = None
    final_priority: Optional[str] = None # "P0-Critical", "P1-High", etc.
    remediation_steps: Optional[List[str]] = None
    verification_summary_reasoning: Optional[str] = None
    agent_verification_status: Optional[str] = None

    # Add a sort key for severity
    _severity_order: dict = field(default_factory=lambda: {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1})

    def __lt__(self, other):
        """Enable sorting by severity (descending)."""
        if not isinstance(other, ConsolidatedFinding):
            return NotImplemented
        return self._severity_order.get(self.severity, 0) > self._severity_order.get(other.severity, 0)
        
    def __post_init__(self):
        # Basic validation or normalization can happen here if needed
        if self.line_start <= 0:
             self.line_start = 1 # Ensure line numbers are positive
        if self.line_end is not None and self.line_end < self.line_start:
             self.line_end = self.line_start

        # Normalize severity if needed (e.g., handle case variations)
        self.severity = self.severity.capitalize() if self.severity else "Informational"
        if self.severity not in self._severity_order:
            self.severity = "Informational" # Default to lowest if unknown 
