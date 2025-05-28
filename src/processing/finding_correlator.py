import logging
from typing import List, Dict, Optional
from .finding_types import ConsolidatedFinding, SEMGREP_SEVERITY_MAP, SeverityLevel

logger = logging.getLogger(__name__)

# Define line proximity tolerance for correlation
LINE_TOLERANCE = 2

class FindingCorrelator:
    """Correlates findings from different sources (SAST, LLM)."""

    def _convert_sast_finding(self, sast_finding: Dict) -> Optional[ConsolidatedFinding]:
        """Convert a raw Semgrep finding dictionary to a ConsolidatedFinding."""
        try:
            path = sast_finding.get("path")
            start_line = sast_finding.get("start", {}).get("line")
            end_line = sast_finding.get("end", {}).get("line")
            extra = sast_finding.get("extra", {})
            message = extra.get("message", "").strip()
            semgrep_severity = extra.get("severity", "INFO")
            # code_snippet = extra.get("lines", "") # Original line
            # --- Updated Snippet Handling for SAST Findings ---
            code_snippet_raw = extra.get("lines", "")
            actual_snippet = None
            if code_snippet_raw and code_snippet_raw.strip().lower() != "requires login":
                actual_snippet = code_snippet_raw.strip()
            # --- End Updated Snippet Handling ---
            rule_id = sast_finding.get("check_id", "Unknown Rule")
            metadata = extra.get("metadata", {})
            cwe = metadata.get("cwe")
            if isinstance(cwe, list):
                 cwe = cwe[0] # Take the first CWE if it's a list
            cwe_id = str(cwe) if cwe else None
            
            # --- Updated Recommendation Logic for SAST Findings ---
            # recommendation = f"Review Semgrep rule ({rule_id}) documentation for remediation guidance." # OLD HARDCODED
            if cwe_id:
                 recommendation = f"Address the underlying issue described (related to {cwe_id}). Consult security best practices for mitigating this type of vulnerability."
            elif message: # Use the description if no CWE
                 recommendation = f"Address the issue described: '{message}'. Consult security best practices for mitigating this type of vulnerability."
            else:
                 recommendation = "Consult security best practices for mitigating this type of vulnerability based on the finding description and code snippet."
            # --- End Updated Recommendation Logic ---

            if not path or start_line is None:
                logger.debug(f"Skipping SAST finding due to missing path or start line: {sast_finding}")
                return None

            severity = SEMGREP_SEVERITY_MAP.get(semgrep_severity, "Informational")

            return ConsolidatedFinding(
                file_path=path,
                line_start=int(start_line),
                line_end=int(end_line) if end_line is not None else int(start_line),
                description=message,
                severity=severity,
                recommendation=recommendation,
                cwe_id=cwe_id,
                # code_snippet=code_snippet.strip() if code_snippet else None, # Original line
                code_snippet=actual_snippet, # Use the processed snippet value
                source="sast",
                sast_rule_id=rule_id
            )
        except (TypeError, ValueError, KeyError) as e:
             logger.debug(f"Error converting SAST finding: {e} - Finding: {sast_finding}", exc_info=True)
             return None

    def _convert_llm_finding(self, llm_finding: Dict, category: str) -> Optional[ConsolidatedFinding]:
        """Convert a raw LLM finding dictionary to a ConsolidatedFinding."""
        try:
            affected_files = llm_finding.get("affected_files", [])
            line_number = llm_finding.get("line_number")
            
            if not affected_files or line_number is None:
                 logger.debug(f"Skipping LLM finding due to missing affected_files or line_number: {llm_finding}")
                 return None
            
            # Assume the first file is the primary one for correlation
            file_path = affected_files[0]

            return ConsolidatedFinding(
                file_path=file_path, # Use the first affected file
                line_start=int(line_number),
                # line_end can be estimated from snippet if needed, but keep simple for now
                description=llm_finding.get("description", ""),
                severity=llm_finding.get("severity", "Informational"),
                recommendation=llm_finding.get("recommendation"),
                cwe_id=llm_finding.get("cwe_id"),
                code_snippet=llm_finding.get("code_snippet"),
                source="llm",
                llm_category=category
            )
        except (TypeError, ValueError, KeyError) as e:
             logger.debug(f"Error converting LLM finding: {e} - Finding: {llm_finding}", exc_info=True)
             return None

    def correlate_findings(self, sast_findings: List[Dict], llm_findings_by_category: Dict[str, List[Dict]]) -> List[ConsolidatedFinding]:
        """Correlate SAST and LLM findings based on location and type."""
        logger.debug(f"Starting finding correlation. SAST findings: {len(sast_findings)}, LLM findings: {sum(len(v) for v in llm_findings_by_category.values())}")
        
        consolidated: List[ConsolidatedFinding] = []
        processed_llm_indices = set()

        # 1. Process SAST findings and try to match LLM findings
        for sast_raw in sast_findings:
            sast_finding = self._convert_sast_finding(sast_raw)
            if not sast_finding:
                continue

            matched_llm_finding = None
            matched_llm_category = None
            match_index = -1

            # Search for a matching LLM finding
            for category, llm_list in llm_findings_by_category.items():
                 for idx, llm_raw in enumerate(llm_list):
                    llm_conv = self._convert_llm_finding(llm_raw, category)
                    if not llm_conv or (category, idx) in processed_llm_indices:
                         continue

                    # Correlation criteria:
                    # - Same file
                    # - Line numbers within tolerance
                    # - Optional: Matching CWE ID if both exist
                    if (sast_finding.file_path == llm_conv.file_path and
                        abs(sast_finding.line_start - llm_conv.line_start) <= LINE_TOLERANCE):
                        # Stronger match if CWE IDs match
                        if (sast_finding.cwe_id and llm_conv.cwe_id and 
                            sast_finding.cwe_id == llm_conv.cwe_id):
                            matched_llm_finding = llm_conv
                            matched_llm_category = category
                            match_index = idx
                            break # Found strong match
                        # Consider a match even without CWE if location is close (can be tuned)
                        elif not sast_finding.cwe_id or not llm_conv.cwe_id: 
                             matched_llm_finding = llm_conv
                             matched_llm_category = category
                             match_index = idx
                             # Don't break yet, look for potentially stronger CWE match
                 
                 if matched_llm_finding and match_index != -1: # Break outer loop if match found
                    break 
            
            if matched_llm_finding:
                # Merge findings
                logger.debug(f"Correlated SAST ({sast_finding.sast_rule_id} L{sast_finding.line_start}) and LLM ({matched_llm_finding.llm_category} L{matched_llm_finding.line_start}) finding in {sast_finding.file_path}")
                processed_llm_indices.add((matched_llm_category, match_index))
                
                # Create merged finding - prioritize details (e.g., SAST line end, higher severity)
                merged_finding = ConsolidatedFinding(
                    file_path=sast_finding.file_path,
                    line_start=sast_finding.line_start,
                    line_end=sast_finding.line_end, # Use SAST end line if available
                    description=f"[SAST: {sast_finding.sast_rule_id}] {sast_finding.description}\n[LLM: {matched_llm_finding.llm_category}] {matched_llm_finding.description}",
                    severity=max(sast_finding.severity, matched_llm_finding.severity, key=lambda s: sast_finding._severity_order.get(s, 0)),
                    recommendation=f"SAST Rec: {sast_finding.recommendation}\nLLM Rec: {matched_llm_finding.recommendation}", # Combine recommendations
                    cwe_id=sast_finding.cwe_id or matched_llm_finding.cwe_id,
                    code_snippet=sast_finding.code_snippet or matched_llm_finding.code_snippet, # Prefer SAST snippet?
                    source="both",
                    sast_rule_id=sast_finding.sast_rule_id,
                    llm_category=matched_llm_finding.llm_category
                )
                consolidated.append(merged_finding)
            else:
                # No match found, add SAST finding as is
                consolidated.append(sast_finding)

        # 2. Add remaining LLM findings that weren't matched
        for category, llm_list in llm_findings_by_category.items():
            for idx, llm_raw in enumerate(llm_list):
                if (category, idx) not in processed_llm_indices:
                    llm_finding = self._convert_llm_finding(llm_raw, category)
                    if llm_finding:
                        consolidated.append(llm_finding)
        
        logger.debug(f"Correlation complete. Total consolidated findings: {len(consolidated)}")
        return consolidated 
