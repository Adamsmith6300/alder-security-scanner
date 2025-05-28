import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict
import re

# Import using relative path
from ..processing.finding_types import ConsolidatedFinding, SeverityLevel

# No longer needed:
# import markdown 
# from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

# Define severity order for the report
REPORT_SEVERITY_ORDER: List[SeverityLevel] = ["Critical", "High", "Medium", "Low", "Informational"]

class ReportGenerator:
    def __init__(self, output_dir="./reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        logger.debug(f"ReportGenerator initialized. Outputting reports to: {self.output_dir}")

    def _group_findings_by_severity(self, findings: List[ConsolidatedFinding]) -> Dict[SeverityLevel, List[ConsolidatedFinding]]:
        """Group consolidated findings by severity level."""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.severity].append(finding)
        # Sort findings within each severity group (e.g., by file path then line number)
        for severity in grouped:
            grouped[severity].sort(key=lambda f: (f.file_path, f.line_start))
        return grouped

    def _convert_raw_llm_finding_to_consolidated(self, llm_finding_raw: Dict, category: str) -> Optional[ConsolidatedFinding]:
        """Convert a single raw LLM finding dictionary to a ConsolidatedFinding object."""
        try:
            affected_files = llm_finding_raw.get("affected_files", [])
            line_number = llm_finding_raw.get("line_number")
            
            # LLM findings might not always have a file/line, though our current ones do.
            # Handle cases where they might be missing, though the orchestrator's current LLM calls
            # are expected to produce these.
            if not affected_files or not line_number: 
                logger.debug(f"Skipping LLM finding due to missing affected_files or line_number: {llm_finding_raw} in category {category}")
                return None
            
            # Assume the first file is the primary one
            file_path = affected_files[0]

            # Basic check for line_number type
            if not isinstance(line_number, int):
                try:
                    line_number = int(line_number)
                except ValueError:
                    logger.debug(f"Could not convert line_number '{line_number}' to int for finding: {llm_finding_raw}")
                    return None

            return ConsolidatedFinding(
                file_path=file_path,
                line_start=int(line_number), 
                description=llm_finding_raw.get("description", ""),
                severity=llm_finding_raw.get("severity", "Informational"),
                recommendation=llm_finding_raw.get("recommendation"),
                cwe_id=str(llm_finding_raw.get("cwe_id")) if llm_finding_raw.get("cwe_id") else None, # Ensure CWE is string or None
                code_snippet=llm_finding_raw.get("code_snippet"),
                source="llm",
                llm_category=category,
                # New fields from finding_verifier workflow
                verified_exploitability_status=llm_finding_raw.get("verified_exploitability_status"),
                verified_exploitability_confidence=llm_finding_raw.get("verified_exploitability_confidence"),
                verified_exploitability_reasoning=llm_finding_raw.get("verified_exploitability_reasoning"),
                data_source_analysis=llm_finding_raw.get("data_source_analysis"),
                verified_risk_level=llm_finding_raw.get("verified_risk_level"),
                verified_attack_scenario=llm_finding_raw.get("verified_attack_scenario"),
                verified_business_impact=llm_finding_raw.get("verified_business_impact"),
                verified_consequences=llm_finding_raw.get("verified_consequences"),
                final_priority=llm_finding_raw.get("final_priority"),
                remediation_steps=llm_finding_raw.get("remediation_steps"),
                verification_summary_reasoning=llm_finding_raw.get("verification_summary_reasoning"),
                agent_verification_status=llm_finding_raw.get("agent_verification_status")
            )
        except (TypeError, ValueError, KeyError) as e:
             logger.debug(f"Error converting raw LLM finding to ConsolidatedFinding: {e} - Finding: {llm_finding_raw}", exc_info=True)
             return None

    def _convert_and_group_llm_findings(self, llm_findings_by_category: Dict[str, List[Dict]]) -> Dict[SeverityLevel, List[ConsolidatedFinding]]:
        """Convert dictionary of raw LLM findings by category into ConsolidatedFinding objects and group them by severity."""
        all_consolidated_llm_findings: List[ConsolidatedFinding] = []
        for category, raw_findings_list in llm_findings_by_category.items():
            for raw_finding_dict in raw_findings_list:
                converted_finding = self._convert_raw_llm_finding_to_consolidated(raw_finding_dict, category)
                if converted_finding:
                    all_consolidated_llm_findings.append(converted_finding)
        
        return self._group_findings_by_severity(all_consolidated_llm_findings)

    def _build_markdown_report(
        self, 
        repo_name: str, 
        grouped_code_findings: Dict[SeverityLevel, List[ConsolidatedFinding]], 
        severity_order: List[SeverityLevel],
        total_code_findings: int
        ) -> str:
        """Build the markdown report string directly."""
        logger.debug("Building Markdown report content...")
        report_lines = []
        
        # --- Header --- 
        report_lines.append(f"# Security Analysis Report: {repo_name}")
        report_lines.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*\n")

        # --- Executive Summary --- 
        report_lines.append("## Executive Summary\n")
        report_lines.append("This report summarizes potential security findings identified through Large Language Model (LLM) analysis and verified through an AI agent workflow.\n")
        
        # Count verified vs unverified findings
        verified_count = 0
        exploitable_count = 0
        not_exploitable_count = 0
        uncertain_count = 0
        
        for findings_list in grouped_code_findings.values():
            for finding in findings_list:
                if finding.agent_verification_status == "verified_by_agent_workflow":
                    verified_count += 1
                    if finding.verified_exploitability_status == "Exploitable":
                        exploitable_count += 1
                    elif finding.verified_exploitability_status == "Not Exploitable":
                        not_exploitable_count += 1
                    elif finding.verified_exploitability_status == "Uncertain":
                        uncertain_count += 1
        
        report_lines.append("### Verification Summary\n")
        report_lines.append(f"- **Total Findings**: {total_code_findings}")
        report_lines.append(f"- **Agent Verified**: {verified_count}")
        report_lines.append(f"- **Exploitable**: {exploitable_count}")
        report_lines.append(f"- **Not Exploitable**: {not_exploitable_count}")
        report_lines.append(f"- **Uncertain**: {uncertain_count}\n")
        
        report_lines.append("### Findings Summary\n")
        report_lines.append("| Severity      | Code Findings | Exploitable | Not Exploitable | Uncertain |")
        report_lines.append("|---------------|---------------|-------------|-----------------|-----------|")
        
        for severity in severity_order:
            findings_in_severity = grouped_code_findings.get(severity, [])
            total_count = len(findings_in_severity)
            exploitable = len([f for f in findings_in_severity if f.verified_exploitability_status == "Exploitable"])
            not_exploitable = len([f for f in findings_in_severity if f.verified_exploitability_status == "Not Exploitable"])
            uncertain = len([f for f in findings_in_severity if f.verified_exploitability_status == "Uncertain"])
            
            report_lines.append(f"| {severity:<13} | {total_count:<13} | {exploitable:<11} | {not_exploitable:<15} | {uncertain:<9} |")
        
        report_lines.append("\n")

        # --- Code Findings Section --- 
        report_lines.append("## Detailed Findings\n")
        if not total_code_findings:
             report_lines.append("No code analysis findings reported.\n")
        else:
            finding_counter = 0
            for severity in severity_order:
                findings_in_severity = grouped_code_findings.get(severity)
                if not findings_in_severity:
                    continue
                
                report_lines.append(f"### {severity} Findings\n")
                for finding in findings_in_severity:
                    finding_counter += 1
                    
                    # Build the header with priority and exploitability status
                    header_parts = [f"{finding_counter}. {finding.description.splitlines()[0]}"]
                    if finding.final_priority:
                        header_parts.append(f"[{finding.final_priority}]")
                    if finding.verified_exploitability_status:
                        status_emoji = {
                            "Exploitable": "🔴",
                            "Not Exploitable": "🟢", 
                            "Uncertain": "🟡"
                        }.get(finding.verified_exploitability_status, "")
                        header_parts.append(f"{status_emoji} {finding.verified_exploitability_status}")
                    
                    report_lines.append(f"#### {' '.join(header_parts)}")
                    
                    # Basic information
                    if finding.source == "sast":
                        source_tag = f"Rule: {finding.sast_rule_id}"
                    elif finding.source == "llm":
                         source_tag = f"Category: {finding.llm_category}"
                    elif finding.source == "both":
                         source_tag = f"SAST Rule: {finding.sast_rule_id}, LLM Category: {finding.llm_category}"
                         
                    report_lines.append(f"**Source:** {source_tag}")
                    report_lines.append(f"**File:** `{finding.file_path}:{finding.line_start}`")
                    if finding.cwe_id:
                         report_lines.append(f"**CWE:** {finding.cwe_id}")
                    
                    # Agent verification status
                    if finding.agent_verification_status:
                        status_display = finding.agent_verification_status.replace("_", " ").title()
                        report_lines.append(f"**Verification Status:** {status_display}")
                    
                    report_lines.append("")
                    
                    # Description
                    report_lines.append(f"**Description:**\n{finding.description}\n")
                    
                    # Exploitability Analysis
                    if finding.verified_exploitability_status:
                        report_lines.append("**🔍 Exploitability Analysis:**")
                        report_lines.append(f"- **Status:** {finding.verified_exploitability_status}")
                        if finding.verified_exploitability_confidence is not None:
                            confidence_pct = f"{finding.verified_exploitability_confidence * 100:.0f}%"
                            report_lines.append(f"- **Confidence:** {confidence_pct}")
                        if finding.verified_exploitability_reasoning:
                            report_lines.append(f"- **Reasoning:** {finding.verified_exploitability_reasoning}")
                        if finding.data_source_analysis:
                            report_lines.append(f"- **Data Source Analysis:** {finding.data_source_analysis}")
                        report_lines.append("")
                    
                    # Risk and Impact Analysis
                    if finding.verified_risk_level or finding.verified_business_impact:
                        report_lines.append("**📊 Risk & Impact Analysis:**")
                        if finding.verified_risk_level:
                            report_lines.append(f"- **Risk Level:** {finding.verified_risk_level}")
                        if finding.verified_business_impact:
                            report_lines.append(f"- **Business Impact:** {finding.verified_business_impact}")
                        if finding.verified_attack_scenario:
                            report_lines.append(f"- **Attack Scenario:** {finding.verified_attack_scenario}")
                        if finding.verified_consequences:
                            report_lines.append("- **Potential Consequences:**")
                            for consequence in finding.verified_consequences:
                                report_lines.append(f"  - {consequence}")
                        report_lines.append("")
                    
                    # Code snippet
                    if finding.code_snippet:
                         snippet = finding.code_snippet.strip()
                         lang_hint = finding.language if hasattr(finding, 'language') and finding.language else ''
                         report_lines.append(f"**Code Snippet:**\n```{lang_hint}\n{snippet}\n```\n")
                    
                    # Remediation steps (prioritized over generic recommendation)
                    if finding.remediation_steps:
                        report_lines.append("**🔧 Remediation Steps:**")
                        for i, step in enumerate(finding.remediation_steps, 1):
                            report_lines.append(f"{i}. {step}")
                        report_lines.append("")
                    elif finding.recommendation:
                        report_lines.append(f"**Recommendation:**\n{finding.recommendation}\n")
                    
                    # Verification summary reasoning
                    if finding.verification_summary_reasoning:
                        report_lines.append(f"**🤖 AI Analysis Summary:**\n{finding.verification_summary_reasoning}\n")
                    
                    report_lines.append("---\n")
            report_lines.append("\n")

        # --- Summary Statistics ---
        report_lines.append("## Analysis Summary\n")
        
        # Priority distribution
        priority_counts = {}
        for findings_list in grouped_code_findings.values():
            for finding in findings_list:
                if finding.final_priority:
                    priority_counts[finding.final_priority] = priority_counts.get(finding.final_priority, 0) + 1
        
        if priority_counts:
            report_lines.append("### Priority Distribution\n")
            for priority in sorted(priority_counts.keys()):
                count = priority_counts[priority]
                report_lines.append(f"- **{priority}**: {count} findings")
            report_lines.append("")
        
        # Exploitability distribution
        if verified_count > 0:
            report_lines.append("### Exploitability Assessment\n")
            report_lines.append(f"- **Exploitable**: {exploitable_count} ({exploitable_count/verified_count*100:.1f}%)")
            report_lines.append(f"- **Not Exploitable**: {not_exploitable_count} ({not_exploitable_count/verified_count*100:.1f}%)")
            report_lines.append(f"- **Uncertain**: {uncertain_count} ({uncertain_count/verified_count*100:.1f}%)")
            report_lines.append("")

        # --- Footer / General Recs --- 
        report_lines.append("## General Recommendations")
        report_lines.append("- **Prioritize Exploitable Findings**: Focus immediate attention on findings marked as 'Exploitable'")
        report_lines.append("- **Review Uncertain Findings**: Manually review findings marked as 'Uncertain' for context-specific risks")
        report_lines.append("- **Implement Defense in Depth**: Even 'Not Exploitable' findings may become exploitable with code changes")
        report_lines.append("- **Regular Security Reviews**: Conduct periodic security assessments as code evolves")
        report_lines.append("- **Security Training**: Ensure development team understands secure coding practices")
        report_lines.append("\n---\n")
        report_lines.append("*This report was generated by Alder AI Security Scanner with agent-based verification.*")

        return "\n".join(report_lines)

    def generate_report(
        self,
        repo_name: str,
        raw_llm_findings_by_category: Dict[str, List[Dict]]
    ):
        """Generate a comprehensive security report from raw LLM findings."""
        logger.debug(f"Generating security report for: {repo_name}")

        # Convert and group LLM findings
        grouped_code_findings = self._convert_and_group_llm_findings(raw_llm_findings_by_category)
        
        # Calculate total code findings after conversion and grouping
        total_code_findings = sum(len(lst) for lst in grouped_code_findings.values())

        logger.debug(f"Processing {total_code_findings} LLM code findings.")

        # Generate report content directly in Python
        report_md = self._build_markdown_report(
             repo_name, 
             grouped_code_findings, 
             REPORT_SEVERITY_ORDER, 
             total_code_findings
        )
        
        # Save markdown report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_name)
        report_filename_base = f"security_report_{safe_repo_name}_{timestamp}"
        md_path = os.path.join(self.output_dir, f"{report_filename_base}.md")
        try:
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(report_md)
            logger.debug(f"Markdown report saved to: {md_path}")
        except IOError as e:
            logger.debug(f"Failed to save Markdown report to {md_path}: {e}")
            md_path = None # Indicate failure

        return {
            "markdown_path": md_path,
            "html_path": None
        }
