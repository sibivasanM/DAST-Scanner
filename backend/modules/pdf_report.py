"""
PDF Report Generator — Simple and reliable vulnerability report generation.
"""

import json
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image


class PDFReportGenerator:
    """Generate simple, reliable PDF vulnerability reports."""

    def __init__(self):
        self.severity_order = ["critical", "high", "medium", "low", "info"]

    def generate_report(
        self,
        scan: Dict[str, Any],
        findings: List[Dict[str, Any]],
        report_title: str = "Vulnerability Scan Report",
    ) -> BytesIO:
        """Generate a PDF report for a scan and its findings."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph(f"<b>{report_title}</b>", styles["Heading1"]))
        story.append(Spacer(1, 0.2 * inch))
        
        # Scan info
        story.append(Paragraph(f"<b>Target:</b> {scan.get('target', 'Unknown')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Scan Type:</b> {scan.get('scan_type', 'N/A')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Engine:</b> {scan.get('scanner_engine', 'N/A')}", styles["Normal"]))
        story.append(Paragraph(f"<b>Date:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))

        # Summary table
        story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
        summary_data = self._build_summary_data(findings)
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(self._get_table_style())
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Severity breakdown
        story.append(Paragraph("<b>Severity Breakdown</b>", styles["Heading2"]))
        severity_data = self._build_severity_data(findings)
        severity_table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch, 2 * inch])
        severity_table.setStyle(self._get_table_style())
        story.append(severity_table)
        story.append(Spacer(1, 0.3 * inch))

        # Page break before findings
        story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph("<b>Detailed Findings</b>", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))

        if findings:
            sorted_findings = self._sort_findings(findings)
            for idx, finding in enumerate(sorted_findings, 1):
                story.append(Paragraph(f"<b>{idx}. {self._safe_str(finding.get('name', 'Unknown'))[:80]}</b> [{finding.get('severity', 'info').upper()}]", styles["Heading3"]))
                
                # Details as text
                details_text = []
                details_text.append(f"<b>Host:</b> {self._safe_str(finding.get('host', 'N/A'))[:60]}")
                details_text.append(f"<b>URL:</b> {self._safe_str(finding.get('url', finding.get('matched_at', 'N/A')))[:80]}")
                details_text.append(f"<b>CVE:</b> {self._safe_str(finding.get('cve_id', 'N/A'))[:50]}")
                details_text.append(f"<b>CVSS:</b> {finding.get('cvss_score', 'N/A')}")
                details_text.append(f"<b>Type:</b> {self._safe_str(finding.get('vuln_type', 'N/A'))[:50]}")
                details_text.append(f"<b>Source:</b> {self._safe_str(finding.get('scanner_source', 'nuclei')).upper()}")
                
                for detail in details_text:
                    story.append(Paragraph(detail, styles["Normal"]))
                
                # Consolidated URLs (if grouped finding)
                if finding.get("is_consolidated_group"):
                    story.append(Paragraph(f"<b>Consolidated Findings:</b> {finding.get('consolidated_findings_count', 1)} similar instances found", styles["Normal"]))
                    
                    vulnerable_urls = finding.get("vulnerable_urls", [])
                    if vulnerable_urls:
                        story.append(Paragraph("<b>Vulnerable URLs:</b>", styles["Normal"]))
                        for url in vulnerable_urls[:5]:  # Show top 5
                            story.append(Paragraph(f"  • {self._safe_str(url)[:100]}", styles["Normal"]))
                        if len(vulnerable_urls) > 5:
                            story.append(Paragraph(f"  ... and {len(vulnerable_urls) - 5} more URLs", styles["Normal"]))
                    
                    payloads = finding.get("payloads", [])
                    if payloads:
                        story.append(Paragraph("<b>Payloads Used:</b>", styles["Normal"]))
                        for payload in payloads[:3]:  # Show top 3
                            story.append(Paragraph(f"  • {self._safe_str(payload)[:100]}", styles["Normal"]))
                        if len(payloads) > 3:
                            story.append(Paragraph(f"  ... and {len(payloads) - 3} more payloads", styles["Normal"]))
                
                # Description
                if finding.get("description"):
                    desc = self._safe_str(finding.get("description", ""))[:300]
                    story.append(Paragraph(f"<b>Description:</b> {desc}", styles["Normal"]))
                
                # AI Analysis
                if finding.get("ai_analysis"):
                    try:
                        ai_data = json.loads(finding.get("ai_analysis", "{}"))
                        if ai_data and isinstance(ai_data, dict):
                            if ai_data.get("business_impact"):
                                impact = self._safe_str(ai_data.get("business_impact", ""))[:300]
                                story.append(Paragraph(f"<b>Business Impact:</b> {impact}", styles["Normal"]))
                            if ai_data.get("remediation"):
                                remediation = self._safe_str(ai_data.get("remediation", ""))[:300]
                                story.append(Paragraph(f"<b>Remediation:</b> {remediation}", styles["Normal"]))
                    except (json.JSONDecodeError, TypeError):
                        pass
                
                # Tags
                if finding.get("tags"):
                    try:
                        tags = finding.get("tags")
                        if isinstance(tags, str):
                            tags = json.loads(tags) if tags else []
                        if tags and isinstance(tags, list):
                            tags_str = ", ".join(self._safe_str(str(t))[:20] for t in tags[:5])
                            story.append(Paragraph(f"<b>Tags:</b> {tags_str}", styles["Normal"]))
                    except (json.JSONDecodeError, TypeError):
                        pass
                
                story.append(Spacer(1, 0.15 * inch))
                
                # Steps to reproduce section
                steps_to_reproduce = {}
                if finding.get("extracted_results"):
                    try:
                        extracted = json.loads(finding["extracted_results"]) if isinstance(finding["extracted_results"], str) else finding["extracted_results"]
                        steps_to_reproduce = extracted.get("steps_to_reproduce", {})
                    except (json.JSONDecodeError, TypeError):
                        pass
                
                steps = steps_to_reproduce.get("steps", []) if steps_to_reproduce else []
                screenshots = steps_to_reproduce.get("screenshots", []) if steps_to_reproduce else []
                
                if steps:
                    story.append(Paragraph("<b>Steps to Reproduce:</b>", styles["Heading3"]))
                    for idx, step in enumerate(steps, 1):
                        story.append(Paragraph(f"<b>Step {idx}:</b> {self._safe_str(step)}", styles["Normal"]))
                        if screenshots and idx <= len(screenshots):
                            screenshot_path = screenshots[idx-1]
                            if screenshot_path and os.path.exists(screenshot_path):
                                try:
                                    img = Image(screenshot_path, width=4*inch, height=2.5*inch)
                                    story.append(img)
                                    story.append(Spacer(1, 0.1 * inch))
                                except Exception as e:
                                    story.append(Paragraph(f"<b>Step Screenshot Error:</b> {e}", styles["Normal"]))
                    
                    # Embed evidence image if available
                    screenshot_path = finding.get("poc_screenshot") or (finding.get("evidence") and finding["evidence"].get("screenshot"))
                    if screenshot_path and os.path.exists(screenshot_path):
                        try:
                            story.append(Paragraph("<b>Evidence Screenshot:</b>", styles["Normal"]))
                            img = Image(screenshot_path, width=5*inch, height=3*inch)
                            story.append(img)
                            story.append(Spacer(1, 0.1 * inch))
                        except Exception as e:
                            story.append(Paragraph(f"<b>Screenshot Error:</b> {e}", styles["Normal"]))
        else:
            story.append(Paragraph("No vulnerabilities found in this scan.", styles["Normal"]))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def _build_summary_data(self, findings: List[Dict[str, Any]]) -> List[List[str]]:
        """Build summary statistics data."""
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")
        info = sum(1 for f in findings if f.get("severity") == "info")

        return [
            ["Metric", "Count"],
            ["Total Vulnerabilities", str(total)],
            ["Critical", str(critical)],
            ["High", str(high)],
            ["Medium", str(medium)],
            ["Low", str(low)],
            ["Informational", str(info)],
        ]

    def _build_severity_data(self, findings: List[Dict[str, Any]]) -> List[List[str]]:
        """Build severity breakdown data."""
        severity_counts = {sev: 0 for sev in self.severity_order}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        data = [["Severity", "Count", "Percentage"]]
        total = len(findings) or 1
        for sev in self.severity_order:
            count = severity_counts[sev]
            pct = round((count / total) * 100, 1)
            data.append([sev.capitalize(), str(count), f"{pct}%"])
        
        return data

    def _sort_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity."""
        return sorted(
            findings,
            key=lambda f: (
                self.severity_order.index(f.get("severity", "info").lower()),
                f.get("name", ""),
            ),
        )

    def _get_table_style(self) -> TableStyle:
        """Get standard table styling."""
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e2028")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), HexColor("#f9fafb")),
            ("GRID", (0, 0), (-1, -1), 1, HexColor("#e5e7eb")),
            ("TOPPADDING", (0, 1), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
        ])

    @staticmethod
    def _safe_str(value: Any) -> str:
        """Safely convert value to string."""
        if value is None:
            return "N/A"
        return str(value).replace("<", "&lt;").replace(">", "&gt;")
