# ares_cli/reporter.py
"""
Enhanced Report Generator for ARES CLI
Professional PDF, HTML, and JSON report generation
"""
import os
import json
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .config import AresConfig
from .display import print_success, print_error

@dataclass  
class ReportData:
    """Container for report data"""
    target: str
    profile: str
    duration: str
    timestamp: str
    
    # Findings
    open_ports: List[Dict]
    subdomains: List[str]
    technologies: List[str]
    endpoints: List[str]
    vulnerabilities: List[Dict]
    
    # Scoring
    severity_score: float
    severity_level: str
    
    # Metadata
    tools_used: List[str]
    messages: List[str]
    waf_detected: bool
    
    # AI Summary
    executive_summary: str = ""
    
    # Compliance
    compliance_results: Dict = None

class ReportGenerator:
    """
    Multi-format report generator for ARES scans.
    Produces professional PDF, interactive HTML, and JSON exports.
    """
    
    def __init__(self, config: Optional[AresConfig] = None):
        self.config = config or AresConfig()
    
    def _generate_mitre_mapping(self, data: ReportData) -> Dict[str, Any]:
        """Generate MITRE ATT&CK mapping from findings"""
        mapping = {
            "T1595": {"name": "Active Scanning", "findings": [], "count": 0},
            "T1190": {"name": "Exploit Public-Facing Application", "findings": [], "count": 0},
            "T1589": {"name": "Gather Victim Identity Information", "findings": [], "count": 0},
            "T1087": {"name": "Account Discovery", "findings": [], "count": 0},
        }
        
        # Map findings to techniques
        if data.open_ports:
            mapping["T1595"]["findings"].append(f"Discovered {len(data.open_ports)} open ports")
            mapping["T1595"]["count"] += 1
            
        if data.subdomains:
            mapping["T1595"]["findings"].append(f"Enumerated {len(data.subdomains)} subdomains")
            mapping["T1595"]["count"] += 1
            
        for vuln in data.vulnerabilities:
            name = vuln.get("name", "").lower()
            if "sql" in name or "injection" in name or "rce" in name:
                mapping["T1190"]["findings"].append(vuln.get("name"))
                mapping["T1190"]["count"] += 1
                
        if data.endpoints:
            mapping["T1595"]["findings"].append(f"Crawled {len(data.endpoints)} endpoints")
            mapping["T1595"]["count"] += 1
            
        return {k: v for k, v in mapping.items() if v["count"] > 0}

    def _generate_quick_wins_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for quick wins section"""
        from .remediation_db import get_quick_wins
        
        quick_wins = get_quick_wins(vulnerabilities)
        
        if not quick_wins:
            return "<p style='color: var(--cyber);'>No quick wins identified - good security posture!</p>"
        
        html = "<div class='quick-wins'>"
        for i, win in enumerate(quick_wins[:5], 1):
            html += f"""
            <div style="background: rgba(0,255,65,0.1); padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid var(--cyber);">
                <strong style="color: var(--cyber);">#{i} {win['title']}</strong>
                <p style="margin: 5px 0;">{win['fix']}</p>
                {f'<code style="background: #1a1a2e; padding: 5px; display: block; margin-top: 5px; font-size: 12px;">{win["command"]}</code>' if win.get('command') else ''}
            </div>
            """
        html += "</div>"
        return html
    
    def _generate_roadmap_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for remediation roadmap"""
        from .remediation_db import generate_remediation_roadmap
        
        roadmap = generate_remediation_roadmap(vulnerabilities)
        
        if not roadmap:
            return "<p>No remediation items - target appears secure.</p>"
        
        html = "<div class='roadmap'>"
        
        # Group by timeline
        phases = {}
        for item in roadmap:
            timeline = item.get("timeline", "As needed")
            if timeline not in phases:
                phases[timeline] = []
            phases[timeline].append(item)
        
        priority_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14", 
            "Medium": "#ffc107",
            "Low": "#17a2b8"
        }
        
        for timeline, items in phases.items():
            html += f"<h4 style='color: var(--accent); margin-top: 15px;'>📅 {timeline}</h4>"
            for item in items:
                color = priority_colors.get(item['priority'], '#6c757d')
                html += f"""
                <div style="display: flex; align-items: start; margin: 8px 0; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 5px;">
                    <span style="background: {color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-right: 10px;">{item['priority']}</span>
                    <div>
                        <strong>{item['title']}</strong>
                        <span style="color: var(--text-muted); font-size: 12px;"> ({item['effort']} effort)</span>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">{item['cwe']} | {item['owasp']}</div>
                    </div>
                </div>
                """
        
        html += "</div>"
        return html

    def generate(
        self,
        scan_results: Dict[str, Any],
        output_dir: str,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        Generate reports in multiple formats.
        
        Args:
            scan_results: Scan state dictionary
            output_dir: Output directory for reports
            formats: List of formats (pdf, html, json, linkedin)
            
        Returns:
            Dict mapping format to file path
        """
        if formats is None:
            formats = ["pdf", "html", "json"]
        
        # Prepare output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Prepare report data
        data = self._prepare_data(scan_results)
        
        # Generate executive summary with AI
        if self.config.enable_ai_analysis:
            data.executive_summary = self._generate_ai_summary(data)
        
        # Generate compliance mapping
        if self.config.enable_compliance_check:
            data.compliance_results = self._generate_compliance(data)
        
        # Generate reports
        generated = {}
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"ares_report_{data.target.replace('.', '_')}_{timestamp}"
        
        if "json" in formats:
            json_path = os.path.join(output_dir, f"{base_name}.json")
            self._generate_json(data, json_path)
            generated["json"] = json_path
        
        if "pdf" in formats:
            pdf_path = os.path.join(output_dir, f"{base_name}.pdf")
            self._generate_pdf(data, pdf_path)
            generated["pdf"] = pdf_path
        
        if "html" in formats:
            html_path = os.path.join(output_dir, f"{base_name}.html")
            self._generate_html(data, html_path)
            generated["html"] = html_path
        
        return generated
    
    def _prepare_data(self, scan_results: Dict) -> ReportData:
        """Prepare report data from scan results"""
        return ReportData(
            target=scan_results.get("target", "Unknown"),
            profile=scan_results.get("profile", "Unknown"),
            duration=scan_results.get("duration", "N/A"),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            open_ports=scan_results.get("open_ports", []) if isinstance(scan_results.get("open_ports"), list) else [],
            subdomains=scan_results.get("subdomains", []),
            technologies=scan_results.get("technologies", []),
            endpoints=scan_results.get("endpoints", []),
            vulnerabilities=scan_results.get("vulnerabilities", []),
            severity_score=scan_results.get("severity_score", 0.0),
            severity_level=scan_results.get("severity_level", "LOW"),
            tools_used=scan_results.get("tools_used", []),
            messages=scan_results.get("messages", []),
            waf_detected=scan_results.get("waf_detected", False),
        )
    
    def _generate_ai_summary(self, data: ReportData) -> str:
        """Generate AI-powered executive summary"""
        try:
            from langchain_ollama import ChatOllama
            from langchain_core.messages import SystemMessage
            
            llm = ChatOllama(
                model=self.config.ollama_model,
                base_url=self.config.ollama_host,
                temperature=0.3,
            )
            
            context = f"""
            Target: {data.target}
            Risk Score: {data.severity_score}/10 ({data.severity_level})
            Open Ports: {len(data.open_ports)}
            Vulnerabilities: {len(data.vulnerabilities)}
            Technologies: {', '.join(data.technologies[:5])}
            WAF Detected: {data.waf_detected}
            """
            
            prompt = f"""You are a Senior Penetration Tester writing an executive summary.
            
            Assessment Context:
            {context}
            
            Write a 2-3 sentence professional executive summary for executives.
            Focus on business impact and key risks.
            Start directly with the summary, no headers."""
            
            response = llm.invoke([SystemMessage(content=prompt)])
            return response.content.strip()
            
        except Exception as e:
            # Fallback summary
            return (
                f"Security assessment of {data.target} revealed a {data.severity_level} risk profile "
                f"with {len(data.vulnerabilities)} vulnerabilities across {len(data.open_ports)} open ports. "
                f"Immediate remediation is {'required' if data.severity_score >= 7 else 'recommended'}."
            )
    
    def _generate_compliance(self, data: ReportData) -> Dict:
        """Generate compliance mapping"""
        try:
            from backend.reports.compliance import compliance_analyzer, ComplianceFramework
            
            # Convert vulnerabilities to findings format
            findings = []
            for vuln in data.vulnerabilities:
                findings.append({
                    "type": vuln.get("name", ""),
                    "name": vuln.get("name", ""),
                    "severity": vuln.get("severity", ""),
                    "evidence": vuln.get("description", ""),
                })
            
            reports = compliance_analyzer.analyze_findings(
                findings,
                [ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA]
            )
            
            return {
                name: {
                    "passed": r.passed,
                    "failed": r.failed,
                    "compliance_percentage": r.compliance_percentage,
                    "summary": r.summary,
                }
                for name, r in reports.items()
            }
            
        except Exception as e:
            return {}
    
    def _generate_json(self, data: ReportData, output_path: str) -> None:
        """Generate JSON report with remediation guidance"""
        from .remediation_db import get_quick_wins, generate_remediation_roadmap, get_remediation
        
        # Generate remediation data
        quick_wins = get_quick_wins(data.vulnerabilities)
        roadmap = generate_remediation_roadmap(data.vulnerabilities)
        
        # Enrich vulnerabilities with remediation
        enriched_vulns = []
        for vuln in data.vulnerabilities:
            vuln_copy = dict(vuln)
            remediation = get_remediation(vuln.get("name", ""))
            if remediation:
                vuln_copy["remediation"] = {
                    "title": remediation.title,
                    "fix": remediation.fix_steps[0] if remediation.fix_steps else "",
                    "commands": remediation.commands[:2],
                    "effort": remediation.effort,
                    "cwe": remediation.cwe_id,
                    "owasp": remediation.owasp_category,
                    "references": remediation.references[:2],
                }
            enriched_vulns.append(vuln_copy)
        
        report = {
            "meta": {
                "generated_by": "ARES v2.0.1",
                "timestamp": data.timestamp,
                "target": data.target,
                "profile": data.profile,
                "duration": data.duration,
            },
            "summary": {
                "severity_score": data.severity_score,
                "severity_level": data.severity_level,
                "executive_summary": data.executive_summary,
            },
            "findings": {
                "open_ports": data.open_ports,
                "subdomains": data.subdomains,
                "technologies": data.technologies,
                "endpoints": data.endpoints,
                "endpoints_count": len(data.endpoints),
                "vulnerabilities": enriched_vulns,
            },
            "remediation": {
                "quick_wins": quick_wins,
                "roadmap": roadmap,
            },
            "compliance": data.compliance_results or {},
            "audit": {
                "tools_used": data.tools_used,
                "waf_detected": data.waf_detected,
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print_success(f"JSON report: {output_path}")
    
    def _generate_pdf(self, data: ReportData, output_path: str) -> None:
        """Generate professional PDF report"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.colors import HexColor
            
            c = canvas.Canvas(output_path, pagesize=letter)
            width, height = letter
            
            # Colors
            primary = HexColor("#1a1a2e")
            accent = HexColor("#e94560")
            cyber = HexColor("#00ff41")
            
            # Header
            c.setFillColor(primary)
            c.rect(0, height - 120, width, 120, fill=True)
            
            c.setFillColor(cyber)
            c.setFont("Helvetica-Bold", 28)
            c.drawString(50, height - 50, "ARES")
            
            c.setFillColor(HexColor("#ffffff"))
            c.setFont("Helvetica", 14)
            c.drawString(50, height - 75, "Autonomous Recon & Exploitation System")
            c.setFont("Helvetica", 10)
            c.drawString(50, height - 95, f"Security Assessment Report | {data.timestamp}")
            
            # Target info box
            y = height - 160
            c.setFillColor(HexColor("#2d2d2d"))
            c.roundRect(40, y - 60, width - 80, 70, 5, fill=True)
            
            c.setFillColor(HexColor("#ffffff"))
            c.setFont("Helvetica-Bold", 12)
            c.drawString(60, y - 15, f"TARGET: {data.target}")
            c.setFont("Helvetica", 10)
            c.drawString(60, y - 35, f"Profile: {data.profile} | Duration: {data.duration}")
            c.drawString(60, y - 50, f"Tools: {', '.join(data.tools_used)}")
            
            # Severity indicator
            severity_colors = {
                "CRITICAL": "#ff0000",
                "HIGH": "#ff6600",
                "MEDIUM": "#ffcc00",
                "LOW": "#00ff00",
            }
            sev_color = HexColor(severity_colors.get(data.severity_level, "#888888"))
            c.setFillColor(sev_color)
            c.roundRect(width - 180, y - 55, 120, 50, 5, fill=True)
            c.setFillColor(HexColor("#000000"))
            c.setFont("Helvetica-Bold", 14)
            c.drawCentredString(width - 120, y - 25, data.severity_level)
            c.setFont("Helvetica", 12)
            c.drawCentredString(width - 120, y - 45, f"{data.severity_score}/10")
            
            # Executive Summary
            y = height - 250
            c.setFillColor(HexColor("#000000"))
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "EXECUTIVE SUMMARY")
            c.setStrokeColor(accent)
            c.setLineWidth(2)
            c.line(50, y - 5, 200, y - 5)
            
            y -= 25
            c.setFont("Helvetica", 10)
            
            # Wrap summary text
            summary_lines = textwrap.wrap(data.executive_summary, width=95)
            for line in summary_lines[:5]:
                c.drawString(50, y, line)
                y -= 14
            
            # Findings Summary
            y -= 20
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y, "FINDINGS SUMMARY")
            c.line(50, y - 5, 200, y - 5)
            
            y -= 30
            c.setFont("Helvetica", 11)
            findings = [
                f"• Open Ports: {len(data.open_ports)}",
                f"• Subdomains: {len(data.subdomains)}",
                f"• Technologies: {len(data.technologies)}",
                f"• Endpoints: {len(data.endpoints)}",
                f"• Vulnerabilities: {len(data.vulnerabilities)}",
                f"• WAF Detected: {'Yes' if data.waf_detected else 'No'}",
            ]
            for finding in findings:
                c.drawString(60, y, finding)
                y -= 16
            
            # Vulnerabilities
            if data.vulnerabilities:
                y -= 20
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, y, "TOP VULNERABILITIES")
                c.line(50, y - 5, 210, y - 5)
                
                y -= 25
                c.setFont("Helvetica", 10)
                
                for vuln in data.vulnerabilities[:8]:
                    sev = vuln.get("severity", "info").upper()
                    name = vuln.get("name", "Unknown")[:60]
                    
                    # Severity color dot
                    dot_colors = {
                        "CRITICAL": "#ff0000",
                        "HIGH": "#ff6600",
                        "MEDIUM": "#ffcc00",
                        "LOW": "#00ccff",
                    }
                    c.setFillColor(HexColor(dot_colors.get(sev, "#888888")))
                    c.circle(60, y + 3, 4, fill=True)
                    
                    cvss = vuln.get("cvss_score") or vuln.get("cvss_base", "N/A")
                    cve = vuln.get("cve_id") or vuln.get("cve", "N/A")
                    
                    c.setFillColor(HexColor("#000000"))
                    c.drawString(75, y, f"[{sev}] {name} (CVSS: {cvss} | CVE: {cve})")
                    y -= 14
                    
                    if y < 100:
                        c.showPage()
                        y = height - 50
            
            # Compliance Section
            if data.compliance_results:
                y -= 30
                if y < 150:
                    c.showPage()
                    y = height - 50
                
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, y, "COMPLIANCE STATUS")
                c.line(50, y - 5, 200, y - 5)
                
                y -= 25
                c.setFont("Helvetica", 10)
                
                for framework, results in data.compliance_results.items():
                    pct = results.get("compliance_percentage", 0)
                    status = "PASS" if pct >= 70 else "FAIL"
                    c.drawString(60, y, f"• {framework}: {pct:.1f}% [{status}]")
                    y -= 14
            
            # Footer
            c.setFillColor(HexColor("#888888"))
            c.setFont("Helvetica", 8)
            c.drawString(50, 30, f"Generated by ARES v2.0.1 | {data.timestamp}")
            c.drawString(width - 150, 30, "CONFIDENTIAL")
            
            c.save()
            print_success(f"PDF report: {output_path}")
            
        except ImportError:
            print_error("ReportLab not installed. Install with: pip install reportlab")
        except Exception as e:
            print_error(f"PDF generation failed: {e}")
    
    def _generate_html(self, data: ReportData, output_path: str) -> None:
        """Generate interactive HTML report"""
        
        # Vulnerability rows
        vuln_rows = ""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        
        for vuln in data.vulnerabilities[:20]:
            sev = vuln.get("severity", "info").lower()
            color = severity_colors.get(sev, "#6c757d")
            
            cvss = vuln.get("cvss_score") or vuln.get("cvss_base", "N/A")
            cve = vuln.get("cve_id") or vuln.get("cve", "N/A")
            
            vuln_rows += f"""
            <tr>
                <td><span class="badge" style="background-color: {color}">{sev.upper()}</span></td>
                <td>{vuln.get("name", "Unknown")[:50]}</td>
                <td>{cvss}</td>
                <td>{cve}</td>
            </tr>
            """
        
        # Ports list
        ports_list = ", ".join([f"{p.get('port')}/{p.get('service', '?')}" for p in data.open_ports[:20]])
        
        # Technologies list
        tech_badges = "".join([f'<span class="tech-badge">{t}</span>' for t in data.technologies[:10]])
        
        # Compliance cards
        compliance_cards = ""
        if data.compliance_results:
            for framework, results in data.compliance_results.items():
                pct = results.get("compliance_percentage", 0)
                status_class = "success" if pct >= 70 else "danger"
                compliance_cards += f"""
                <div class="compliance-card">
                    <h4>{framework}</h4>
                    <div class="compliance-score {status_class}">{pct:.1f}%</div>
                    <p>Passed: {results.get("passed", 0)} | Failed: {results.get("failed", 0)}</p>
                </div>
                """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARES Security Report - {data.target}</title>
    <style>
        :root {{
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #e94560;
            --cyber: #00ff41;
            --text: #ffffff;
            --text-muted: #a0a0a0;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            color: var(--text);
            line-height: 1.6;
        }}
        
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: rgba(0, 0, 0, 0.3);
            padding: 40px;
            border-radius: 15px;
            margin-bottom: 30px;
            border: 1px solid rgba(233, 69, 96, 0.3);
        }}
        
        .logo {{
            font-size: 48px;
            font-weight: bold;
            color: var(--cyber);
            text-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
        }}
        
        .subtitle {{ color: var(--text-muted); margin-top: 5px; }}
        
        .target-info {{
            background: rgba(0, 0, 0, 0.4);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .target-name {{ font-size: 24px; color: var(--accent); }}
        
        .severity-badge {{
            padding: 15px 30px;
            border-radius: 10px;
            font-weight: bold;
            font-size: 18px;
        }}
        
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #000; }}
        .severity-low {{ background: #28a745; }}
        
        .card {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .card h3 {{
            color: var(--accent);
            margin-bottom: 15px;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 10px;
        }}
        
        .summary {{ font-size: 16px; line-height: 1.8; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            background: rgba(0, 255, 65, 0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(0, 255, 65, 0.3);
        }}
        
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: var(--cyber);
        }}
        
        .stat-label {{ color: var(--text-muted); margin-top: 5px; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        th {{ background: rgba(0, 0, 0, 0.3); color: var(--accent); }}
        tr:hover {{ background: rgba(255, 255, 255, 0.05); }}
        
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        
        .tech-badge {{
            display: inline-block;
            padding: 5px 12px;
            margin: 3px;
            background: rgba(0, 255, 65, 0.2);
            border: 1px solid var(--cyber);
            border-radius: 20px;
            font-size: 13px;
        }}
        
        .compliance-card {{
            display: inline-block;
            background: rgba(0, 0, 0, 0.4);
            padding: 20px;
            border-radius: 10px;
            margin: 10px;
            min-width: 200px;
            text-align: center;
        }}
        
        .compliance-score {{
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .compliance-score.success {{ color: #28a745; }}
        .compliance-score.danger {{ color: #dc3545; }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 14px;
        }}
        
        @media (max-width: 768px) {{
            .target-info {{ flex-direction: column; text-align: center; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">ARES</div>
            <div class="subtitle">Autonomous Recon & Exploitation System | Security Assessment Report</div>
            
            <div class="target-info">
                <div>
                    <div class="target-name">{data.target}</div>
                    <div>Profile: {data.profile} | Duration: {data.duration} | {data.timestamp}</div>
                </div>
                <div class="severity-badge severity-{data.severity_level.lower()}">
                    {data.severity_level} ({data.severity_score}/10)
                </div>
            </div>
        </header>
        
        <div class="card">
            <h3>📋 Executive Summary</h3>
            <p class="summary">{data.executive_summary}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value">{len(data.open_ports)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(data.subdomains)}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(data.endpoints)}</div>
                <div class="stat-label">Endpoints</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(data.vulnerabilities)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(data.technologies)}</div>
                <div class="stat-label">Technologies</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{'🛡️' if data.waf_detected else '❌'}</div>
                <div class="stat-label">WAF Detected</div>
            </div>
        </div>
        
        <div class="card">
            <h3>🔌 Open Ports</h3>
            <p>{ports_list if ports_list else 'No open ports detected'}</p>
        </div>
        
        <div class="card">
            <h3>🔧 Technologies Detected</h3>
            <div>{tech_badges if tech_badges else 'No technologies detected'}</div>
        </div>
        
        <div class="card">
            <h3>🚨 Vulnerabilities</h3>
            {'<table><tr><th>Severity</th><th>Name</th><th>CVSS</th><th>CVE</th></tr>' + vuln_rows + '</table>' if vuln_rows else '<p>No vulnerabilities detected</p>'}
        </div>
        
        <div class="card" style="border-color: var(--cyber);">
            <h3>⚡ Quick Wins (High Impact, Low Effort)</h3>
            {self._generate_quick_wins_html(data.vulnerabilities)}
        </div>
        
        <div class="card">
            <h3>🗺️ Remediation Roadmap</h3>
            {self._generate_roadmap_html(data.vulnerabilities)}
        </div>
        
        {'<div class="card"><h3>📜 Compliance Status</h3>' + compliance_cards + '</div>' if compliance_cards else ''}
        
        <footer>
            <p>Generated by ARES v2.0.1 - Autonomous Recon & Exploitation System</p>
            <p>Developed by <a href="https://github.com/farixzz" style="color: var(--cyber);">farixzz</a> | {data.timestamp}</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        print_success(f"HTML report: {output_path}")
