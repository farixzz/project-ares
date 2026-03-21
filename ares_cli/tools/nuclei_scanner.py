# backend/tools/nuclei_scanner.py
"""
Nuclei - Modern Vulnerability Scanner Integration
Uses template-based scanning for fast, accurate vulnerability detection
"""
import subprocess
import json
import shutil
from typing import List, Dict
from dataclasses import dataclass, asdict
from enum import Enum

class NucleiSeverity(Enum):
    """Nuclei severity levels aligned with CVSS"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

@dataclass
class NucleiVulnerability:
    """Structured vulnerability finding from Nuclei"""
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    tags: List[str] = None
    reference: List[str] = None
    cvss_score: float = 0.0
    cve_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)

class NucleiScanner:
    """
    Nuclei vulnerability scanner wrapper.
    Executes template-based scans and returns structured results.
    """
    
    # Template categories for targeted scanning
    TEMPLATE_CATEGORIES = {
        "cves": "http/cves/",
        "vulnerabilities": "http/vulnerabilities/",
        "exposures": "http/exposures/",
        "misconfigurations": "http/misconfiguration/",
        "default_logins": "http/default-logins/",
        "takeovers": "http/takeovers/",
        "technologies": "http/technologies/",
    }
    
    SEVERITY_SCORES = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.5,
        "low": 3.0,
        "info": 0.0,
    }

    def __init__(self, templates_path: str = None):
        self.templates_path = templates_path
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Verify Nuclei is installed"""
        if not shutil.which("nuclei"):
            print("[!] WARNING: Nuclei not found in PATH")
            return False
        return True
    
    def scan(
        self,
        target: str,
        templates: List[str] = None,
        severity: List[str] = None,
        rate_limit: int = 150,
        timeout: int = 30,
        concurrency: int = 25,
        silent: bool = True,
        tags: List[str] = None,
        exclude_tags: List[str] = None,
    ) -> Dict:
        """
        Execute Nuclei scan against target.
        
        Args:
            target: URL or IP to scan
            templates: Specific template paths/categories (default: cves, vulnerabilities)
            severity: Filter by severity levels (critical, high, medium, low, info)
            rate_limit: Max requests per second
            timeout: Request timeout in seconds
            concurrency: Number of parallel templates
            silent: Suppress banner output
            tags: Filter templates by tags (e.g., ["sqli", "xss"])
            exclude_tags: Exclude templates with these tags
            
        Returns:
            Dict with vulnerabilities, stats, and raw output
        """
        print(f"[*] TOOL: Nuclei scanning {target}")
        
        if not shutil.which("nuclei"):
            return {"error": "Nuclei not installed", "vulnerabilities": []}
        
        import tempfile
        import os
        fd, output_file = tempfile.mkstemp(suffix=".json", prefix="nuclei_")
        os.close(fd)
        
        cmd = [
            "nuclei",
            "-target", target,
            "-je", output_file,
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout),
            "-concurrency", str(concurrency),
            "-retries", "2",
        ]
        
        if silent:
            cmd.append("-silent")
        
        # Add template filters
        if templates:
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
        else:
            # Default: broad scan for CVEs, vulns, exposures, misconfigs
            cmd.extend([
                "-t", "http/cves/",
                "-t", "http/vulnerabilities/",
                "-t", "http/exposures/",
                "-t", "http/misconfiguration/",
                "-t", "http/technologies/",
            ])
        
        # Severity filter — include info to catch EOL/tech findings
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        else:
            cmd.extend(["-severity", "critical,high,medium,low,info"])
        
        # Tag filters
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        
        scan_error = None
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 60 minute max
            )
            raw_stderr = result.stderr[:500] if result.stderr else ""
            
        except subprocess.TimeoutExpired as e:
            scan_error = "Scan timeout exceeded, partial results returned"
            raw_stderr = e.stderr[:500] if e and hasattr(e, 'stderr') and e.stderr else ""
        except Exception as e:
            scan_error = str(e)
            raw_stderr = ""
            
        vulnerabilities = self._parse_output(output_file)
        
        try:
            os.remove(output_file)
        except OSError:
            pass
            
        res = {
            "vulnerabilities": vulnerabilities,
            "stats": self._calculate_stats(vulnerabilities),
            "target": target,
            "templates_used": templates or ["http/cves/", "http/vulnerabilities/", "http/exposures/"],
            "raw_stderr": raw_stderr,
        }
        if scan_error:
            res["error"] = scan_error
            
        return res
    
    def _parse_output(self, output_file: str) -> List[NucleiVulnerability]:
        """Parse Nuclei JSON output into structured vulnerabilities"""
        vulnerabilities = []
        
        try:
            with open(output_file, 'r') as f:
                content = f.read().strip()
                if not content:
                    return []
                
                # Check if it's a JSON array or JSON lines
                if content.startswith('['):
                    try:
                        data_list = json.loads(content)
                        if not isinstance(data_list, list):
                            data_list = [data_list]
                    except json.JSONDecodeError:
                        data_list = []
                else:
                    # JSON lines parsing
                    data_list = []
                    for line in content.split('\n'):
                        if not line.strip():
                            continue
                        try:
                            data_list.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

                for data in data_list:
                    if not isinstance(data, dict):
                        continue
                    vuln = NucleiVulnerability(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", "Unknown"),
                        severity=data.get("info", {}).get("severity", "unknown"),
                        host=data.get("host", ""),
                        matched_at=data.get("matched-at", ""),
                        description=data.get("info", {}).get("description", ""),
                        tags=data.get("info", {}).get("tags", []),
                        reference=data.get("info", {}).get("reference", []),
                        cvss_score=self._get_cvss(data),
                        cve_id=self._extract_cve(data),
                    )
                    vulnerabilities.append(vuln)
        except Exception:
            pass
        
        return vulnerabilities
    
    def _get_cvss(self, data: dict) -> float:
        """Extract or estimate CVSS score"""
        # Check for explicit CVSS
        classification = data.get("info", {}).get("classification", {})
        if "cvss-score" in classification:
            return float(classification["cvss-score"])
        
        # Estimate from severity
        severity = data.get("info", {}).get("severity", "info")
        return self.SEVERITY_SCORES.get(severity, 0.0)
    
    def _extract_cve(self, data: dict) -> str:
        """Extract CVE ID if present"""
        classification = data.get("info", {}).get("classification", {})
        cve_list = classification.get("cve-id", [])
        if cve_list and isinstance(cve_list, list):
            return cve_list[0]
        return ""
    
    def _calculate_stats(self, vulns: List[NucleiVulnerability]) -> Dict:
        """Calculate vulnerability statistics"""
        stats = {
            "total": len(vulns),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "max_cvss": 0.0,
            "cves_found": [],
        }
        
        for v in vulns:
            severity = v.severity.lower()
            if severity in stats:
                stats[severity] += 1
            if v.cvss_score > stats["max_cvss"]:
                stats["max_cvss"] = v.cvss_score
            if v.cve_id:
                stats["cves_found"].append(v.cve_id)
        
        return stats
    
    def quick_scan(self, target: str) -> Dict:
        """Fast scan with essential templates — includes all CVE years and tech detection"""
        return self.scan(
            target=target,
            templates=[
                "http/cves/",
                "http/vulnerabilities/",
                "http/technologies/",
                "http/misconfiguration/",
            ],
            severity=["critical", "high", "medium", "low", "info"],
            rate_limit=200,
            concurrency=25,
        )
    
    def full_scan(self, target: str) -> Dict:
        """Comprehensive scan with all template categories"""
        return self.scan(
            target=target,
            templates=list(self.TEMPLATE_CATEGORIES.values()),
            severity=["critical", "high", "medium", "low", "info"],
            rate_limit=100,
            concurrency=25,
        )
