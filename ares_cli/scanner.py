# ares_cli/scanner.py
"""
Autonomous Scanning Engine for ARES CLI
AI-driven tool selection and execution with state machine workflow
"""
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .config import ScanProfile, AresConfig, SCAN_PROFILES
from .display import (
    console, print_phase, print_tool, print_finding, 
    print_success, print_error, print_warning, print_info,
    create_scan_progress
)

class ScanPhase(Enum):
    """Scanning phases"""
    INIT = auto()
    SUBDOMAIN = auto()
    NETWORK = auto()
    FINGERPRINT = auto()
    CRAWL = auto()
    FUZZ = auto()
    VULN_SCAN = auto()
    EXPLOIT = auto()
    REPORT = auto()
    COMPLETE = auto()

@dataclass
class ScanState:
    """Current state of the scan"""
    target: str
    profile: ScanProfile
    phase: ScanPhase = ScanPhase.INIT
    start_time: datetime = field(default_factory=datetime.now)
    
    # Results storage
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    exploitation_results: Dict = field(default_factory=dict)
    
    # Metadata
    messages: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    
    # Flags
    has_web_service: bool = False
    waf_detected: bool = False
    stealth_mode: bool = False
    
    # Scoring
    severity_score: float = 0.0
    severity_level: str = "LOW"
    
    def add_message(self, msg: str) -> None:
        self.messages.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def get_duration(self) -> str:
        elapsed = datetime.now() - self.start_time
        minutes = int(elapsed.total_seconds() // 60)
        seconds = int(elapsed.total_seconds() % 60)
        return f"{minutes}m {seconds}s"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            "target": self.target,
            "profile": self.profile.name,
            "duration": self.get_duration(),
            "open_ports": self.open_ports,
            "open_ports_count": len(self.open_ports),
            "subdomains": self.subdomains,
            "subdomain_count": len(self.subdomains),
            "technologies": self.technologies,
            "tech_count": len(self.technologies),
            "endpoints": self.endpoints,
            "endpoints_count": len(self.endpoints),
            "vulnerabilities": self.vulnerabilities,
            "severity_score": self.severity_score,
            "severity_level": self.severity_level,
            "tools_used": self.tools_used,
            "messages": self.messages,
            "waf_detected": self.waf_detected,
            "exploitation_results": self.exploitation_results,
        }

def check_ollama_connection(host: str = "http://localhost:11434") -> bool:
    """Check if Ollama is reachable before scan starts."""
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{host}/api/tags",
            headers={"User-Agent": "ARES/2.0.1"}
        )
        resp = urllib.request.urlopen(req, timeout=3)
        return resp.status == 200
    except Exception:
        return False


class AutonomousScanner:
    """
    AI-driven autonomous scanning engine.
    Orchestrates security tools based on findings and target characteristics.
    """
    
    def __init__(self, config: Optional[AresConfig] = None):
        self.config = config or AresConfig()
        self.tools = None
        self.state: Optional[ScanState] = None
        self._progress_callback: Optional[Callable] = None
        self._ai_available: bool = False
        self._init_tools()
    
    def _init_tools(self) -> None:
        """Initialize security tools"""
        try:
            from ares_cli.tools.enhanced_tool_manager import EnhancedReconTools
            self.tools = EnhancedReconTools()
        except ImportError as e:
            print_warning(f"Could not import enhanced tools: {e}")
            self.tools = None
    
    def set_progress_callback(self, callback: Callable[[str, float], None]) -> None:
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def _update_progress(self, message: str, progress: float) -> None:
        """Update progress via callback"""
        if self._progress_callback:
            self._progress_callback(message, progress)
    
    def scan(
        self,
        target: str,
        profile_name: str = "standard",
        dry_run: bool = False
    ) -> ScanState:
        """
        Execute autonomous scan against target.
        
        Args:
            target: IP, hostname, or URL to scan
            profile_name: Scan profile (quick, standard, deep, stealth)
            dry_run: If True, only show what would be done
            
        Returns:
            ScanState with all results
        """
        # Initialize state
        profile = SCAN_PROFILES.get(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile: {profile_name}")
        
        self.state = ScanState(target=target, profile=profile, stealth_mode=profile.stealth_mode)
        self.state.add_message(f"Starting {profile.name} scan on {target}")

        # Check Ollama connectivity and warn loudly if unavailable
        if self.config.enable_ai_analysis:
            self._ai_available = check_ollama_connection(self.config.ollama_host)
            if not self._ai_available:
                print_warning("=" * 60)
                print_warning("  OLLAMA NOT REACHABLE — AI analysis is DISABLED")
                print_warning(f"  Expected at: {self.config.ollama_host}")
                print_warning("  Fix: Run 'ollama serve' on your host machine")
                print_warning("  Then: 'ollama pull mistral' to download the model")
                print_warning("  Docker users: use --ollama-host http://host.docker.internal:11434")
                print_warning("=" * 60)
                self.state.add_message("WARNING: Ollama unavailable — AI analysis disabled")
                # Disable AI for this scan so reporter falls back cleanly
                self.config.enable_ai_analysis = False
            else:
                print_success(f"Ollama connected at {self.config.ollama_host}")
                self.state.add_message("Ollama AI analysis: ENABLED")
        else:
            self._ai_available = False

        if dry_run:
            return self._dry_run()
        
        # Check tools availability
        if not self.tools:
            print_error("Security tools not available. Please check installation.")
            return self.state
        
        # Execute scan phases
        try:
            self._execute_scan()
        except Exception as e:
            self.state.errors.append(str(e))
            print_error(f"Scan error: {e}")
        
        return self.state
    
    def _dry_run(self) -> ScanState:
        """Show what the scan would do without executing"""
        print_info("DRY RUN MODE - No actual scanning will be performed")
        console.print()
        
        profile = self.state.profile
        
        phases = []
        if profile.enable_subdomain:
            phases.append(("Subdomain Enumeration", "subfinder"))
        phases.append(("Network Discovery", "nmap"))
        if profile.enable_fingerprint:
            phases.append(("Technology Fingerprinting", "whatweb"))
        if profile.enable_fuzzing:
            phases.append(("Web Fuzzing", "ffuf"))
        if profile.enable_crawl:
            phases.append(("Web Crawling", "katana"))
        if profile.enable_nuclei:
            phases.append(("Vulnerability Scanning", "nuclei, nikto"))
        if profile.enable_exploitation:
            phases.append(("Exploitation", "sqlmap, commix, hydra"))
        phases.append(("Report Generation", "reporter"))
        
        console.print(f"[bold]Scan Plan for [cyan]{self.state.target}[/cyan][/bold]")
        console.print(f"Profile: [magenta]{profile.name}[/magenta] - {profile.description}")
        console.print(f"Estimated time: [yellow]{profile.timeout_minutes} minutes[/yellow]")
        console.print()
        
        for i, (phase_name, tool) in enumerate(phases, 1):
            console.print(f"  {i}. [cyan]{phase_name}[/cyan] → [dim]{tool}[/dim]")
        
        return self.state
    
    def _execute_scan(self) -> None:
        """Execute the full scan workflow"""
        profile = self.state.profile
        total_phases = 7
        current = 0
        
        with create_scan_progress() as progress:
            task = progress.add_task(f"Scanning {self.state.target}...", total=total_phases)
            
            # Phase 1: Subdomain Discovery
            if profile.enable_subdomain and not self._is_ip(self.state.target):
                self.state.phase = ScanPhase.SUBDOMAIN
                print_phase("Subdomain Discovery", "Enumerating subdomains...")
                self._run_subdomain_enum()
                current += 1
                progress.update(task, completed=current)
            
            # Phase 2: Network Discovery
            self.state.phase = ScanPhase.NETWORK
            print_phase("Network Discovery", "Scanning ports and services...")
            self._run_network_scan()
            current += 1
            progress.update(task, completed=current)
            
            # Phase 3: Technology Fingerprinting
            if profile.enable_fingerprint and self.state.has_web_service:
                self.state.phase = ScanPhase.FINGERPRINT
                print_phase("Technology Fingerprinting", "Identifying technologies...")
                self._run_fingerprint()
                current += 1
                progress.update(task, completed=current)
            
            # Phase 4: Web Fuzzing
            if profile.enable_fuzzing and self.state.has_web_service:
                self.state.phase = ScanPhase.FUZZ
                print_phase("Web Fuzzing", "Discovering hidden paths...")
                self._run_fuzzing()
                current += 1
                progress.update(task, completed=current)
            
            # Phase 5: Web Crawling
            if profile.enable_crawl and self.state.has_web_service:
                self.state.phase = ScanPhase.CRAWL
                print_phase("Web Crawling", "Mapping application endpoints...")
                self._run_crawl()
                current += 1
                progress.update(task, completed=current)
            
            # Phase 6: Vulnerability Scanning
            if profile.enable_nuclei and self.state.has_web_service:
                self.state.phase = ScanPhase.VULN_SCAN
                print_phase("Vulnerability Scanning", "Checking for known vulnerabilities...")
                self._run_vuln_scan()
                current += 1
                progress.update(task, completed=current)
            
            # Phase 7: Exploitation (if enabled and vulnerabilities found)
            if profile.enable_exploitation and self._has_exploitable_vulns():
                self.state.phase = ScanPhase.EXPLOIT
                print_phase("Exploitation", "Testing exploitation vectors...")
                self._run_exploitation()
                current += 1
                progress.update(task, completed=current)
            
            # Calculate final score
            self._calculate_severity()
            progress.update(task, completed=total_phases)
        
        self.state.phase = ScanPhase.COMPLETE
        self.state.add_message("Scan completed successfully")
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
        return bool(re.match(ip_pattern, clean_target))
    
    def _get_url(self, target: str) -> str:
        """Convert target to URL"""
        if target.startswith("http://") or target.startswith("https://"):
            return target
        return f"http://{target}"
    
    def _run_subdomain_enum(self) -> None:
        """Run subdomain enumeration"""
        print_tool("subfinder", self.state.target)
        self.state.tools_used.append("subfinder")
        
        try:
            domain = self.state.target.replace("http://", "").replace("https://", "").split("/")[0]
            result = self.tools.run_subfinder(domain, quick=True)
            
            if result and result.get("subdomains"):
                self.state.subdomains = result["subdomains"]
                print_success(f"Found {len(self.state.subdomains)} subdomains")
                self.state.add_message(f"Discovered {len(self.state.subdomains)} subdomains")
        except Exception as e:
            self.state.errors.append(f"Subdomain enum failed: {e}")
            print_warning(f"Subdomain enumeration failed: {e}")
    
    def _run_network_scan(self) -> None:
        """Run network port scanning"""
        print_tool("nmap", self.state.target)
        self.state.tools_used.append("nmap")
        
        try:
            # Determine scan type based on profile
            scan_type = "fast" if self.state.profile.name == "quick" else "default"
            if self.state.stealth_mode:
                scan_type = "stealth"
            
            result = self.tools.run_nmap(self.state.target, scan_type)
            
            if result and not result[0].get("error"):
                for host in result:
                    for port in host.get("ports", []):
                        port_info = {
                            "port": port.get("port"),
                            "protocol": port.get("protocol", "tcp"),
                            "service": port.get("service", "unknown"),
                            "version": port.get("version", ""),
                        }
                        self.state.open_ports.append(port_info)
                        
                        # Check for web services
                        if port["port"] in [80, 443, 8080, 8443, 3000]:
                            self.state.has_web_service = True
                
                print_success(f"Found {len(self.state.open_ports)} open ports")
                self.state.add_message(f"Network scan: {len(self.state.open_ports)} open ports")
                
                # Force web service flag if any HTTP-related port found
                for port in self.state.open_ports:
                    p = port.get("port", 0)
                    svc = port.get("service", "").lower()
                    if p in [80, 443, 8080, 8443, 3000, 8000, 8888] or "http" in svc:
                        self.state.has_web_service = True
                        break
                
                # Also default to True for any web target if no ports explicitly blocked it
                if not self.state.has_web_service and self.state.open_ports:
                    self.state.has_web_service = True
                
                # Log interesting ports
                for port in self.state.open_ports[:5]:
                    print_info(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
            
            # Fallback: HTTP probe if nmap found no ports (common for cloud/WAF targets)
            if not self.state.open_ports:
                import urllib.request
                import urllib.error
                print_info("  Probing HTTP/HTTPS directly (firewall may be blocking port scan)...")
                
                for port, proto in [(80, "http"), (443, "https")]:
                    try:
                        url = f"{proto}://{self.state.target.replace('http://', '').replace('https://', '').split('/')[0]}/"
                        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                        resp = urllib.request.urlopen(req, timeout=10)
                        if resp.status == 200:
                            self.state.open_ports.append({
                                "port": port,
                                "protocol": "tcp",
                                "service": proto,
                                "version": f"HTTP {resp.status}",
                            })
                            self.state.has_web_service = True
                            print_success(f"  HTTP probe: Port {port} is open ({proto})")
                    except (urllib.error.URLError, TimeoutError, ConnectionError):
                        pass
                
                if self.state.open_ports:
                    self.state.add_message(f"HTTP probe detected {len(self.state.open_ports)} web services")
                
        except Exception as e:
            self.state.errors.append(f"Network scan failed: {e}")
            print_error(f"Network scan failed: {e}")
    
    def _run_fingerprint(self) -> None:
        """Run technology fingerprinting"""
        print_tool("whatweb", self.state.target)
        self.state.tools_used.append("whatweb")
        
        try:
            url = self._get_url(self.state.target)
            result = self.tools.run_whatweb(url, quick=True)
            
            if result and result.get("fingerprint"):
                techs = result["fingerprint"].get("technologies", [])
                # Store name/version strings like "PHP/5.6.40", "nginx/1.19.0"
                tech_strings = []
                for t in techs:
                    name = t.get("name", "")
                    version = t.get("version", "")
                    if name:
                        if version:
                            tech_strings.append(f"{name}/{version}")
                        else:
                            tech_strings.append(name)
                self.state.technologies = tech_strings
                
                # Also store HTTP headers info for tech analysis
                server = result["fingerprint"].get("server", "")
                x_powered = result["fingerprint"].get("x_powered_by", "")
                if server and server not in " ".join(tech_strings).lower():
                    self.state.technologies.append(f"Server:{server}")
                if x_powered and x_powered not in " ".join(tech_strings):
                    self.state.technologies.append(f"X-Powered-By:{x_powered}")
                
                # Check for WAF
                if result.get("analysis", {}).get("has_waf"):
                    self.state.waf_detected = True
                    print_warning("WAF/Firewall detected!")
                
                print_success(f"Detected {len(self.state.technologies)} technologies")
                for tech in self.state.technologies[:8]:
                    print_info(f"    {tech}")
                self.state.add_message(f"Technologies: {', '.join(self.state.technologies[:5])}")
                
                # Analyze technologies for known vulnerabilities (EOL, etc.)
                self._analyze_technologies()
                
        except Exception as e:
            self.state.errors.append(f"Fingerprinting failed: {e}")
            print_warning(f"Fingerprinting failed: {e}")
    
    def _run_fuzzing(self) -> None:
        """Run web fuzzing"""
        print_tool("ffuf", self.state.target)
        self.state.tools_used.append("ffuf")
        
        try:
            url = self._get_url(self.state.target)
            quick_fuzz = self.state.profile.name == "quick" or self.state.stealth_mode
            result = self.tools.run_ffuf(
                url, 
                mode="dir", 
                quick=quick_fuzz,
                threads=self.state.profile.threads,
                rate_limit=self.state.profile.rate_limit
            )
            
            if result and result.get("results"):
                for r in result["results"]:
                    endpoint = r.get("url", "")
                    if endpoint:
                        self.state.endpoints.append(endpoint)
                
                print_success(f"Discovered {len(self.state.endpoints)} paths")
                self.state.add_message(f"Fuzzing found {len(self.state.endpoints)} endpoints")
        except Exception as e:
            self.state.errors.append(f"Fuzzing failed: {e}")
            print_warning(f"Fuzzing failed: {e}")
    
    def _run_crawl(self) -> None:
        """Run web crawling"""
        print_tool("katana", self.state.target)
        self.state.tools_used.append("katana")
        
        try:
            url = self._get_url(self.state.target)
            result = self.tools.run_katana(url, quick=True)
            
            if result and result.get("error"):
                print_warning(f"Katana: {result['error']}")
            
            if result and result.get("endpoints"):
                for ep in result["endpoints"]:
                    if isinstance(ep, dict):
                        self.state.endpoints.append(ep.get("url", ""))
                    else:
                        self.state.endpoints.append(str(ep))
                
                # Remove duplicates
                self.state.endpoints = list(set(self.state.endpoints))
                print_success(f"Crawled {len(self.state.endpoints)} total endpoints")
            elif not (result and result.get("error")):
                print_info("    Katana found no new endpoints")
        except Exception as e:
            self.state.errors.append(f"Crawling failed: {e}")
            print_warning(f"Crawling failed: {e}")
    
    def _run_vuln_scan(self) -> None:
        """Run vulnerability scanning"""
        # Auto-update nuclei templates before scanning
        try:
            import subprocess
            print_info("  Updating Nuclei templates...")
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                print_success("Nuclei templates updated")
            else:
                print_warning("Nuclei template update skipped (non-fatal)")
        except Exception:
            print_warning("Nuclei template update skipped (non-fatal)")

        # 1. Nuclei Scan
        print_tool("nuclei", self.state.target)
        self.state.tools_used.append("nuclei")
        
        try:
            url = self._get_url(self.state.target)
            # quick_scan for quick/standard, full_scan for deep/stealth
            is_quick = self.state.profile.name in ["quick", "standard"]
            result = self.tools.run_nuclei(url, quick=is_quick)
            
            if result and result.get("error"):
                self.state.add_message(f"Nuclei Warning: {result['error']}")
                print_warning(f"Nuclei: {result['error']}")
                
            if result and result.get("vulnerabilities"):
                self.state.vulnerabilities.extend(result["vulnerabilities"])
                
                # Print findings by severity
                stats = result.get("stats", {})
                if stats.get("critical", 0) > 0:
                    print_finding("critical", f"{stats['critical']} critical vulnerabilities found!")
                if stats.get("high", 0) > 0:
                    print_finding("high", f"{stats['high']} high severity vulnerabilities")
                if stats.get("medium", 0) > 0:
                    print_finding("medium", f"{stats['medium']} medium severity vulnerabilities")
                if stats.get("low", 0) > 0:
                    print_finding("low", f"{stats['low']} low severity vulnerabilities")
                if stats.get("info", 0) > 0:
                    print_info(f"    {stats['info']} info level findings")
        except Exception as e:
            print_warning(f"Nuclei scan failed: {e}")
            
        # 2. Nikto Scan (Web Server Scanner)
        if self.state.profile.enable_nuclei:
            print_tool("nikto", self.state.target)
            self.state.tools_used.append("nikto")
            try:
                target_host = self.state.target.replace("http://", "").replace("https://", "").split("/")[0]
                nikto_out = self.tools.run_nikto(target_host)
                if nikto_out and "Nikto" in nikto_out:
                    self.state.add_message("Nikto scan completed")
                    self._parse_nikto_findings(nikto_out)
            except Exception as e:
                print_warning(f"Nikto scan failed: {e}")
    
    def _parse_nikto_findings(self, nikto_output: str) -> None:
        """Parse Nikto output into individual vulnerability entries with proper severity"""
        import re
        
        # Severity classification keywords
        critical_keywords = ["remote code execution", "rce", "command execution", "backdoor", "shell upload"]
        high_keywords = ["sql injection", "sqli", "xss", "cross-site scripting", "file inclusion",
                         "directory traversal", "path traversal", "lfi", "rfi", "xxe",
                         "unrestricted upload", "arbitrary file", "authentication bypass"]
        medium_keywords = ["misconfiguration", "directory listing", "directory indexing",
                           "information disclosure", "default credentials", "default password",
                           "clickjacking", "x-frame-options", "content-type-options",
                           "cors", "cookie", "httponly", "secure flag", "csrf",
                           "server version", "php version", "debug", "phpinfo"]
        
        findings = []
        for line in nikto_output.split("\n"):
            line = line.strip()
            if not line.startswith("+"):
                continue
            # Skip banner/summary lines and stats
            if any(x in line.lower() for x in [
                "start time", "end time", "host(s) tested", "target ip",
                "target hostname", "target port", "server:",
                "requests:", "item(s) reported", "error(s) and",
            ]):
                continue
            
            finding_text = line.lstrip("+ ").strip()
            if len(finding_text) < 10:
                continue
            
            # Classify severity
            finding_lower = finding_text.lower()
            if any(kw in finding_lower for kw in critical_keywords):
                severity = "critical"
                name = "Critical Web Vulnerability"
            elif any(kw in finding_lower for kw in high_keywords):
                severity = "high"
                name = "High Risk Web Vulnerability"
            elif any(kw in finding_lower for kw in medium_keywords):
                severity = "medium"
                name = "Web Server Misconfiguration"
            elif "osvdb-" in finding_lower:
                severity = "medium"
                name = "OSVDB Listed Vulnerability"
            else:
                severity = "low"
                name = "Web Server Finding"
            
            # Extract OSVDB ID if present
            osvdb_match = re.search(r'OSVDB-(\d+)', finding_text)
            vuln_id = f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else ""
            
            findings.append({
                "tool": "nikto",
                "name": name,
                "severity": severity,
                "details": finding_text,
                "vuln_id": vuln_id,
                "cve_id": "N/A",
            })
        
        if findings:
            self.state.vulnerabilities.extend(findings)
            
            # Count by severity
            sev_counts = {}
            for f in findings:
                sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
            
            for sev in ["critical", "high", "medium", "low"]:
                cnt = sev_counts.get(sev, 0)
                if cnt > 0:
                    print_finding(sev, f"Nikto: {cnt} {sev} findings")
            
            self.state.add_message(f"Nikto found {len(findings)} issues")
        else:
            print_info("    Nikto completed with no significant findings")
    
    def _analyze_technologies(self) -> None:
        """Generate vulnerability findings from detected technologies (EOL, known-vulnerable versions)"""
        if not self.state.technologies:
            return
        
        # Known EOL / vulnerable technology patterns
        # Each entry includes CVE references where applicable
        eol_tech = {
            # PHP EOL versions
            "php/5.": {"name": "PHP 5.x End-of-Life", "severity": "high",
                       "cve": "CVE-2019-11043",
                       "details": "PHP 5.x is end-of-life and no longer receives security patches. "
                                  "Known vulnerabilities include remote code execution (CVE-2019-11043), "
                                  "type juggling bypasses, and memory corruption."},
            "php/7.0": {"name": "PHP 7.0 End-of-Life", "severity": "high",
                        "cve": "CVE-2019-11043",
                        "details": "PHP 7.0 is end-of-life since January 2019. Vulnerable to CVE-2019-11043 (RCE via FPM)."},
            "php/7.1": {"name": "PHP 7.1 End-of-Life", "severity": "high",
                        "cve": "CVE-2019-11043",
                        "details": "PHP 7.1 is end-of-life since December 2019. Contains known RCE and deserialization flaws."},
            "php/7.2": {"name": "PHP 7.2 End-of-Life", "severity": "medium",
                        "cve": "CVE-2020-7071",
                        "details": "PHP 7.2 is end-of-life since November 2020. Vulnerable to URL validation bypass (CVE-2020-7071)."},
            "php/7.3": {"name": "PHP 7.3 End-of-Life", "severity": "medium",
                        "cve": "CVE-2021-21702",
                        "details": "PHP 7.3 is end-of-life since December 2021. Vulnerable to NULL pointer dereference in SOAP (CVE-2021-21702)."},
            "php/7.4": {"name": "PHP 7.4 End-of-Life", "severity": "medium",
                        "cve": "CVE-2022-31625",
                        "details": "PHP 7.4 is end-of-life since November 2022. Vulnerable to use-after-free in pg_query_params (CVE-2022-31625)."},
            "php/8.0": {"name": "PHP 8.0 End-of-Life", "severity": "low",
                        "cve": "CVE-2023-3824",
                        "details": "PHP 8.0 is end-of-life since November 2023. Vulnerable to buffer overflow in phar (CVE-2023-3824)."},
            
            # Nginx versions
            "nginx/1.19": {"name": "Nginx 1.19 End-of-Life", "severity": "medium",
                           "cve": "CVE-2021-23017",
                           "details": "Nginx 1.19 is a legacy mainline version. Vulnerable to DNS resolver off-by-one (CVE-2021-23017)."},
            "nginx/1.18": {"name": "Nginx 1.18 End-of-Life", "severity": "medium",
                           "cve": "CVE-2021-23017",
                           "details": "Nginx 1.18 is an outdated stable branch. Vulnerable to CVE-2021-23017 (DNS resolver overflow)."},
            "nginx/1.17": {"name": "Nginx 1.17 End-of-Life", "severity": "high",
                           "cve": "CVE-2019-20372",
                           "details": "Nginx 1.17 is end-of-life. Vulnerable to HTTP request smuggling (CVE-2019-20372)."},
            "nginx/1.16": {"name": "Nginx 1.16 End-of-Life", "severity": "high",
                           "cve": "CVE-2019-20372",
                           "details": "Nginx 1.16 is end-of-life. Vulnerable to request smuggling and buffer overflows."},
            
            # Apache HTTPD
            "apache/2.2": {"name": "Apache 2.2 End-of-Life", "severity": "high",
                           "cve": "CVE-2017-9798",
                           "details": "Apache 2.2 is end-of-life since 2017. Vulnerable to Optionsbleed (CVE-2017-9798) and multiple RCE/DoS."},
            "apache/2.4.7": {"name": "Apache 2.4.7 End-of-Life", "severity": "high", "cve": "CVE-2021-41773", "details": "Apache 2.4.7 is severely outdated (released 2013). Missing 8+ years of security patches."},
            "apache/2.4.49": {"name": "Apache 2.4.49 Path Traversal", "severity": "critical",
                              "cve": "CVE-2021-41773",
                              "details": "Apache 2.4.49 has a critical path traversal and RCE vulnerability (CVE-2021-41773)."},
            "apache/2.4.50": {"name": "Apache 2.4.50 Path Traversal", "severity": "critical",
                              "cve": "CVE-2021-42013",
                              "details": "Apache 2.4.50 has a path traversal bypass (CVE-2021-42013), fix for CVE-2021-41773 was incomplete."},
            
            # jQuery
            "jquery/1.": {"name": "jQuery 1.x Vulnerable", "severity": "medium",
                          "cve": "CVE-2020-11022",
                          "details": "jQuery 1.x has known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023)."},
            "jquery/2.": {"name": "jQuery 2.x Vulnerable", "severity": "medium",
                          "cve": "CVE-2020-11022",
                          "details": "jQuery 2.x has known XSS vulnerabilities (CVE-2020-11022)."},
            
            # OpenSSH
            "openssh/7.": {"name": "OpenSSH 7.x Outdated", "severity": "medium",
                           "cve": "CVE-2021-41617",
                           "details": "OpenSSH 7.x is outdated. Vulnerable to privilege escalation (CVE-2021-41617)."},
            "openssh/6.": {"name": "OpenSSH 6.x End-of-Life", "severity": "high",
                           "cve": "CVE-2016-10009",
                           "details": "OpenSSH 6.x is end-of-life. Vulnerable to agent forwarding RCE (CVE-2016-10009)."},
            
            # OpenSSL
            "openssl/1.0": {"name": "OpenSSL 1.0 End-of-Life", "severity": "high",
                            "cve": "CVE-2022-0778",
                            "details": "OpenSSL 1.0 is end-of-life. Vulnerable to infinite loop DoS (CVE-2022-0778) and many others."},
            "openssl/1.1.0": {"name": "OpenSSL 1.1.0 End-of-Life", "severity": "high",
                              "cve": "CVE-2022-0778",
                              "details": "OpenSSL 1.1.0 is end-of-life. No longer receiving security fixes."},
            
            # IIS
            "iis/7.": {"name": "IIS 7.x End-of-Life", "severity": "high",
                       "cve": "CVE-2017-7269",
                       "details": "IIS 7.x is end-of-life (Windows Server 2008). Vulnerable to buffer overflow RCE (CVE-2017-7269)."},
            "iis/8.": {"name": "IIS 8.x End-of-Life", "severity": "medium",
                       "cve": "CVE-2015-1635",
                       "details": "IIS 8.x is end-of-life. Vulnerable to HTTP.sys RCE (CVE-2015-1635)."},
            
            # Node.js
            "node/12.": {"name": "Node.js 12.x End-of-Life", "severity": "medium",
                         "cve": "CVE-2021-22960",
                         "details": "Node.js 12 is end-of-life since April 2022. Vulnerable to HTTP request smuggling (CVE-2021-22960)."},
            "node/14.": {"name": "Node.js 14.x End-of-Life", "severity": "low",
                         "cve": "CVE-2023-30590",
                         "details": "Node.js 14 is end-of-life since April 2023. Vulnerable to DiffieHellman key generation DoS."},
            
            # WordPress
            "wordpress/": {"name": "WordPress Detected", "severity": "medium",
                           "details": "WordPress installations are frequent targets. Ensure all plugins and core are updated."},
        }
        
        tech_vulns_found = 0
        tech_str = " ".join(self.state.technologies).lower()
        
        for pattern, vuln_info in eol_tech.items():
            if pattern.lower() in tech_str:
                vuln_entry = {
                    "tool": "whatweb",
                    "name": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "details": vuln_info["details"],
                }
                # Add CVE if available
                if vuln_info.get("cve"):
                    vuln_entry["cve"] = vuln_info["cve"]
                
                self.state.vulnerabilities.append(vuln_entry)
                print_finding(vuln_info["severity"], vuln_info["name"])
                tech_vulns_found += 1
        
        if tech_vulns_found > 0:
            self.state.add_message(f"Technology analysis: {tech_vulns_found} outdated/vulnerable components")
    
    def _has_exploitable_vulns(self) -> bool:
        """Check if there are exploitable vulnerabilities"""
        # Check for SQL injection indicators
        for vuln in self.state.vulnerabilities:
            vuln_name = str(vuln.get("name", "")).lower()
            if any(x in vuln_name for x in ["sql", "inject", "sqli"]):
                return True
        
        # Check for endpoints with parameters
        for endpoint in self.state.endpoints:
            if "?" in endpoint and "=" in endpoint:
                return True
        
        return False
    
    def _run_exploitation(self) -> None:
        """Run exploitation attempts"""
        # Find a vulnerable endpoint
        target_url = None
        
        for endpoint in self.state.endpoints:
            if "?" in endpoint and "=" in endpoint:
                target_url = endpoint
                break
        
        if not target_url:
            print_info("No exploitable endpoints found")
            return
        
        print_tool("sqlmap", target_url)
        self.state.tools_used.append("sqlmap")
        
        try:
            stealth = self.state.stealth_mode or self.state.waf_detected
            result = self.tools.run_sqlmap(target_url, stealth=stealth)
            
            self.state.exploitation_results["sqlmap"] = result
            
            if "vulnerable" in result.lower():
                print_finding("critical", "SQL Injection CONFIRMED!", "Database access possible")
                self.state.add_message("SQL Injection vulnerability confirmed!")
                self.state.severity_score = 10.0
                
        except Exception as e:
            self.state.errors.append(f"SQLMap failed: {e}")
            print_warning(f"SQLMap failed: {e}")

        # 2. Commix (Command Injection)
        if target_url:
            print_tool("commix", target_url)
            self.state.tools_used.append("commix")
            try:
                res = self.tools.run_commix(target_url)
                if res and ("(OS commanding)" in res or "vulnerable" in res.lower()):
                    print_finding("critical", "Command Injection CONFIRMED!", "RCE possible")
                    self.state.exploitation_results["commix"] = "VULNERABLE"
                    self.state.severity_score = 10.0
            except Exception as e:
                print_warning(f"Commix failed: {e}")
                
        # 3. Hydra (Brute Force) on Ports
        # Only run if explicitly enabled in deep/exploitation profile to be safe
        if self.state.profile.enable_exploitation:
            for port in self.state.open_ports:
                svc = port.get("service", "")
                if svc in ["ssh", "ftp", "telnet"]:
                    print_tool("hydra", f"{self.state.target}:{port['port']}")
                    self.state.tools_used.append("hydra")
                    try:
                        # Use a very short timeout/quick check for safety
                        res = self.tools.run_hydra(self.state.target, svc)
                        if "password:" in res or "login:" in res:
                            print_finding("high", f"Weak credentials found for {svc}")
                            self.state.exploitation_results[f"hydra_{svc}"] = "Weak Credentials"
                    except Exception as e:
                        print_warning(f"Hydra failed: {e}")
    
    def _calculate_severity(self) -> None:
        """Calculate overall severity score using CVSS 3.1 + attack surface analysis"""
        from .cvss import CVSSCalculator, calculate_aggregate_score
        
        # Normalize vulnerabilities: convert NucleiVulnerability dataclass objects to dicts
        normalized_vulns = []
        for vuln in self.state.vulnerabilities:
            if isinstance(vuln, dict):
                normalized_vulns.append(vuln)
            elif hasattr(vuln, 'to_dict'):
                normalized_vulns.append(vuln.to_dict())
            else:
                # Last resort fallback if it's some object we don't recognize
                normalized_vulns.append({
                    "name": getattr(vuln, 'name', 'Unknown Vulnerability'),
                    "severity": getattr(vuln, 'severity', 'unknown'),
                    "description": getattr(vuln, 'description', ''),
                    "cve_id": getattr(vuln, 'cve_id', ''),
                    "tool": getattr(vuln, 'tool', 'unknown')
                })
        self.state.vulnerabilities = normalized_vulns
        
        # Score each vulnerability with CVSS
        for vuln in self.state.vulnerabilities:
            name = vuln.get("name", "")
            has_exploit = vuln.get("exploited", False) or "confirmed" in str(vuln).lower()
            existing_severity = vuln.get("severity", "").lower()
            
            cvss_result = CVSSCalculator.score_vulnerability(name, has_exploit=has_exploit)
            
            # Respect tool-assigned severity as a floor
            severity_floor = {
                "critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0
            }.get(existing_severity, 0.0)
            
            if cvss_result["cvss_base"] < severity_floor:
                cvss_result["cvss_base"] = severity_floor
                cvss_result["cvss_temporal"] = severity_floor
                cvss_result["severity"] = existing_severity.upper()
            
            vuln["cvss_base"] = cvss_result["cvss_base"]
            vuln["cvss_temporal"] = cvss_result["cvss_temporal"]
            vuln["cvss_vector"] = cvss_result["cvss_vector"]
            vuln["exploitable"] = cvss_result["exploitable"]
            
            if not vuln.get("severity") or vuln.get("severity") == "unknown":
                vuln["severity"] = cvss_result["severity"].lower()
        
        # === ATTACK SURFACE SCORING ===
        import math
        
        # 1. Port exposure score
        port_score = 0.0
        for port in self.state.open_ports:
            port_num = port.get("port", 0)
            service = port.get("service", "").lower()
            if service in ["ssh", "ftp", "telnet", "rdp"] or port_num in [22, 21, 23, 3389]:
                port_score += 2.5
            elif service in ["mysql", "postgresql", "mssql", "mongodb"] or port_num in [3306, 5432, 1433, 27017]:
                port_score += 3.5
            elif service in ["http", "https"] or port_num in [80, 443, 8080, 8443]:
                port_score += 1.5
            else:
                port_score += 0.5
        
        # 2. Technology risk score (outdated/vulnerable tech = higher risk)
        tech_score = 0.0
        risky_tech_keywords = [
            "php/5", "php/4", "php 5", "php 4",  # End-of-life PHP
            "apache/2.2", "apache/2.0",  # Old Apache
            "nginx/1.1", "nginx/1.0",  # Old nginx
            "wordpress", "joomla", "drupal",  # CMS (common attack targets)
            "jquery/1.", "jquery/2.",  # Old jQuery
            "flash", "activex", "silverlight",  # Deprecated tech
        ]
        for tech in self.state.technologies:
            tech_lower = str(tech).lower()
            if any(kw in tech_lower for kw in risky_tech_keywords):
                tech_score += 2.0
            elif tech_lower not in ["", "country", "ip", "httpserver"]:
                tech_score += 0.3
        
        # 3. Endpoint attack surface (more paths = more attack surface)
        endpoint_score = 0.0
        if hasattr(self.state, 'endpoints'):
            ep_count = len(self.state.endpoints)
            if ep_count > 50:
                endpoint_score = 3.0
            elif ep_count > 20:
                endpoint_score = 2.0
            elif ep_count > 5:
                endpoint_score = 1.0
        
        # 4. WAF detection (no WAF = higher risk)
        waf_penalty = 0.0 if self.state.waf_detected else 1.0
        
        # === COMBINE SCORES ===
        
        # Vulnerability-based score (CVSS aggregate)
        vuln_score, vuln_level = calculate_aggregate_score(self.state.vulnerabilities)
        
        # Attack surface composite (ports + tech + endpoints + WAF)
        surface_raw = port_score + tech_score + endpoint_score + waf_penalty
        surface_score = min(5.0, math.log1p(surface_raw) * 1.5) if surface_raw > 0 else 0.0
        
        # Final: max of vuln score or surface score, whichever indicates more risk
        # If vulns found, they dominate. If not, attack surface still raises the floor.
        if vuln_score >= 4.0:
            combined = min(10.0, vuln_score + surface_score * 0.2)
        elif vuln_score > 0:
            combined = max(vuln_score, surface_score)
        else:
            combined = surface_score
        
        # Boost if exploitation succeeded
        if self.state.exploitation_results:
            for result in self.state.exploitation_results.values():
                if "vulnerable" in str(result).lower() or "confirmed" in str(result).lower():
                    combined = max(combined, 9.0)
                    break
        
        self.state.severity_score = round(combined, 1)
        
        # Determine level using CVSS thresholds — INFO findings don't count toward risk level
        non_info_vulns = [v for v in self.state.vulnerabilities 
                          if v.get("severity", "").lower() not in ("info", "unknown", "")]
        has_real_vulns = len(non_info_vulns) > 0
        
        if combined >= 9.0:
            self.state.severity_level = "CRITICAL"
        elif combined >= 7.0:
            self.state.severity_level = "HIGH"
        elif combined >= 4.0:
            self.state.severity_level = "MEDIUM"
        elif combined >= 0.1 and (has_real_vulns or combined >= 2.0):
            self.state.severity_level = "LOW"
        else:
            self.state.severity_level = "NONE"
        
        self.state.add_message(f"CVSS Assessment: {self.state.severity_level} ({self.state.severity_score}/10)")

def get_tools_status() -> Dict[str, bool]:
    """Get status of all security tools"""
    try:
        from ares_cli.tools.enhanced_tool_manager import EnhancedReconTools
        tools = EnhancedReconTools()
        return {name: status.available for name, status in tools.tool_status.items()}
    except:
        return {}