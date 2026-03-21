# backend/tools/enhanced_tool_manager.py
"""
Enhanced Tool Manager - Unified interface for all security tools
Combines original tools with new integrations
"""
import nmap
import os
import subprocess
import shutil
import re
from typing import List, Dict
from dataclasses import dataclass

# Import new tool modules
from .nuclei_scanner import NucleiScanner
from .subdomain_enum import SubdomainEnumerator
from .ffuf_fuzzer import FFUFFuzzer
from .katana_crawler import KatanaCrawler
from .whatweb_fingerprint import WhatWebFingerprinter

@dataclass
class ToolStatus:
    """Track tool availability and health"""
    name: str
    available: bool
    version: str = ""
    error: str = ""

class EnhancedReconTools:
    """
    Unified tool manager for all reconnaissance and exploitation tools.
    Extends original ReconTools with new integrations.
    """
    
    def __init__(self):
        # Original tools
        try:
            self.nm = nmap.PortScanner()
        except:
            self.nm = None
        
        # New tool instances
        self.nuclei = NucleiScanner()
        self.subfinder = SubdomainEnumerator()
        self.ffuf = FFUFFuzzer()
        self.katana = KatanaCrawler()
        self.whatweb = WhatWebFingerprinter()
        
        # Check all tools
        self.tool_status = self._check_all_tools()
    
    def _check_all_tools(self) -> Dict[str, ToolStatus]:
        """Check availability of all tools"""
        tools = {
            "nmap": ToolStatus("nmap", self.nm is not None),
            "gobuster": ToolStatus("gobuster", shutil.which("gobuster") is not None),
            "nikto": ToolStatus("nikto", shutil.which("nikto") is not None),
            "sqlmap": ToolStatus("sqlmap", shutil.which("sqlmap") is not None),
            "nuclei": ToolStatus("nuclei", shutil.which("nuclei") is not None),
            "subfinder": ToolStatus("subfinder", shutil.which("subfinder") is not None),
            "ffuf": ToolStatus("ffuf", shutil.which("ffuf") is not None),
            "katana": ToolStatus("katana", shutil.which("katana") is not None),
            "whatweb": ToolStatus("whatweb", shutil.which("whatweb") is not None),
            "httpx": ToolStatus("httpx", shutil.which("httpx") is not None),
            "hydra": ToolStatus("hydra", shutil.which("hydra") is not None),
            "commix": ToolStatus("commix", shutil.which("commix") is not None),
        }
        
        # Get versions where possible
        for name, status in tools.items():
            if status.available:
                status.version = self._get_tool_version(name)
        
        return tools
    
    def _get_tool_version(self, tool: str) -> str:
        """Get tool version string"""
        try:
            if tool == "nmap" and self.nm:
                return self.nm.nmap_version_number()
            
            version_flags = {
                "nuclei": "--version",
                "subfinder": "-version",
                "ffuf": "-V",
                "katana": "-version",
                "whatweb": "--version",
                "sqlmap": "--version",
                "gobuster": "version",
                "nikto": "-Version",
            }
            
            flag = version_flags.get(tool, "--version")
            result = subprocess.run(
                [tool, flag],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout or result.stderr
            # Extract version pattern
            match = re.search(r'(\d+\.\d+(?:\.\d+)?)', output)
            return match.group(1) if match else "unknown"
        except:
            return ""
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        return [name for name, status in self.tool_status.items() if status.available]
    
    # =============================================
    # ORIGINAL TOOLS (Enhanced)
    # =============================================
    
    def run_nmap(self, target: str, scan_type: str = "default") -> List[Dict]:
        """
        Enhanced Nmap scanning with multiple scan types.
        
        Args:
            target: IP, hostname, or CIDR range
            scan_type: 'default', 'fast', 'full', 'udp', 'stealth'
        """
        print(f"[*] TOOL: Nmap ({scan_type}) on {target}")
        if not self.nm:
            return [{"error": "Nmap not available"}]
        
        # Scan type configurations - all include -Pn to skip host discovery
        scan_args = {
            "default": "-sV -T4 -Pn --top-ports 1000",
            "fast": "-F -T5 -Pn",
            "full": "-sV -sC -p- -T4 -Pn",
            "udp": "-sU -sV -Pn --top-ports 100",
            "stealth": "-sS -T2 -Pn",
            "vuln": "-sV -Pn --script vuln",
        }
        
        args = scan_args.get(scan_type, scan_args["default"])
        
        try:
            self.nm.scan(hosts=target, arguments=args)
            scan_data = []
            
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "hostname": self.nm[host].hostname(),
                    "state": self.nm[host].state(),
                    "ports": [],
                    "os_matches": [],
                }
                
                # TCP ports
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        port_data = self.nm[host]['tcp'][port]
                        if port_data['state'] == 'open':
                            host_info["ports"].append({
                                "port": port,
                                "protocol": "tcp",
                                "service": port_data['name'],
                                "version": port_data.get('version', ''),
                                "product": port_data.get('product', ''),
                                "extra_info": port_data.get('extrainfo', ''),
                            })
                
                # UDP ports (if scanned)
                if 'udp' in self.nm[host]:
                    for port in self.nm[host]['udp']:
                        port_data = self.nm[host]['udp'][port]
                        if port_data['state'] == 'open':
                            host_info["ports"].append({
                                "port": port,
                                "protocol": "udp",
                                "service": port_data['name'],
                                "version": port_data.get('version', ''),
                            })
                
                # OS detection (if available)
                if 'osmatch' in self.nm[host]:
                    host_info["os_matches"] = [
                        {"name": os['name'], "accuracy": os['accuracy']}
                        for os in self.nm[host]['osmatch'][:3]
                    ]
                
                scan_data.append(host_info)
            
            return scan_data
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def run_gobuster(self, target: str, wordlist: str = "common") -> Dict:
        """Original Gobuster - kept for compatibility"""
        print(f"[*] TOOL: Gobuster on {target}")
        url = f"http://{target}" if not target.startswith("http") else target
        
        wordlist_paths = {
            "common": "/usr/share/wordlists/dirb/common.txt",
            "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        }
        wordlist_path = wordlist_paths.get(wordlist, wordlist_paths["common"])
        
        try:
            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist_path,
                "-q", "-z",
                "--no-error",
                "--timeout", "10s"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {"directories": res.stdout.splitlines()[:30]}
        except:
            return {"directories": []}
    
    def run_nikto(self, target: str, tuning: str = "1") -> str:
        """Original Nikto - enhanced with output parsing"""
        print(f"[*] TOOL: Nikto on {target}")
        if not shutil.which("nikto"):
            return "Nikto not installed"
        
        try:
            cmd = [
                "nikto",
                "-h", target,
                "-Tuning", tuning,
                "-maxtime", "120s",
                "-Format", "txt"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return res.stdout[:2000]
        except Exception as e:
            return f"Nikto error: {e}"
    
    def run_sqlmap(self, url: str, stealth: bool = False, level: int = 1) -> str:
        """Original SQLMap - enhanced with more options"""
        mode = "STEALTH" if stealth else "STANDARD"
        print(f"[*] TOOL: SQLMap ({mode}) on {url}")
        
        if not shutil.which("sqlmap"):
            return "SQLMap not installed"
        
        try:
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",
                "--dbs",
                "--level", str(level),
                "--timeout", "15",
                "--output-dir", "/tmp/sqlmap_output"
            ]
            
            if stealth:
                cmd.extend([
                    "--tamper=space2comment,randomcase",
                    "--random-agent",
                    "--delay=2",
                    "--safe-url", url.split("?")[0],
                    "--safe-freq", "3"
                ])
            
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return res.stdout[-2000:]
            
        except Exception as e:
            return f"SQLMap error: {e}"
    def run_hydra(self, target: str, service: str, userlist: str = None, passlist: str = None) -> str:
        """Run Hydra brute-force"""
        print(f"[*] TOOL: Hydra on {target} ({service})")
        if not shutil.which("hydra"):
            return "Hydra not installed"
            
        try:
            # Defaults
            user = userlist or "admin"
            pw_list = passlist or "/usr/share/wordlists/rockyou.txt"
            
            cmd = ["hydra", "-l", user, "-P", pw_list, service + "://" + target, "-t", "4", "-W", "1"]
            
            # Simple check for demo purposes or very small list if default
            if not os.path.exists(pw_list):
                # Fallback to internal quick list
                cmd = ["hydra", "-l", user, "-p", "password", service + "://" + target]
                
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return res.stdout
        except Exception as e:
            return f"Hydra error: {e}"

    def run_commix(self, url: str, batch: bool = True) -> str:
        """Run Commix for command injection"""
        print(f"[*] TOOL: Commix on {url}")
        if not shutil.which("commix"):
            return "Commix not installed"
            
        try:
            cmd = ["commix", "--url", url, "--batch", "--disable-coloring"]
            if batch:
                cmd.append("--all") # Enumerate everything if vulnerable
                
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return res.stdout[-2000:]
        except Exception as e:
            return f"Commix error: {e}"
    
    # =============================================
    # NEW TOOLS
    # =============================================
    
    def run_nuclei(
        self,
        target: str,
        templates: List[str] = None,
        severity: List[str] = None,
        quick: bool = False
    ) -> Dict:
        """
        Run Nuclei vulnerability scanner.
        
        Args:
            target: URL to scan
            templates: Template categories (cves, vulnerabilities, etc.)
            severity: Filter by severity (critical, high, medium, low)
            quick: Use quick scan mode
        """
        if quick:
            return self.nuclei.quick_scan(target)
        return self.nuclei.scan(target, templates=templates, severity=severity)
    
    def run_subfinder(
        self,
        domain: str,
        check_alive: bool = True,
        quick: bool = False
    ) -> Dict:
        """
        Run subdomain enumeration.
        
        Args:
            domain: Target domain
            check_alive: Verify which subdomains respond
            quick: Fast mode with limited sources
        """
        if quick:
            return self.subfinder.quick_enum(domain)
        return self.subfinder.enumerate(domain, check_alive=check_alive)
    
    def run_ffuf(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "small",
        extensions: List[str] = None,
        quick: bool = False
    ) -> Dict:
        """
        Run FFUF web fuzzer.
        
        Args:
            url: Target URL
            mode: 'dir' (directory), 'param' (parameters), 'vhost' (virtual hosts)
            wordlist: Wordlist name or path
            extensions: File extensions to try
            quick: Fast mode
        """
        if quick:
            return self.ffuf.quick_scan(url)
        
        if mode == "dir":
            return self.ffuf.fuzz_directories(url, wordlist=wordlist, extensions=extensions)
        elif mode == "param":
            return self.ffuf.fuzz_parameters(url, wordlist=wordlist)
        else:
            return self.ffuf.fuzz_directories(url, wordlist=wordlist)
    
    def run_katana(
        self,
        url: str,
        depth: int = 3,
        headless: bool = True,
        quick: bool = False
    ) -> Dict:
        """
        Run Katana web crawler.
        
        Args:
            url: Target URL
            depth: Crawl depth
            headless: Use headless browser
            quick: Fast mode
        """
        if quick:
            return self.katana.quick_crawl(url)
        return self.katana.crawl(url, depth=depth, headless=headless)
    
    def run_whatweb(
        self,
        url: str,
        aggressive: bool = False,
        quick: bool = False
    ) -> Dict:
        """
        Run WhatWeb technology fingerprinting.
        
        Args:
            url: Target URL
            aggressive: Use aggressive detection
            quick: Fast mode
        """
        if quick:
            return self.whatweb.quick_fingerprint(url)
        if aggressive:
            return self.whatweb.full_fingerprint(url)
        return self.whatweb.fingerprint(url)
    
    # =============================================
    # COMBINED WORKFLOWS
    # =============================================
    
    def full_reconnaissance(self, target: str) -> Dict:
        """
        Run comprehensive reconnaissance workflow.
        Combines multiple tools for full attack surface mapping.
        """
        print(f"[*] Starting full reconnaissance on {target}")
        
        results = {
            "target": target,
            "tools_used": [],
            "network": None,
            "web": None,
            "subdomains": None,
            "vulnerabilities": None,
            "technologies": None,
        }
        
        # 1. Network scan
        if self.tool_status["nmap"].available:
            results["network"] = self.run_nmap(target, "default")
            results["tools_used"].append("nmap")
        
        # 2. Subdomain enumeration (if domain)
        if not target.replace(".", "").isdigit():  # Not an IP
            if self.tool_status["subfinder"].available:
                results["subdomains"] = self.run_subfinder(target, quick=True)
                results["tools_used"].append("subfinder")
        
        # 3. Technology fingerprinting
        url = f"http://{target}" if not target.startswith("http") else target
        if self.tool_status["whatweb"].available:
            results["technologies"] = self.run_whatweb(url, quick=True)
            results["tools_used"].append("whatweb")
        
        # 4. Web crawling
        if self.tool_status["katana"].available:
            results["web"] = self.run_katana(url, quick=True)
            results["tools_used"].append("katana")
        
        # 5. Vulnerability scanning
        if self.tool_status["nuclei"].available:
            results["vulnerabilities"] = self.run_nuclei(url, quick=True)
            results["tools_used"].append("nuclei")
        
        return results
    
    def quick_assessment(self, target: str) -> Dict:
        """
        Fast assessment using only available quick scans.
        """
        print(f"[*] Quick assessment on {target}")
        
        results = {"target": target, "findings": []}
        url = f"http://{target}" if not target.startswith("http") else target
        
        # Nmap fast scan
        if self.tool_status["nmap"].available:
            nmap_results = self.run_nmap(target, "fast")
            if nmap_results and not nmap_results[0].get("error"):
                port_count = sum(len(h.get("ports", [])) for h in nmap_results)
                results["findings"].append(f"Found {port_count} open ports")
        
        # Quick fingerprint
        if self.tool_status["whatweb"].available:
            fp = self.run_whatweb(url, quick=True)
            if fp.get("fingerprint"):
                tech_count = len(fp["fingerprint"].get("technologies", []))
                results["findings"].append(f"Detected {tech_count} technologies")
        
        return results
