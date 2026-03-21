# backend/tools/subdomain_enum.py
"""
Subdomain Enumeration Tools
Combines Subfinder, Amass, and passive DNS for comprehensive subdomain discovery
"""
import subprocess
import json
import shutil
import re
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, asdict

@dataclass
class Subdomain:
    """Discovered subdomain with metadata"""
    name: str
    source: str
    ip_addresses: List[str] = None
    is_alive: bool = False
    http_status: int = 0
    technologies: List[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)

class SubdomainEnumerator:
    """
    Multi-source subdomain enumeration.
    Uses Subfinder as primary tool with fallback options.
    """
    
    # Common subdomain prefixes for brute-force fallback
    COMMON_PREFIXES = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
        "api", "dev", "staging", "test", "admin", "portal",
        "vpn", "remote", "secure", "app", "m", "mobile",
        "blog", "shop", "store", "cdn", "assets", "static",
        "beta", "alpha", "demo", "docs", "help", "support",
        "login", "auth", "sso", "dashboard", "panel", "cp",
    ]

    def __init__(self):
        self.tools_available = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which enumeration tools are available"""
        return {
            "subfinder": shutil.which("subfinder") is not None,
            "amass": shutil.which("amass") is not None,
            "httpx": shutil.which("httpx") is not None,
        }
    
    def enumerate(
        self,
        domain: str,
        use_passive: bool = True,
        use_bruteforce: bool = False,
        check_alive: bool = True,
        timeout: int = 300,
        max_results: int = 500,
    ) -> Dict:
        """
        Enumerate subdomains for a given domain.
        
        Args:
            domain: Target domain (e.g., example.com)
            use_passive: Use passive enumeration via APIs
            use_bruteforce: Include common prefix brute-force
            check_alive: Verify which subdomains are alive
            timeout: Max execution time
            max_results: Limit results
            
        Returns:
            Dict with subdomains, stats, and metadata
        """
        print(f"[*] TOOL: Subdomain enumeration on {domain}")
        
        all_subdomains: Set[str] = set()
        sources_used = []
        
        # 1. Subfinder (primary - fast passive enumeration)
        if self.tools_available.get("subfinder"):
            subs = self._run_subfinder(domain, timeout)
            all_subdomains.update(subs)
            sources_used.append("subfinder")
        
        # 2. Amass (if available - more comprehensive but slower)
        if self.tools_available.get("amass") and use_passive:
            subs = self._run_amass(domain, timeout)
            all_subdomains.update(subs)
            sources_used.append("amass")
        
        # 3. Common prefix brute-force (fallback)
        if use_bruteforce or not sources_used:
            subs = self._bruteforce_common(domain)
            all_subdomains.update(subs)
            sources_used.append("bruteforce")
        
        # Limit results
        subdomains_list = list(all_subdomains)[:max_results]
        
        # Build structured results
        results = [
            Subdomain(name=sub, source="passive")
            for sub in subdomains_list
        ]
        
        # 4. Check which are alive (optional)
        if check_alive and self.tools_available.get("httpx"):
            results = self._check_alive_httpx(results)
        
        alive_count = sum(1 for r in results if r.is_alive)
        
        return {
            "domain": domain,
            "subdomains": [r.to_dict() for r in results],
            "total_found": len(results),
            "alive_count": alive_count,
            "sources": sources_used,
            "unique_ips": self._extract_unique_ips(results),
        }
    
    def _run_subfinder(self, domain: str, timeout: int = 300) -> Set[str]:
        """Run Subfinder for passive subdomain enumeration"""
        try:
            cmd = [
                "subfinder",
                "-d", domain,
                "-silent",
                "-all",
                "-timeout", str(min(timeout // 60, 5)),  # minutes
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            subdomains = set()
            for line in result.stdout.splitlines():
                sub = line.strip().lower()
                if sub and self._is_valid_subdomain(sub, domain):
                    subdomains.add(sub)
            
            print(f"    Subfinder found {len(subdomains)} subdomains")
            return subdomains
            
        except subprocess.TimeoutExpired:
            print("    Subfinder timeout")
            return set()
        except Exception as e:
            print(f"    Subfinder error: {e}")
            return set()
    
    def _run_amass(self, domain: str, timeout: int = 300) -> Set[str]:
        """Run Amass for passive enumeration (slower but thorough)"""
        try:
            cmd = [
                "amass", "enum",
                "-passive",
                "-d", domain,
                "-timeout", str(timeout // 60),
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            subdomains = set()
            for line in result.stdout.splitlines():
                sub = line.strip().lower()
                if sub and self._is_valid_subdomain(sub, domain):
                    subdomains.add(sub)
            
            print(f"    Amass found {len(subdomains)} subdomains")
            return subdomains
            
        except subprocess.TimeoutExpired:
            return set()
        except Exception:
            return set()
    
    def _bruteforce_common(self, domain: str) -> Set[str]:
        """Generate subdomains from common prefixes"""
        subdomains = set()
        for prefix in self.COMMON_PREFIXES:
            subdomains.add(f"{prefix}.{domain}")
        return subdomains
    
    def _check_alive_httpx(self, subdomains: List[Subdomain]) -> List[Subdomain]:
        """Use httpx to check which subdomains are alive"""
        if not subdomains:
            return subdomains
        
        try:
            # Write subdomains to temp file
            with open("/tmp/subs_to_check.txt", "w") as f:
                for sub in subdomains:
                    f.write(f"{sub.name}\n")
            
            cmd = [
                "httpx",
                "-l", "/tmp/subs_to_check.txt",
                "-silent",
                "-json",
                "-timeout", "5",
                "-threads", "50",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            alive_hosts = {}
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    host = data.get("input", "").lower()
                    alive_hosts[host] = {
                        "status": data.get("status_code", 0),
                        "technologies": data.get("tech", []),
                    }
                except:
                    continue
            
            # Update subdomain objects
            for sub in subdomains:
                if sub.name in alive_hosts:
                    sub.is_alive = True
                    sub.http_status = alive_hosts[sub.name].get("status", 0)
                    sub.technologies = alive_hosts[sub.name].get("technologies", [])
            
            return subdomains
            
        except Exception as e:
            print(f"    httpx check failed: {e}")
            return subdomains
    
    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Validate subdomain format"""
        if not subdomain.endswith(parent_domain):
            return False
        
        # Basic DNS name validation
        pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$'
        return bool(re.match(pattern, subdomain))
    
    def _extract_unique_ips(self, subdomains: List[Subdomain]) -> List[str]:
        """Extract unique IP addresses from results"""
        ips = set()
        for sub in subdomains:
            if sub.ip_addresses:
                ips.update(sub.ip_addresses)
        return list(ips)
    
    def quick_enum(self, domain: str) -> Dict:
        """Fast enumeration with minimal checks"""
        return self.enumerate(
            domain=domain,
            use_passive=True,
            use_bruteforce=False,
            check_alive=False,
            timeout=60,
            max_results=100,
        )
    
    def deep_enum(self, domain: str) -> Dict:
        """Comprehensive enumeration with all sources"""
        return self.enumerate(
            domain=domain,
            use_passive=True,
            use_bruteforce=True,
            check_alive=True,
            timeout=600,
            max_results=1000,
        )
