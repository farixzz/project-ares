# backend/tools/katana_crawler.py
"""
Katana - Fast Web Crawler Integration
Modern, headless browser-based crawler for deep web reconnaissance
"""
import subprocess
import json
import shutil
import re
import os
from typing import List, Dict
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
from enum import Enum

class CrawlScope(Enum):
    """Crawling scope levels"""
    STRICT = "strict"       # Same subdomain only
    HOST = "host"           # Same host
    DOMAIN = "domain"       # Same domain (includes subdomains)
    FQDN = "fqdn"          # Full qualified domain name

@dataclass
class CrawlResult:
    """Single crawl finding"""
    url: str
    method: str
    source: str
    depth: int
    content_type: str = ""
    status_code: int = 0
    parameters: List[str] = None
    forms: List[Dict] = None
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class EndpointAnalysis:
    """Analyzed endpoint with attack surface info"""
    url: str
    has_parameters: bool
    parameter_names: List[str]
    is_api_endpoint: bool
    file_extension: str
    potential_vulns: List[str]
    
    def to_dict(self) -> dict:
        return asdict(self)

class KatanaCrawler:
    """
    Katana web crawler wrapper.
    Headless browser-based crawling for JavaScript-heavy applications.
    """
    
    # Patterns indicating interesting endpoints
    INTERESTING_PATTERNS = {
        "api_endpoints": [
            r"/api/", r"/v\d+/", r"/rest/", r"/graphql",
            r"/json", r"/xml", r"/rpc",
        ],
        "auth_endpoints": [
            r"/login", r"/auth", r"/signin", r"/signup",
            r"/register", r"/password", r"/oauth", r"/sso",
        ],
        "admin_endpoints": [
            r"/admin", r"/dashboard", r"/console", r"/panel",
            r"/manage", r"/control", r"/backend",
        ],
        "file_upload": [
            r"/upload", r"/file", r"/attachment", r"/media",
            r"/import", r"/document",
        ],
        "data_endpoints": [
            r"/export", r"/download", r"/backup", r"/dump",
            r"/report", r"/data",
        ],
    }
    
    # File extensions that may indicate vulnerabilities
    VULN_EXTENSIONS = {
        "php": ["LFI", "RCE", "SQLi"],
        "asp": ["LFI", "RCE"],
        "aspx": ["LFI", "RCE"],
        "jsp": ["LFI", "RCE"],
        "cgi": ["RCE", "Command Injection"],
        "pl": ["RCE"],
    }

    def __init__(self):
        # Ensure Go bin is in PATH for katana discovery
        go_bin = os.path.expanduser("~/go/bin")
        if go_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = go_bin + ":" + os.environ.get("PATH", "")
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Verify Katana is installed"""
        if not shutil.which("katana"):
            print("[!] WARNING: Katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            return False
        return True
    
    def crawl(
        self,
        url: str,
        depth: int = 3,
        scope: CrawlScope = CrawlScope.DOMAIN,
        headless: bool = True,
        timeout: int = 30,
        concurrency: int = 10,
        rate_limit: int = 150,
        crawl_duration: int = 300,
        include_js: bool = True,
        form_extract: bool = True,
        field_fuzz: bool = False,
        output_all: bool = True,
    ) -> Dict:
        """
        Crawl a web application and extract endpoints.
        
        Args:
            url: Starting URL
            depth: Maximum crawl depth
            scope: Crawling scope (strict/host/domain)
            headless: Use headless browser for JS rendering
            timeout: Request timeout in seconds
            concurrency: Parallel crawlers
            rate_limit: Requests per second
            crawl_duration: Maximum crawl time in seconds
            include_js: Parse JavaScript for endpoints
            form_extract: Extract form data
            field_fuzz: Fuzz form fields
            output_all: Output all endpoints (not just with params)
            
        Returns:
            Dict with endpoints, forms, and analysis
        """
        print(f"[*] TOOL: Katana crawling {url}")
        
        if not shutil.which("katana"):
            return {"error": "Katana not installed", "endpoints": []}
        
        # Ensure Go bin is in PATH for katana
        env = os.environ.copy()
        go_bin = os.path.expanduser("~/go/bin")
        if go_bin not in env.get("PATH", ""):
            env["PATH"] = go_bin + ":" + env.get("PATH", "")
        
        # Build command — flags verified against Katana v1.5.0
        cmd = [
            "katana",
            "-u", url,
            "-d", str(depth),
            "-jc",                          # JavaScript crawling
            "-ct", f"{crawl_duration}s",     # Maximum crawl duration
            "-c", str(concurrency),
            "-rl", str(rate_limit),
            "-timeout", str(timeout),        # Per-request timeout (seconds)
            "-o", "/tmp/katana_output.txt",
            "-j",                            # JSON Lines output
            "-silent",
        ]
        
        # Scope
        cmd.extend(["-fs", scope.value])
        
        # Headless mode
        if headless:
            cmd.append("-hl")
        
        # Form extraction
        if form_extract:
            cmd.append("-fx")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=crawl_duration + 60,
                env=env,
            )
            
            endpoints = self._parse_output("/tmp/katana_output.txt")
            analysis = self._analyze_endpoints(endpoints)
            forms = self._extract_forms(endpoints)
            
            return {
                "target": url,
                "endpoints": [e.to_dict() for e in endpoints],
                "total_found": len(endpoints),
                "analysis": {
                    "total_analyzed": len(analysis),
                    "with_parameters": sum(1 for a in analysis if a.has_parameters),
                    "api_endpoints": sum(1 for a in analysis if a.is_api_endpoint),
                    "potential_vulns": self._count_vulns(analysis),
                },
                "analyzed_endpoints": [a.to_dict() for a in analysis],
                "forms": forms,
                "interesting_endpoints": self._find_interesting(endpoints),
                "js_files": self._extract_js_files(endpoints),
                "stderr": result.stderr[:500] if result.stderr else "",
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Crawl timeout exceeded", "endpoints": []}
        except Exception as e:
            return {"error": str(e), "endpoints": []}
    
    def _parse_output(self, output_file: str) -> List[CrawlResult]:
        """Parse Katana output"""
        results = []
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        result = CrawlResult(
                            url=data.get("url", data.get("endpoint", line)),
                            method=data.get("method", "GET"),
                            source=data.get("source", "crawl"),
                            depth=data.get("depth", 0),
                            content_type=data.get("content-type", ""),
                            status_code=data.get("status_code", 0),
                            parameters=self._extract_params(data.get("url", "")),
                        )
                        results.append(result)
                    except json.JSONDecodeError:
                        # Plain URL output
                        if line.startswith("http"):
                            result = CrawlResult(
                                url=line,
                                method="GET",
                                source="crawl",
                                depth=0,
                                parameters=self._extract_params(line),
                            )
                            results.append(result)
                            
        except FileNotFoundError:
            pass
        
        # Deduplicate by URL
        seen = set()
        unique = []
        for r in results:
            if r.url not in seen:
                seen.add(r.url)
                unique.append(r)
        
        return unique
    
    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL"""
        params = []
        try:
            parsed = urlparse(url)
            if parsed.query:
                for pair in parsed.query.split("&"):
                    if "=" in pair:
                        param_name = pair.split("=")[0]
                        if param_name:
                            params.append(param_name)
        except:
            pass
        return params
    
    def _analyze_endpoints(self, endpoints: List[CrawlResult]) -> List[EndpointAnalysis]:
        """Analyze endpoints for attack surface"""
        analyzed = []
        
        for ep in endpoints:
            parsed = urlparse(ep.url)
            path = parsed.path.lower()
            
            # Get file extension
            ext = ""
            if "." in path.split("/")[-1]:
                ext = path.split(".")[-1]
            
            # Check if API endpoint
            is_api = any(
                re.search(pattern, ep.url, re.I)
                for pattern in self.INTERESTING_PATTERNS["api_endpoints"]
            )
            
            # Identify potential vulnerabilities
            vulns = []
            if ext in self.VULN_EXTENSIONS:
                vulns.extend(self.VULN_EXTENSIONS[ext])
            if ep.parameters:
                vulns.append("Parameter Tampering")
                if any(p.lower() in ["id", "page", "file", "path", "url", "redirect"] for p in ep.parameters):
                    vulns.append("Potential Injection Point")
            
            analysis = EndpointAnalysis(
                url=ep.url,
                has_parameters=bool(ep.parameters),
                parameter_names=ep.parameters or [],
                is_api_endpoint=is_api,
                file_extension=ext,
                potential_vulns=list(set(vulns)),
            )
            analyzed.append(analysis)
        
        return analyzed
    
    def _extract_forms(self, endpoints: List[CrawlResult]) -> List[Dict]:
        """Extract and structure form data"""
        forms = []
        for ep in endpoints:
            if ep.forms:
                for form in ep.forms:
                    forms.append({
                        "action": form.get("action", ep.url),
                        "method": form.get("method", "POST"),
                        "fields": form.get("inputs", []),
                        "source_url": ep.url,
                    })
        return forms
    
    def _find_interesting(self, endpoints: List[CrawlResult]) -> List[str]:
        """Find particularly interesting endpoints"""
        interesting = []
        
        for ep in endpoints:
            url_lower = ep.url.lower()
            
            for category, patterns in self.INTERESTING_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url_lower, re.I):
                        interesting.append({
                            "url": ep.url,
                            "category": category,
                            "matched_pattern": pattern,
                        })
                        break
        
        return interesting[:50]  # Limit results
    
    def _extract_js_files(self, endpoints: List[CrawlResult]) -> List[str]:
        """Extract JavaScript file URLs"""
        js_files = []
        for ep in endpoints:
            if ep.url.endswith(".js") or "/js/" in ep.url:
                js_files.append(ep.url)
        return list(set(js_files))[:100]
    
    def _count_vulns(self, analyzed: List[EndpointAnalysis]) -> Dict[str, int]:
        """Count potential vulnerabilities by type"""
        counts = {}
        for a in analyzed:
            for vuln in a.potential_vulns:
                counts[vuln] = counts.get(vuln, 0) + 1
        return counts
    
    def quick_crawl(self, url: str) -> Dict:
        """Fast crawl with minimal depth"""
        return self.crawl(
            url=url,
            depth=2,
            headless=False,
            timeout=10,
            concurrency=20,
            crawl_duration=60,
        )
    
    def deep_crawl(self, url: str) -> Dict:
        """Comprehensive crawl with JS rendering"""
        return self.crawl(
            url=url,
            depth=5,
            headless=True,
            timeout=30,
            concurrency=5,
            crawl_duration=600,
            form_extract=True,
        )
