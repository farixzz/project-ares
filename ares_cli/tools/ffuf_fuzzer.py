# backend/tools/ffuf_fuzzer.py
"""
FFUF - Fast Web Fuzzer Integration
High-performance directory/parameter fuzzing replacement for Gobuster
"""
import subprocess
import json
import shutil
import os
from typing import List, Dict
from dataclasses import dataclass, asdict
from enum import Enum

class FuzzMode(Enum):
    """FFUF fuzzing modes"""
    DIRECTORY = "dir"
    PARAMETER = "param"
    SUBDOMAIN = "vhost"
    HEADER = "header"

@dataclass
class FuzzResult:
    """Single fuzzing result"""
    input_value: str
    url: str
    status_code: int
    content_length: int
    content_words: int
    content_lines: int
    redirect_location: str = ""
    content_type: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)

class FFUFFuzzer:
    """
    FFUF (Fuzz Faster U Fool) wrapper for web fuzzing.
    Faster and more flexible than Gobuster.
    """
    
    # Default wordlists (Docker paths)
    WORDLISTS = {
        "small": "/usr/share/wordlists/dirb/common.txt",
        "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        "params": "/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
        "subdomains": "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    }
    
    # Status codes to filter by default
    INTERESTING_CODES = [200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500]

    def __init__(self):
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Verify FFUF is installed"""
        if not shutil.which("ffuf"):
            print("[!] WARNING: FFUF not found. Install with: go install github.com/ffuf/ffuf@latest")
            return False
        return True
    
    def fuzz_directories(
        self,
        url: str,
        wordlist: str = "small",
        extensions: List[str] = None,
        rate_limit: int = 0,
        threads: int = 40,
        timeout: int = 10,
        recursion: bool = False,
        recursion_depth: int = 2,
        filter_codes: List[int] = None,
        filter_size: List[int] = None,
        follow_redirects: bool = False,
    ) -> Dict:
        """
        Directory/file fuzzing.
        
        Args:
            url: Target URL with FUZZ keyword (e.g., http://example.com/FUZZ)
            wordlist: Wordlist name or path
            extensions: File extensions to try (e.g., ["php", "html", "txt"])
            rate_limit: Requests per second (0 = unlimited)
            threads: Concurrent threads
            timeout: Request timeout in seconds
            recursion: Enable recursive scanning
            recursion_depth: Max recursion depth
            filter_codes: Status codes to exclude (default: filter 404)
            filter_size: Response sizes to exclude
            follow_redirects: Follow HTTP redirects
            
        Returns:
            Dict with discovered paths, stats, and metadata
        """
        # Ensure URL has FUZZ keyword
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        
        print(f"[*] TOOL: FFUF directory fuzzing on {url}")
        
        if not shutil.which("ffuf"):
            return {"error": "FFUF not installed", "results": []}
        
        # Resolve wordlist path
        wordlist_path = self.WORDLISTS.get(wordlist, wordlist)
        if not os.path.exists(wordlist_path):
            # Try alternate path
            alt_path = f"/usr/share/wordlists/dirb/{wordlist}.txt"
            if os.path.exists(alt_path):
                wordlist_path = alt_path
            else:
                return {"error": f"Wordlist not found: {wordlist}", "results": []}
        
        # Build command
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist_path,
            "-o", "/tmp/ffuf_output.json",
            "-of", "json",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-mc", ",".join(map(str, filter_codes or self.INTERESTING_CODES)),
        ]
        
        # Extensions
        if extensions:
            cmd.extend(["-e", ",".join(f".{e.lstrip('.')}" for e in extensions)])
        
        # Rate limiting
        if rate_limit > 0:
            cmd.extend(["-rate", str(rate_limit)])
        
        # Recursion
        if recursion:
            cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])
        
        # Redirects
        if follow_redirects:
            cmd.append("-r")
        
        # Filter by size
        if filter_size:
            cmd.extend(["-fs", ",".join(map(str, filter_size))])
        
        # Silent mode
        cmd.append("-s")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 min max
            )
            
            results = self._parse_output("/tmp/ffuf_output.json")
            
            return {
                "target": url.replace("FUZZ", "*"),
                "results": [r.to_dict() for r in results],
                "total_found": len(results),
                "wordlist": wordlist,
                "interesting_paths": self._extract_interesting(results),
                "stderr": result.stderr[:500] if result.stderr else "",
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Fuzzing timeout exceeded", "results": []}
        except Exception as e:
            return {"error": str(e), "results": []}
    
    def fuzz_parameters(
        self,
        url: str,
        wordlist: str = "params",
        method: str = "GET",
        threads: int = 40,
        timeout: int = 10,
    ) -> Dict:
        """
        Parameter discovery fuzzing.
        
        Args:
            url: URL with FUZZ placeholder (e.g., http://example.com/page.php?FUZZ=test)
            wordlist: Parameter wordlist
            method: HTTP method
            threads: Concurrent threads
            timeout: Request timeout
            
        Returns:
            Dict with discovered parameters
        """
        if "FUZZ" not in url:
            # Add parameter placeholder
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}FUZZ=test"
        
        print(f"[*] TOOL: FFUF parameter fuzzing on {url}")
        
        wordlist_path = self.WORDLISTS.get(wordlist, wordlist)
        
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist_path,
            "-o", "/tmp/ffuf_params.json",
            "-of", "json",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-X", method,
            "-mc", "200,301,302,307,401,403,500",
            "-s",
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results = self._parse_output("/tmp/ffuf_params.json")
            
            return {
                "target": url,
                "parameters": [r.input_value for r in results],
                "results": [r.to_dict() for r in results],
                "total_found": len(results),
            }
            
        except Exception as e:
            return {"error": str(e), "parameters": []}
    
    def fuzz_vhosts(
        self,
        url: str,
        domain: str,
        wordlist: str = "subdomains",
        threads: int = 40,
    ) -> Dict:
        """
        Virtual host / subdomain fuzzing via Host header.
        
        Args:
            url: Target URL (IP or resolved domain)
            domain: Base domain for fuzzing (e.g., example.com)
            wordlist: Subdomain wordlist
            threads: Concurrent threads
            
        Returns:
            Dict with discovered virtual hosts
        """
        print(f"[*] TOOL: FFUF vhost fuzzing for {domain}")
        
        wordlist_path = self.WORDLISTS.get(wordlist, wordlist)
        
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist_path,
            "-H", f"Host: FUZZ.{domain}",
            "-o", "/tmp/ffuf_vhosts.json",
            "-of", "json",
            "-t", str(threads),
            "-mc", "200,301,302,307,401,403",
            "-s",
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results = self._parse_output("/tmp/ffuf_vhosts.json")
            
            return {
                "domain": domain,
                "vhosts": [f"{r.input_value}.{domain}" for r in results],
                "results": [r.to_dict() for r in results],
                "total_found": len(results),
            }
            
        except Exception as e:
            return {"error": str(e), "vhosts": []}
    
    def _parse_output(self, output_file: str) -> List[FuzzResult]:
        """Parse FFUF JSON output"""
        results = []
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            for entry in data.get("results", []):
                result = FuzzResult(
                    input_value=entry.get("input", {}).get("FUZZ", ""),
                    url=entry.get("url", ""),
                    status_code=entry.get("status", 0),
                    content_length=entry.get("length", 0),
                    content_words=entry.get("words", 0),
                    content_lines=entry.get("lines", 0),
                    redirect_location=entry.get("redirectlocation", ""),
                    content_type=entry.get("content-type", ""),
                )
                results.append(result)
                
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        return results
    
    def _extract_interesting(self, results: List[FuzzResult]) -> List[str]:
        """Extract particularly interesting findings"""
        interesting = []
        
        keywords = [
            "admin", "login", "dashboard", "config", "backup",
            "api", "upload", "console", "debug", "test",
            ".git", ".env", ".htaccess", "wp-admin", "phpmyadmin",
        ]
        
        for r in results:
            path = r.input_value.lower()
            if any(kw in path for kw in keywords):
                interesting.append(r.url)
            elif r.status_code in [401, 403]:  # Protected resources
                interesting.append(r.url)
        
        return interesting[:20]  # Top 20
    
    def quick_scan(self, url: str, threads: int = 50, rate_limit: int = 0) -> Dict:
        """Fast directory scan with common paths"""
        return self.fuzz_directories(
            url=url,
            wordlist="small",
            extensions=["php", "html", "txt", "js"],
            threads=threads,
            rate_limit=rate_limit,
            timeout=5,
        )
    
    def deep_scan(self, url: str, threads: int = 30, rate_limit: int = 0) -> Dict:
        """Comprehensive directory scan with recursion"""
        return self.fuzz_directories(
            url=url,
            wordlist="medium",
            extensions=["php", "html", "asp", "aspx", "jsp", "txt", "json", "xml", "bak"],
            threads=threads,
            rate_limit=rate_limit,
            timeout=10,
            recursion=True,
            recursion_depth=3,
        )
