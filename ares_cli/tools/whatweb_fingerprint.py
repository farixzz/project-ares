# backend/tools/whatweb_fingerprint.py
"""
WhatWeb - Web Technology Fingerprinting
Identifies web technologies, frameworks, and server configurations
"""
import subprocess
import json
import shutil
import re
import os
import uuid
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class AggressionLevel(Enum):
    """WhatWeb aggression levels"""
    STEALTHY = 1      # One request per target
    PASSIVE = 2       # Multiple requests, no aggressive
    AGGRESSIVE = 3    # Trigger edge cases
    HEAVY = 4         # Heavy load, intrusive
    

@dataclass
class Technology:
    """Detected technology with metadata"""
    name: str
    version: str = ""
    category: str = ""
    confidence: int = 100
    evidence: str = ""
    cpe: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class WebFingerprint:
    """Complete fingerprint of a web target"""
    url: str
    status_code: int
    title: str
    ip_address: str
    country: str
    technologies: List[Technology]
    server: str = ""
    x_powered_by: str = ""
    cookies: List[str] = None
    headers: Dict[str, str] = None
    
    def to_dict(self) -> dict:
        result = asdict(self)
        result['technologies'] = [t.to_dict() if isinstance(t, Technology) else t for t in self.technologies]
        return result


class WhatWebFingerprinter:
    """
    WhatWeb technology fingerprinting wrapper.
    Identifies CMS, frameworks, plugins, and server technologies.
    """
    
    # Technology categories and their security implications
    SECURITY_IMPLICATIONS = {
        "WordPress": ["Check for outdated plugins", "WPScan recommended"],
        "Joomla": ["Check CVE database", "Version-specific exploits"],
        "Drupal": ["Drupalgeddon vulnerabilities", "Module security"],
        "PHP": ["Check for RCE vulnerabilities", "Version disclosure"],
        "Apache": ["Check httpd.conf", "mod_security bypass"],
        "Nginx": ["Config file leaks", "Path traversal"],
        "jQuery": ["Old versions have XSS", "Check dependencies"],
        "Bootstrap": ["XSS in older versions", "Update recommended"],
        "ASP.NET": ["ViewState attacks", "Web.config exposure"],
        "Node.js": ["Prototype pollution", "Dependency vulnerabilities"],
    }
    
    # CVE lookup for common tech
    KNOWN_CVES = {
        "WordPress 4.": "CVE-2017-8295, CVE-2018-6389",
        "WordPress 5.0": "CVE-2019-8943",
        "Drupal 7": "Drupalgeddon (CVE-2014-3704)",
        "Apache 2.4.49": "CVE-2021-41773 (Path Traversal)",
        "Apache 2.4.50": "CVE-2021-42013 (RCE)",
        "jQuery 1.": "CVE-2020-11022, CVE-2020-11023",
        "jQuery 2.": "CVE-2020-11022",
    }

    def __init__(self):
        self._check_installation()
    
    def _check_installation(self) -> bool:
        """Verify WhatWeb is installed"""
        if not shutil.which("whatweb"):
            print("[!] WARNING: WhatWeb not found. Install with: apt-get install whatweb")
            return False
        return True
    
    def fingerprint(
        self,
        url: str,
        aggression: AggressionLevel = AggressionLevel.PASSIVE,
        user_agent: str = None,
        proxy: str = None,
        timeout: int = 30,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        color: bool = False,
    ) -> Dict:
        """
        Fingerprint web technologies on a target.
        
        Args:
            url: Target URL
            aggression: Scan intensity level (1-4)
            user_agent: Custom user agent string
            proxy: Proxy URL (http://host:port)
            timeout: Request timeout in seconds
            follow_redirects: Follow HTTP redirects
            max_redirects: Maximum redirects to follow
            color: Include color codes in output
            
        Returns:
            Dict with detected technologies and analysis
        """
        print(f"[*] TOOL: WhatWeb fingerprinting {url}")
        
        if not shutil.which("whatweb"):
            return {"error": "WhatWeb not installed", "fingerprint": None}
            
        # Use unique output file to avoid collisions/appending
        output_file = f"/tmp/whatweb_{uuid.uuid4().hex}.json"
        
        # Build command
        cmd = [
            "whatweb",
            url,
            f"-a{aggression.value}",
            f"--log-json={output_file}",
            f"--open-timeout={timeout}",
            f"--read-timeout={timeout}",
            f"--max-redirects={max_redirects}",
        ]
        
        if not follow_redirects:
            cmd.append("--no-follow-redirect")
        
        if user_agent:
            cmd.extend(["--user-agent", user_agent])
        
        if proxy:
            cmd.extend(["--proxy", proxy])
        
        if not color:
            cmd.append("--color=never")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            fingerprint = self._parse_output(output_file)
            
            
            if fingerprint:
                analysis = self._analyze_fingerprint(fingerprint)
                
                # Cleanup
                if os.path.exists(output_file):
                    try:
                        os.remove(output_file)
                    except:
                        pass
                
                return {
                    "target": url,
                    "fingerprint": fingerprint.to_dict(),
                    "analysis": analysis,
                    "security_notes": self._get_security_notes(fingerprint),
                    "potential_cves": self._find_cves(fingerprint),
                    "attack_surface": self._assess_attack_surface(fingerprint),
                }
            else:
                if os.path.exists(output_file):
                    try:
                        os.remove(output_file)
                    except:
                        pass
                return {
                    "target": url,
                    "error": "Failed to parse fingerprint",
                    "raw_output": result.stdout[:1000],
                }
            
        except subprocess.TimeoutExpired:
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass
            return {"error": "Fingerprinting timeout", "fingerprint": None}
        except Exception as e:
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass
            return {"error": str(e), "fingerprint": None}
    
    def _parse_output(self, output_file: str) -> Optional[WebFingerprint]:
        """Parse WhatWeb JSON output - handles multi-object output from redirect chains"""
        try:
            with open(output_file, 'r') as f:
                raw = f.read().strip()
            
            if not raw:
                return None
            
            # WhatWeb outputs one JSON array per redirect hop, concatenated.
            # e.g. [{...}]\n[{...}]  -- this is NOT valid JSON as a whole.
            # Strategy: parse each JSON array separately using a decoder.
            all_entries = []
            decoder = json.JSONDecoder()
            pos = 0
            while pos < len(raw):
                # Skip whitespace
                while pos < len(raw) and raw[pos] in ' \t\n\r':
                    pos += 1
                if pos >= len(raw):
                    break
                try:
                    obj, end_pos = decoder.raw_decode(raw, pos)
                    if isinstance(obj, list):
                        all_entries.extend(obj)
                    elif isinstance(obj, dict):
                        all_entries.append(obj)
                    pos = end_pos
                except json.JSONDecodeError:
                    break
            
            if not all_entries:
                return None
            
            # Use the LAST entry (final destination after redirects) for best data
            entry = all_entries[-1]
            
            technologies = []
            plugins = entry.get("plugins", {})
            
            for name, details in plugins.items():
                tech = Technology(
                    name=name,
                    version=self._extract_version(details),
                    category=self._categorize_tech(name),
                    confidence=details.get("certainty", 100),
                    evidence=str(details.get("string", [""])[0] if details.get("string") else ""),
                )
                technologies.append(tech)
            
            fingerprint = WebFingerprint(
                url=entry.get("target", ""),
                status_code=entry.get("http_status", 0),
                title=plugins.get("Title", {}).get("string", [""])[0] if "Title" in plugins else "",
                ip_address=plugins.get("IP", {}).get("string", [""])[0] if "IP" in plugins else "",
                country=plugins.get("Country", {}).get("string", [""])[0] if "Country" in plugins else "",
                technologies=technologies,
                server=plugins.get("HTTPServer", {}).get("string", [""])[0] if "HTTPServer" in plugins else "",
                x_powered_by=plugins.get("X-Powered-By", {}).get("string", [""])[0] if "X-Powered-By" in plugins else "",
                cookies=plugins.get("Cookies", {}).get("string", []) if "Cookies" in plugins else [],
            )
            
            return fingerprint
            
        except (FileNotFoundError, KeyError) as e:
            print(f"    [!] WhatWeb Parse Error: {e}")
            return None
        except Exception as e:
            print(f"    [!] WhatWeb Parse Error: {e}")
            try:
                with open(output_file, 'r') as f:
                    print(f"    [?] Raw Output Start: {f.read(200)}...")
            except:
                pass
            return None
    
    def _extract_version(self, details: dict) -> str:
        """Extract version from plugin details"""
        if "version" in details:
            versions = details["version"]
            if isinstance(versions, list) and versions:
                return str(versions[0])
            return str(versions)
        
        # Try to extract from string
        strings = details.get("string", [])
        if strings:
            for s in strings:
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', str(s))
                if version_match:
                    return version_match.group(1)
        
        return ""
    
    def _categorize_tech(self, name: str) -> str:
        """Categorize technology by name"""
        categories = {
            "CMS": ["WordPress", "Joomla", "Drupal", "Magento", "Shopify"],
            "Framework": ["Bootstrap", "jQuery", "React", "Angular", "Vue"],
            "Language": ["PHP", "ASP.NET", "Python", "Ruby", "Node.js"],
            "Server": ["Apache", "Nginx", "IIS", "LiteSpeed"],
            "Database": ["MySQL", "PostgreSQL", "MongoDB"],
            "Security": ["Cloudflare", "WAF", "Sucuri"],
            "Analytics": ["Google Analytics", "Matomo", "Mixpanel"],
        }
        
        for category, techs in categories.items():
            if any(tech.lower() in name.lower() for tech in techs):
                return category
        
        return "Other"
    
    def _analyze_fingerprint(self, fp: WebFingerprint) -> Dict:
        """Analyze fingerprint for security insights"""
        analysis = {
            "technology_count": len(fp.technologies),
            "has_waf": any("waf" in t.name.lower() or "firewall" in t.name.lower() for t in fp.technologies),
            "has_cms": any(t.category == "CMS" for t in fp.technologies),
            "server_disclosed": bool(fp.server),
            "version_disclosed": any(t.version for t in fp.technologies),
            "security_headers_missing": [],  # Would need additional check
            "outdated_tech": [],
        }
        
        # Check for outdated tech
        for tech in fp.technologies:
            if tech.version:
                version_key = f"{tech.name} {tech.version.split('.')[0]}."
                if version_key in self.KNOWN_CVES:
                    analysis["outdated_tech"].append({
                        "name": tech.name,
                        "version": tech.version,
                        "cves": self.KNOWN_CVES[version_key],
                    })
        
        return analysis
    
    def _get_security_notes(self, fp: WebFingerprint) -> List[str]:
        """Get security notes based on detected tech"""
        notes = []
        
        for tech in fp.technologies:
            for key, implications in self.SECURITY_IMPLICATIONS.items():
                if key.lower() in tech.name.lower():
                    notes.extend(implications)
        
        # Server-specific notes
        if fp.server:
            notes.append(f"Server disclosed: {fp.server} - Consider removing banner")
        
        if fp.x_powered_by:
            notes.append(f"X-Powered-By header present: {fp.x_powered_by}")
        
        return list(set(notes))  # Dedupe
    
    def _find_cves(self, fp: WebFingerprint) -> List[Dict]:
        """Find known CVEs for detected technologies"""
        cves = []
        
        for tech in fp.technologies:
            version_key = f"{tech.name} {tech.version}"
            
            for pattern, cve_list in self.KNOWN_CVES.items():
                if pattern.lower() in version_key.lower():
                    cves.append({
                        "technology": tech.name,
                        "version": tech.version,
                        "cves": cve_list,
                    })
        
        return cves
    
    def _assess_attack_surface(self, fp: WebFingerprint) -> Dict:
        """Assess overall attack surface"""
        risk_score = 0
        vectors = []
        
        for tech in fp.technologies:
            # CMS = higher risk
            if tech.category == "CMS":
                risk_score += 20
                vectors.append(f"{tech.name} CMS exploitation")
            
            # Outdated versions
            if tech.version and tech.version.startswith(("1.", "2.", "3.")):
                risk_score += 15
                vectors.append(f"Potentially outdated {tech.name}")
            
            # PHP = injection risks
            if "php" in tech.name.lower():
                risk_score += 10
                vectors.append("PHP-based application (injection risks)")
        
        # Version disclosure
        if any(t.version for t in fp.technologies):
            risk_score += 10
            vectors.append("Version information disclosed")
        
        return {
            "risk_score": min(risk_score, 100),
            "attack_vectors": vectors,
            "recommendation": self._get_recommendation(risk_score),
        }
    
    def _get_recommendation(self, risk_score: int) -> str:
        """Get recommendation based on risk score"""
        if risk_score >= 70:
            return "HIGH PRIORITY: Multiple attack vectors identified. Proceed with targeted exploitation."
        elif risk_score >= 40:
            return "MEDIUM: Some attack surface exposed. Conduct further enumeration."
        else:
            return "LOW: Minimal information disclosed. Consider alternative reconnaissance methods."
    
    def quick_fingerprint(self, url: str) -> Dict:
        """Fast fingerprint with minimal requests"""
        return self.fingerprint(
            url=url,
            aggression=AggressionLevel.STEALTHY,
            timeout=15,
        )
    
    def full_fingerprint(self, url: str) -> Dict:
        """Comprehensive fingerprint with aggressive detection"""
        return self.fingerprint(
            url=url,
            aggression=AggressionLevel.AGGRESSIVE,
            timeout=60,
        )
