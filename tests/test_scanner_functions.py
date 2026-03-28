"""
Unit tests for ARES core scanning functions.
Tests: _analyze_technologies, _parse_nikto_findings, _calculate_severity, remediation_db
"""
import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ares_cli.remediation_db import get_remediation, get_quick_wins, generate_remediation_roadmap
from ares_cli.cvss import CVSSCalculator


# =====================================================================
# Test: _analyze_technologies (mocked via direct pattern matching logic)
# =====================================================================
class TestAnalyzeTechnologies(unittest.TestCase):
    """Test the EOL technology detection patterns from scanner._analyze_technologies"""
    
    def _get_eol_tech(self):
        """Return the eol_tech patterns dictionary (mirrors scanner.py)"""
        return {
            "php/5.": {"name": "PHP 5.x End-of-Life", "severity": "high", "cve": "CVE-2019-11043"},
            "php/7.0": {"name": "PHP 7.0 End-of-Life", "severity": "high", "cve": "CVE-2019-11043"},
            "php/7.1": {"name": "PHP 7.1 End-of-Life", "severity": "high", "cve": "CVE-2019-11043"},
            "php/7.2": {"name": "PHP 7.2 End-of-Life", "severity": "medium", "cve": "CVE-2020-7071"},
            "php/7.3": {"name": "PHP 7.3 End-of-Life", "severity": "medium", "cve": "CVE-2021-21702"},
            "php/7.4": {"name": "PHP 7.4 End-of-Life", "severity": "medium", "cve": "CVE-2022-31625"},
            "php/8.0": {"name": "PHP 8.0 End-of-Life", "severity": "low", "cve": "CVE-2023-3824"},
            "nginx/1.19": {"name": "Nginx 1.19 End-of-Life", "severity": "medium", "cve": "CVE-2021-23017"},
            "nginx/1.18": {"name": "Nginx 1.18 End-of-Life", "severity": "medium", "cve": "CVE-2021-23017"},
            "nginx/1.17": {"name": "Nginx 1.17 End-of-Life", "severity": "high", "cve": "CVE-2019-20372"},
            "apache/2.2": {"name": "Apache 2.2 End-of-Life", "severity": "high", "cve": "CVE-2017-9798"},
            "apache/2.4.49": {"name": "Apache 2.4.49 Path Traversal", "severity": "critical", "cve": "CVE-2021-41773"},
            "jquery/1.": {"name": "jQuery 1.x Vulnerable", "severity": "medium", "cve": "CVE-2020-11022"},
            "openssh/7.": {"name": "OpenSSH 7.x Outdated", "severity": "medium", "cve": "CVE-2021-41617"},
            "openssl/1.0": {"name": "OpenSSL 1.0 End-of-Life", "severity": "high", "cve": "CVE-2022-0778"},
            "iis/7.": {"name": "IIS 7.x End-of-Life", "severity": "high", "cve": "CVE-2017-7269"},
            "node/12.": {"name": "Node.js 12.x End-of-Life", "severity": "medium", "cve": "CVE-2021-22960"},
            "wordpress/": {"name": "WordPress Detected", "severity": "medium"},
        }
    
    def _find_matches(self, technologies):
        """Simulate _analyze_technologies pattern matching"""
        eol_tech = self._get_eol_tech()
        tech_str = " ".join(technologies).lower()
        matches = []
        for pattern, vuln_info in eol_tech.items():
            if pattern.lower() in tech_str:
                entry = {
                    "tool": "whatweb",
                    "name": vuln_info["name"],
                    "severity": vuln_info["severity"],
                }
                if vuln_info.get("cve"):
                    entry["cve"] = vuln_info["cve"]
                matches.append(entry)
        return matches
    
    def test_php5_detected(self):
        """PHP 5.6.40 should be flagged as HIGH with CVE"""
        techs = ["PHP/5.6.40", "nginx/1.25.0"]
        matches = self._find_matches(techs)
        php_matches = [m for m in matches if "PHP 5" in m["name"]]
        self.assertEqual(len(php_matches), 1)
        self.assertEqual(php_matches[0]["severity"], "high")
        self.assertEqual(php_matches[0]["cve"], "CVE-2019-11043")
    
    def test_php74_detected(self):
        """PHP 7.4 should be medium severity"""
        techs = ["PHP/7.4.33"]
        matches = self._find_matches(techs)
        self.assertTrue(any("PHP 7.4" in m["name"] for m in matches))
        php74 = [m for m in matches if "PHP 7.4" in m["name"]][0]
        self.assertEqual(php74["severity"], "medium")
    
    def test_nginx_119_detected(self):
        """Nginx 1.19.0 should be medium"""
        techs = ["nginx/1.19.0"]
        matches = self._find_matches(techs)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "medium")
        self.assertEqual(matches[0]["cve"], "CVE-2021-23017")
    
    def test_apache_249_critical(self):
        """Apache 2.4.49 should be critical with CVE-2021-41773"""
        techs = ["Apache/2.4.49"]
        matches = self._find_matches(techs)
        critical = [m for m in matches if m["severity"] == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["cve"], "CVE-2021-41773")
    
    def test_jquery_1x_detected(self):
        """jQuery 1.12.4 should be flagged as medium"""
        techs = ["jQuery/1.12.4"]
        matches = self._find_matches(techs)
        self.assertTrue(any("jQuery 1.x" in m["name"] for m in matches))
    
    def test_modern_software_no_match(self):
        """Modern software versions should not trigger any alerts"""
        techs = ["PHP/8.3.0", "nginx/1.25.3", "Apache/2.4.58"]
        matches = self._find_matches(techs)
        self.assertEqual(len(matches), 0, f"False positive: {[m['name'] for m in matches]}")
    
    def test_empty_technologies(self):
        """Empty tech list should produce no matches"""
        matches = self._find_matches([])
        self.assertEqual(len(matches), 0)
    
    def test_multiple_matches(self):
        """Multiple EOL technologies should all be detected"""
        techs = ["PHP/5.6.40", "nginx/1.19.0", "jQuery/1.9.1"]
        matches = self._find_matches(techs)
        self.assertGreaterEqual(len(matches), 3)
    
    def test_case_insensitive(self):
        """Detection should work regardless of case"""
        techs = ["PHP/5.6.40", "NGINX/1.19.0"]
        matches = self._find_matches(techs)
        self.assertGreaterEqual(len(matches), 2)


# =====================================================================
# Test: _parse_nikto_findings (severity classification)
# =====================================================================
class TestParseNiktoFindings(unittest.TestCase):
    """Test Nikto output parsing and severity classification"""
    
    CRITICAL_KEYWORDS = ["remote code execution", "rce", "command execution", "backdoor", "shell upload"]
    HIGH_KEYWORDS = ["sql injection", "sqli", "xss", "cross-site scripting", "file inclusion",
                     "directory traversal", "path traversal", "lfi", "rfi", "xxe",
                     "unrestricted upload", "arbitrary file", "authentication bypass"]
    MEDIUM_KEYWORDS = ["misconfiguration", "directory listing", "directory indexing",
                       "information disclosure", "default credentials", "default password",
                       "clickjacking", "x-frame-options", "content-type-options",
                       "cors", "cookie", "httponly", "secure flag", "csrf",
                       "server version", "php version", "debug", "phpinfo"]
    
    def _classify(self, finding_text):
        """Simulate Nikto severity classification"""
        import re
        finding_lower = finding_text.lower()
        if any(kw in finding_lower for kw in self.CRITICAL_KEYWORDS):
            return "critical"
        elif any(kw in finding_lower for kw in self.HIGH_KEYWORDS):
            return "high"
        elif any(kw in finding_lower for kw in self.MEDIUM_KEYWORDS):
            return "medium"
        elif "osvdb-" in finding_lower:
            return "medium"
        else:
            return "low"
    
    def test_sql_injection_is_high(self):
        self.assertEqual(self._classify("OSVDB-1234: SQL Injection found in search parameter"), "high")
    
    def test_xss_is_high(self):
        self.assertEqual(self._classify("Cross-site scripting vulnerability found"), "high")
    
    def test_rce_is_critical(self):
        self.assertEqual(self._classify("Remote code execution via CGI"), "critical")
    
    def test_backdoor_is_critical(self):
        self.assertEqual(self._classify("Backdoor detected at /shell.php"), "critical")
    
    def test_directory_listing_is_medium(self):
        self.assertEqual(self._classify("Directory listing enabled on /images/"), "medium")
    
    def test_missing_header_is_medium(self):
        self.assertEqual(self._classify("X-Frame-Options header not set"), "medium")
    
    def test_phpinfo_is_medium(self):
        self.assertEqual(self._classify("phpinfo() page found at /info.php"), "medium")
    
    def test_osvdb_generic_is_medium(self):
        self.assertEqual(self._classify("OSVDB-3092: Some known vulnerability"), "medium")
    
    def test_unknown_finding_is_low(self):
        self.assertEqual(self._classify("Web server returned unusual response"), "low")
    
    def test_lfi_is_high(self):
        self.assertEqual(self._classify("LFI vulnerability in file= parameter"), "high")
    
    def test_path_traversal_is_high(self):
        self.assertEqual(self._classify("Path traversal via ../../../etc/passwd"), "high")


# =====================================================================
# Test: CVSS Scoring
# =====================================================================
class TestCVSSScoring(unittest.TestCase):
    """Test CVSS vulnerability scoring"""
    
    def test_sql_injection_critical(self):
        result = CVSSCalculator.score_vulnerability("SQL Injection in login form")
        self.assertGreaterEqual(result["cvss_base"], 8.0)
    
    def test_xss_high(self):
        result = CVSSCalculator.score_vulnerability("Cross-Site Scripting (XSS)")
        self.assertGreaterEqual(result["cvss_base"], 5.0)
    
    def test_rce_critical(self):
        result = CVSSCalculator.score_vulnerability("Remote Code Execution")
        self.assertGreaterEqual(result["cvss_base"], 9.0)
    
    def test_info_disclosure_low(self):
        result = CVSSCalculator.score_vulnerability("Information Disclosure")
        self.assertLessEqual(result["cvss_base"], 6.0)
    
    def test_exploit_increases_score(self):
        base = CVSSCalculator.score_vulnerability("Generic Vulnerability", has_exploit=False)
        exploited = CVSSCalculator.score_vulnerability("Generic Vulnerability", has_exploit=True)
        self.assertGreaterEqual(exploited["cvss_temporal"], base["cvss_temporal"])
    
    def test_unknown_vuln_gets_default(self):
        result = CVSSCalculator.score_vulnerability("Completely Unknown Thing")
        self.assertGreaterEqual(result["cvss_base"], 0.0)
        self.assertIn("cvss_vector", result)


# =====================================================================
# Test: Remediation DB
# =====================================================================
class TestRemediationDB(unittest.TestCase):
    """Test remediation database lookups, quick wins, and roadmap generation"""
    
    def test_sql_injection_lookup(self):
        rem = get_remediation("SQL Injection")
        self.assertIsNotNone(rem)
        self.assertIn("SQL", rem.title)
        self.assertEqual(rem.cwe_id, "CWE-89")
    
    def test_xss_lookup(self):
        rem = get_remediation("Cross-Site Scripting (XSS)")
        self.assertIsNotNone(rem)
        self.assertIn("XSS", rem.title)
    
    def test_rce_lookup(self):
        rem = get_remediation("Remote Code Execution")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.priority, "Critical")
    
    def test_php_eol_routes_to_php_specific(self):
        """PHP EOL should route to php-eol entry (effort=Low) not outdated-software (effort=Medium)"""
        rem = get_remediation("PHP 5.x End-of-Life")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.effort, "Low")
        self.assertIn("PHP", rem.title)
    
    def test_nginx_eol_routes_to_nginx_specific(self):
        """Nginx EOL should route to nginx-eol"""
        rem = get_remediation("Nginx 1.19 End-of-Life")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.effort, "Low")
        self.assertIn("Nginx", rem.title)
    
    def test_apache_eol_routes_to_apache_specific(self):
        """Apache EOL should route to apache-eol"""
        rem = get_remediation("Apache 2.2 End-of-Life")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.effort, "Low")
        self.assertIn("Apache", rem.title)
    
    def test_unknown_vuln_returns_none(self):
        """A completely unrecognized vulnerability should return None"""
        rem = get_remediation("ZeroDay UnknownType Vuln XYZ")
        self.assertIsNone(rem)
    
    def test_quick_wins_includes_eol(self):
        """PHP EOL should appear in Quick Wins (effort=Low, priority=High)"""
        vulns = [
            {"name": "PHP 5.x End-of-Life", "severity": "high"},
            {"name": "Nginx 1.19 End-of-Life", "severity": "medium"},
        ]
        wins = get_quick_wins(vulns)
        self.assertGreater(len(wins), 0, "Quick wins should not be empty for EOL findings")
        titles = [w["title"] for w in wins]
        self.assertTrue(any("PHP" in t for t in titles), f"PHP not in quick wins: {titles}")
    
    def test_quick_wins_excludes_medium_effort(self):
        """Generic outdated software (effort=Medium) should NOT appear in Quick Wins"""
        vulns = [{"name": "Some Generic CVE Vulnerability", "severity": "high"}]
        wins = get_quick_wins(vulns)
        # "outdated-software" has effort=Medium, shouldn't be in quick wins
        for win in wins:
            self.assertNotEqual(win.get("effort"), "Medium",
                              f"Medium effort item in quick wins: {win['title']}")
    
    def test_roadmap_ordered_by_priority(self):
        """Remediation roadmap should be ordered: Critical > High > Medium > Low"""
        vulns = [
            {"name": "SQL Injection", "severity": "critical"},
            {"name": "Missing Security Headers", "severity": "medium"},
            {"name": "PHP 5.x End-of-Life", "severity": "high"},
        ]
        roadmap = generate_remediation_roadmap(vulns)
        self.assertGreaterEqual(len(roadmap), 2)
        
        # Check ordering
        priorities = [item["priority"] for item in roadmap]
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        indices = [priority_order.get(p, 99) for p in priorities]
        self.assertEqual(indices, sorted(indices), f"Roadmap not in priority order: {priorities}")
    
    def test_roadmap_has_timeline(self):
        """Each roadmap item should have a timeline"""
        vulns = [{"name": "SQL Injection", "severity": "critical"}]
        roadmap = generate_remediation_roadmap(vulns)
        for item in roadmap:
            self.assertIn("timeline", item)
    
    def test_roadmap_deduplicates(self):
        """Multiple same-type vulns should produce only one roadmap entry"""
        vulns = [
            {"name": "PHP 5.x End-of-Life", "severity": "high"},
            {"name": "PHP 7.0 End-of-Life", "severity": "high"},
        ]
        roadmap = generate_remediation_roadmap(vulns)
        php_items = [i for i in roadmap if "PHP" in i["title"]]
        # Both should map to the same remediation, so only 1 entry
        self.assertEqual(len(php_items), 1)


# =====================================================================
# Test: New CVSS Patterns
# =====================================================================
class TestNewCVSSPatterns(unittest.TestCase):
    """Test new CVSS vulnerability patterns added for coverage"""
    
    def test_directory_traversal_high(self):
        result = CVSSCalculator.score_vulnerability("Directory Traversal via ../../etc/passwd")
        self.assertGreaterEqual(result["cvss_base"], 6.0)
    
    def test_xxe_high(self):
        result = CVSSCalculator.score_vulnerability("XXE Injection in XML parser")
        self.assertGreaterEqual(result["cvss_base"], 7.0)
    
    def test_csrf_medium(self):
        result = CVSSCalculator.score_vulnerability("CSRF token missing on form")
        self.assertGreaterEqual(result["cvss_base"], 4.0)
    
    def test_deserialization_critical(self):
        result = CVSSCalculator.score_vulnerability("Insecure Deserialization RCE")
        self.assertGreaterEqual(result["cvss_base"], 8.0)
    
    def test_clickjacking_low(self):
        result = CVSSCalculator.score_vulnerability("Clickjacking - X-Frame-Options missing")
        self.assertGreaterEqual(result["cvss_base"], 2.0)
    
    def test_idor_medium(self):
        result = CVSSCalculator.score_vulnerability("IDOR in user profile API")
        self.assertGreaterEqual(result["cvss_base"], 5.0)
    
    def test_file_upload_critical(self):
        result = CVSSCalculator.score_vulnerability("Unrestricted File Upload")
        self.assertGreaterEqual(result["cvss_base"], 8.0)


# =====================================================================
# Test: New Remediation DB Entries
# =====================================================================
class TestNewRemediationEntries(unittest.TestCase):
    """Test new remediation database entries"""
    
    def test_csrf_lookup(self):
        rem = get_remediation("CSRF token missing")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-352")
    
    def test_xxe_lookup(self):
        rem = get_remediation("XXE Injection in parser")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-611")
    
    def test_idor_lookup(self):
        rem = get_remediation("IDOR vulnerability in API")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-639")
    
    def test_clickjacking_lookup(self):
        rem = get_remediation("Clickjacking vulnerability")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-1021")
    
    def test_cors_lookup(self):
        rem = get_remediation("CORS Misconfiguration")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-942")
    
    def test_deserialization_lookup(self):
        rem = get_remediation("Insecure Deserialization")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-502")
    
    def test_cookie_lookup(self):
        rem = get_remediation("Cookie without HttpOnly flag")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-614")
    
    def test_file_upload_lookup(self):
        rem = get_remediation("Unrestricted File Upload")
        self.assertIsNotNone(rem)
        self.assertEqual(rem.cwe_id, "CWE-434")


if __name__ == "__main__":
    unittest.main(verbosity=2)
