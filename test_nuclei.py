import sys
import os
import json
sys.path.append("/home/rizz/Desktop/ARES")
from ares_cli.tools.nuclei_scanner import NucleiScanner

print("Initializing scanner...")
scanner = NucleiScanner()

print("Running explicit sqli scan on testphp.vulnweb.com...")
# Using explicit scan to hit sqli templates which should find the vulnerabilities
res = scanner.scan("http://testphp.vulnweb.com", tags=["sqli", "xss"], severity=["critical", "high", "medium", "low"], timeout=15)

stats = res.get("stats", {})
print(f"\nStats: {stats}")
if "error" in res:
    print(f"Error: {res['error']}")

vulns = res.get("vulnerabilities", [])
print(f"\nFound {len(vulns)} vulnerabilities:")
for v in vulns:
    print(f"- [{v.severity.upper()}] {v.name}")
