import sys
import os
import json
sys.path.append("/home/rizz/Desktop/ARES")
from ares_cli.tools.nuclei_scanner import NucleiScanner

print("Initializing scanner...")
scanner = NucleiScanner()

print("Running quick scan on testphp.vulnweb.com to verify DAST fuzzing...")
res = scanner.quick_scan("http://testphp.vulnweb.com")

stats = res.get("stats", {})
print(f"\nStats: {stats}")
if "error" in res:
    print(f"Error: {res['error']}")

vulns = res.get("vulnerabilities", [])
print(f"\nFound {len(vulns)} vulnerabilities:")
for v in vulns:
    print(f"- [{v.severity.upper()}] {v.name}")
