# backend/tools/__init__.py
"""
ARES Security Tools Package
Comprehensive reconnaissance and exploitation tools
"""

# Original tool manager (kept for backward compatibility)
from .tool_manager import ReconTools

# New enhanced tool manager (recommended)
from .enhanced_tool_manager import EnhancedReconTools

# Individual tool modules
from .nuclei_scanner import NucleiScanner, NucleiVulnerability, NucleiSeverity
from .subdomain_enum import SubdomainEnumerator, Subdomain
from .ffuf_fuzzer import FFUFFuzzer, FuzzResult, FuzzMode
from .katana_crawler import KatanaCrawler, CrawlResult, EndpointAnalysis
from .whatweb_fingerprint import WhatWebFingerprinter, WebFingerprint, Technology

__all__ = [
    # Managers
    "ReconTools",
    "EnhancedReconTools",
    # Scanners
    "NucleiScanner",
    "NucleiVulnerability",
    "NucleiSeverity",
    # Subdomain
    "SubdomainEnumerator",
    "Subdomain",
    # Fuzzing
    "FFUFFuzzer",
    "FuzzResult",
    "FuzzMode",
    # Crawling
    "KatanaCrawler",
    "CrawlResult",
    "EndpointAnalysis",
    # Fingerprinting
    "WhatWebFingerprinter",
    "WebFingerprint",
    "Technology",
]