# ares_cli/config.py
"""
Configuration management for ARES CLI
Handles scan profiles, tool paths, and user settings
"""
import os
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

def _ensure_go_path():
    """Ensure Go bin directory is in PATH"""
    go_bin = os.path.expanduser("~/go/bin")
    if os.path.exists(go_bin) and go_bin not in os.environ["PATH"]:
        os.environ["PATH"] += f":{go_bin}"

# Initialize PATH
_ensure_go_path()

@dataclass
class ScanProfile:
    """Scan profile configuration"""
    name: str
    description: str
    timeout_minutes: int
    nmap_args: str
    enable_subdomain: bool
    enable_fingerprint: bool
    enable_crawl: bool
    enable_nuclei: bool
    enable_fuzzing: bool
    enable_exploitation: bool
    stealth_mode: bool = False
    rate_limit: int = 100  # requests per second
    threads: int = 10

# Default scan profiles
SCAN_PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast assessment - Top 100 ports, basic fingerprinting",
        timeout_minutes=5,
        nmap_args="-F -T4",
        enable_subdomain=False,
        enable_fingerprint=True,
        enable_crawl=False,
        enable_nuclei=False,
        enable_fuzzing=False,
        enable_exploitation=False,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Full scan - Top 1000 ports, all passive reconnaissance",
        timeout_minutes=30,
        nmap_args="-sV -T4 --top-ports 1000",
        enable_subdomain=True,
        enable_fingerprint=True,
        enable_crawl=True,
        enable_nuclei=True,
        enable_fuzzing=True,
        enable_exploitation=False,
    ),
    "deep": ScanProfile(
        name="deep",
        description="Comprehensive - All ports, full vulnerability assessment",
        timeout_minutes=120,
        nmap_args="-sV -sC -p- -T4",
        enable_subdomain=True,
        enable_fingerprint=True,
        enable_crawl=True,
        enable_nuclei=True,
        enable_fuzzing=True,
        enable_exploitation=True,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Evasive scanning - Low and slow with WAF bypass",
        timeout_minutes=60,
        nmap_args="-sS -T2 -Pn --randomize-hosts",
        enable_subdomain=True,
        enable_fingerprint=True,
        enable_crawl=True,
        enable_nuclei=True,
        enable_fuzzing=False,
        enable_exploitation=True,
        stealth_mode=True,
        rate_limit=10,
        threads=3,
    ),
}

@dataclass
class AresConfig:
    """Main configuration class for ARES CLI"""
    # Paths
    output_dir: str = "./ares_results"
    wordlist_dir: str = "/usr/share/wordlists"
    template_dir: str = ""
    
    # Ollama settings
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    
    # Report settings
    report_author: str = "ARES Security Team"
    report_company: str = ""
    report_logo: str = ""
    
    # Tool settings
    tool_timeout: int = 300  # seconds
    max_concurrent_tools: int = 3
    
    # Scan defaults
    default_profile: str = "standard"
    auto_exploit: bool = False
    
    # Features
    enable_ai_analysis: bool = True
    enable_compliance_check: bool = True
    save_raw_output: bool = True
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "AresConfig":
        """Load configuration from file or use defaults"""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f)
                return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
        
        # Check default locations
        default_paths = [
            Path.home() / ".config" / "ares" / "config.yaml",
            Path.cwd() / "ares_config.yaml",
            Path(__file__).parent.parent / "ares_config.yaml",
        ]
        
        for path in default_paths:
            if path.exists():
                with open(path, 'r') as f:
                    data = yaml.safe_load(f)
                    return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
        
        return cls()
    
    def save(self, config_path: str) -> None:
        """Save configuration to file"""
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            yaml.dump(self.__dict__, f, default_flow_style=False)
    
    def get_profile(self, name: str) -> ScanProfile:
        """Get a scan profile by name"""
        if name not in SCAN_PROFILES:
            raise ValueError(f"Unknown profile: {name}. Available: {list(SCAN_PROFILES.keys())}")
        return SCAN_PROFILES[name]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return self.__dict__.copy()

def get_default_config() -> AresConfig:
    """Get default configuration"""
    return AresConfig()

def get_available_profiles() -> List[str]:
    """Get list of available scan profiles"""
    return list(SCAN_PROFILES.keys())
