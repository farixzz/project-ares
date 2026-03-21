# ares_cli/display.py
"""
Rich console display utilities for ARES CLI
Beautiful terminal output with cyberpunk theming
"""
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Custom cyberpunk theme
ARES_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "phase": "bold magenta",
    "tool": "bold blue",
    "vuln.critical": "bold white on red",
    "vuln.high": "bold red",
    "vuln.medium": "bold yellow",
    "vuln.low": "bold cyan",
    "vuln.info": "dim white",
    "header": "bold white on #1a1a2e",
    "accent": "#e94560",
    "cyber": "#00ff41",
})

console = Console(theme=ARES_THEME)

def print_banner() -> None:
    """Print the ARES banner"""
    banner = """
[bold #e94560]
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██████╗ ███████╗███████╗                          ║
    ║    ██╔══██╗██╔══██╗██╔════╝██╔════╝                          ║
    ║    ███████║██████╔╝█████╗  ███████╗                          ║
    ║    ██╔══██║██╔══██╗██╔══╝  ╚════██║                          ║
    ║    ██║  ██║██║  ██║███████╗███████║                          ║
    ║    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝                          ║
    ║                                                               ║
    ║    [bold #00ff41]Autonomous Recon & Exploitation System[/]             ║
    ║    [dim white]AI-Powered Penetration Testing Framework[/]               ║
    ║    [bold cyan]v2.0.1 | CVSS Scoring | Remediation Intel[/]             ║
    ║    [dim white]Developed by[/] [bold #00ff41]farixzz[/] [dim cyan]github.com/farixzz[/]          ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
[/]"""
    console.print(banner)

def print_phase(phase_name: str, message: str = "") -> None:
    """Print a phase header"""
    console.print(f"\n[phase]▶ PHASE: {phase_name.upper()}[/phase]")
    if message:
        console.print(f"  [dim]{message}[/dim]")

def print_tool(tool_name: str, target: str) -> None:
    """Print tool execution message"""
    console.print(f"  [tool]⚙ {tool_name}[/tool] → [cyan]{target}[/cyan]")

def print_finding(severity: str, finding: str, details: str = "") -> None:
    """Print a security finding"""
    severity_styles = {
        "critical": "vuln.critical",
        "high": "vuln.high",
        "medium": "vuln.medium",
        "low": "vuln.low",
        "info": "vuln.info",
    }
    style = severity_styles.get(severity.lower(), "vuln.info")
    console.print(f"  [{style}]● {severity.upper()}[/{style}]: {finding}")
    if details:
        console.print(f"    [dim]{details}[/dim]")

def print_success(message: str) -> None:
    """Print success message"""
    console.print(f"[success]✓ {message}[/success]")

def print_error(message: str) -> None:
    """Print error message"""
    console.print(f"[error]✗ {message}[/error]")

def print_warning(message: str) -> None:
    """Print warning message"""
    console.print(f"[warning]⚠ {message}[/warning]")

def print_info(message: str) -> None:
    """Print info message"""
    console.print(f"[info]ℹ {message}[/info]")

def create_scan_progress() -> Progress:
    """Create progress bar for scanning"""
    return Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )

def print_scan_summary(results: Dict[str, Any]) -> None:
    """Print scan summary table"""
    table = Table(
        title="[bold]Scan Summary[/bold]",
        show_header=True,
        header_style="bold white on #1a1a2e",
        border_style="cyan",
    )
    
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="white", width=40)
    
    # Add rows
    table.add_row("Target", results.get("target", "N/A"))
    table.add_row("Scan Profile", results.get("profile", "N/A"))
    table.add_row("Duration", results.get("duration", "N/A"))
    table.add_row("Open Ports", str(results.get("open_ports_count", 0)))
    table.add_row("Subdomains Found", str(results.get("subdomain_count", 0)))
    table.add_row("Endpoints Discovered", str(results.get("endpoints_count", 0)))
    table.add_row("Technologies Detected", str(results.get("tech_count", 0)))
    
    console.print(table)

def print_vulnerability_table(vulnerabilities: List[Dict]) -> None:
    """Print vulnerabilities in a table"""
    if not vulnerabilities:
        console.print("[dim]No vulnerabilities detected[/dim]")
        return
    
    table = Table(
        title="[bold red]Vulnerabilities Discovered[/]",
        show_header=True,
        header_style="bold white on red",
        border_style="red",
    )
    
    table.add_column("Severity", width=10)
    table.add_column("Name", width=35)
    table.add_column("CVSS", width=8)
    table.add_column("CVE", width=15)
    
    severity_styles = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "cyan",
        "info": "dim",
    }
    
    for vuln in vulnerabilities[:15]:  # Top 15
        sev = vuln.get("severity", "info").lower()
        style = severity_styles.get(sev, "dim")
        
        cvss = vuln.get("cvss_score") or vuln.get("cvss_base", "N/A")
        cve = vuln.get("cve_id") or vuln.get("cve", "N/A")
        
        table.add_row(
            Text(sev.upper(), style=style),
            vuln.get("name", "Unknown")[:35],
            str(cvss),
            str(cve)[:15],
        )
    
    console.print(table)

def print_compliance_summary(compliance: Dict[str, Any]) -> None:
    """Print compliance summary"""
    table = Table(
        title="[bold]Compliance Status[/bold]",
        show_header=True,
        header_style="bold white on #1a1a2e",
        border_style="yellow",
    )
    
    table.add_column("Framework", style="bold", width=15)
    table.add_column("Status", width=20)
    table.add_column("Passed", width=10)
    table.add_column("Failed", width=10)
    table.add_column("Score", width=10)
    
    for framework, data in compliance.items():
        passed = data.get("passed", 0)
        failed = data.get("failed", 0)
        pct = data.get("compliance_percentage", 0)
        
        if pct >= 90:
            status = "[green]COMPLIANT[/green]"
        elif pct >= 70:
            status = "[yellow]PARTIAL[/yellow]"
        else:
            status = "[red]NON-COMPLIANT[/red]"
        
        table.add_row(
            framework,
            status,
            f"[green]{passed}[/green]",
            f"[red]{failed}[/red]",
            f"{pct:.1f}%"
        )
    
    console.print(table)

def print_tools_status(tools: Dict[str, bool]) -> None:
    """Print tools availability status"""
    table = Table(
        title="[bold]Security Tools Status[/bold]",
        show_header=True,
        header_style="bold white on #1a1a2e",
        border_style="cyan",
    )
    
    table.add_column("Tool", style="cyan", width=20)
    table.add_column("Status", width=15)
    table.add_column("Description", width=40)
    
    tool_descriptions = {
        "nmap": "Network discovery and port scanning",
        "nuclei": "Fast vulnerability scanner",
        "sqlmap": "SQL injection detection & exploitation",
        "ffuf": "Web fuzzing and discovery",
        "katana": "Web crawling and endpoint discovery",
        "whatweb": "Technology fingerprinting",
        "subfinder": "Subdomain enumeration",
        "nikto": "Web server vulnerability scanning",
        "gobuster": "Directory brute-forcing",
        "httpx": "HTTP probing and analysis",
        "hydra": "Credential brute-forcing",
        "commix": "Command injection exploitation",
    }
    
    for tool, available in sorted(tools.items()):
        status = "[green]✓ Available[/green]" if available else "[red]✗ Missing[/red]"
        desc = tool_descriptions.get(tool, "Security tool")
        table.add_row(tool, status, desc)
    
    console.print(table)

def print_report_generated(paths: Dict[str, str]) -> None:
    """Print report generation success"""
    console.print("\n[bold green]═══════════════════════════════════════════════════════════════[/bold green]")
    console.print("[bold green]  ✓ REPORTS GENERATED SUCCESSFULLY[/bold green]")
    console.print("[bold green]═══════════════════════════════════════════════════════════════[/bold green]\n")
    
    for format_name, path in paths.items():
        console.print(f"  [cyan]{format_name.upper():10}[/cyan] → [white]{path}[/white]")
    
    console.print()
