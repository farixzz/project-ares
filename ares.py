#!/usr/bin/env python3
# ares.py
"""
ARES CLI - Autonomous Recon & Exploitation System
Production-ready penetration testing command-line interface

Usage:
    python ares.py scan --target example.com --profile standard
    python ares.py report --input results.json --format pdf
    python ares.py tools --check
    python ares.py config --show
"""
import os
import sys
import click
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Dependency Check
try:
    import nmap  # noqa: F401
    import reportlab  # noqa: F401
    import requests  # noqa: F401
    import rich  # noqa: F401
    import jinja2  # noqa: F401
except ImportError as e:
    print(f"\n[!] CRITICAL ERROR: Missing dependencies ({e})")
    print("[-] Please ensure you have activated the virtual environment:")
    print("    source venv/bin/activate")
    print("[-] Or install requirements:")
    print("    pip install -r requirements.txt")
    sys.exit(1)

from ares_cli import __version__
from ares_cli.config import AresConfig, get_available_profiles, SCAN_PROFILES
from ares_cli.display import (
    console, print_banner, print_success, print_error, print_warning,
    print_info, print_scan_summary, print_vulnerability_table,
    print_tools_status, print_report_generated
)
from ares_cli.scanner import AutonomousScanner, get_tools_status
from ares_cli.reporter import ReportGenerator

# Click context settings
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version=__version__, prog_name="ARES")
@click.option('--config', '-c', type=click.Path(), help='Path to config file')
@click.option('--quiet', '-q', is_flag=True, help='Suppress banner and verbose output')
@click.pass_context
def cli(ctx, config, quiet):
    """
    🛡️ ARES - Autonomous Recon & Exploitation System

    AI-powered penetration testing framework for security professionals.
    Orchestrates Nmap, Nuclei, Nikto, SQLMap, and more into a single autonomous workflow.

    \b
    Quick Start:
        python3 ares.py tools --check              Check tool availability
        python3 ares.py scan -t TARGET -p quick     Fast recon scan
        python3 ares.py scan -t TARGET -p standard  Full vulnerability scan
        python3 ares.py view --latest               Open latest HTML report

    \b
    Scan Profiles:
        quick      Fast recon (~5 min)  — ports + fingerprinting
        standard   Full scan (~30 min)  — recon + vuln scanning
        deep       Pentest (2+ hrs)     — everything + exploitation
        stealth    Evasive (~1 hr)      — slow timing, WAF bypass

    \b
    Run 'python3 ares.py help' for a comprehensive interactive guide.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = AresConfig.load(config)
    ctx.obj['quiet'] = quiet
    
    if not quiet:
        print_banner()

# =============================================
# SCAN COMMAND
# =============================================

@cli.command(short_help='Run autonomous security scan on a target')
@click.option('--target', '-t', required=True, help='Target IP, hostname, URL, or file with targets')
@click.option('--profile', '-p', default='standard', 
              type=click.Choice(['quick', 'standard', 'deep', 'stealth']),
              help='Scan profile (default: standard)')
@click.option('--output', '-o', default='./ares_results', help='Output directory')
@click.option('--format', '-f', default='pdf,html,json', help='Report formats (comma-separated)')
@click.option('--dry-run', is_flag=True, help='Show what would be done without scanning')
@click.option('--no-report', is_flag=True, help='Skip report generation')
@click.pass_context
def scan(ctx, target, profile, output, format, dry_run, no_report):
    """
    🎯 Execute autonomous penetration test
    
    Supports single target or batch scanning from file.
    
    \b
    Profiles:
        quick    - Fast assessment (5 min) - Top 100 ports, basic fingerprinting
        standard - Full scan (30 min) - All passive reconnaissance  
        deep     - Comprehensive (2+ hrs) - All ports, full vuln assessment
        stealth  - Evasive (1 hr) - Low and slow with WAF bypass
    
    \b
    Examples:
        ares scan -t scanme.nmap.org -p quick
        ares scan -t targets.txt -p standard
        ares scan -t "target1.com,target2.com" -p quick
    """
    config = ctx.obj['config']
    
    # Parse targets
    targets = []
    if os.path.isfile(target):
        with open(target, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    elif ',' in target:
        targets = [t.strip() for t in target.split(',')]
    else:
        targets = [target]
        
    if not targets:
        print_error("No valid targets found")
        sys.exit(1)
        
    console.print(f"\n[bold cyan]Batch Scan:[/bold cyan] {len(targets)} targets")
    console.print(f"[bold cyan]Profile:[/bold cyan] {profile}")
    console.print()
    
    # Legal disclaimer
    if not dry_run:
        console.print("[yellow]⚠️  LEGAL NOTICE: Only scan systems you have permission to test.[/yellow]")
        console.print()
    
    scanner = AutonomousScanner(config)
    
    for i, current_target in enumerate(targets, 1):
        console.print(f"\n[bold magenta]════════════════════════════════════════════════════════════[/bold magenta]")
        console.print(f"[bold magenta] Target {i}/{len(targets)}: {current_target}[/bold magenta]")
        console.print(f"[bold magenta]════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        try:
            # Create target-specific output dir
            target_slug = current_target.replace('http://', '').replace('https://', '').split('/')[0]
            target_output = os.path.join(output, target_slug)
            
            result = scanner.scan(current_target, profile, dry_run=dry_run)
            
            if dry_run:
                continue
            
            # Print summary
            console.print()
            print_scan_summary(result.to_dict())
            
            # Print vulnerabilities
            if result.vulnerabilities:
                console.print()
                print_vulnerability_table(result.vulnerabilities)
            
            # Generate reports
            if not no_report:
                console.print()
                print_info("Generating reports...")
                
                formats_list = [f.strip() for f in format.split(',')]
                reporter = ReportGenerator(config)
                paths = reporter.generate(result.to_dict(), target_output, formats_list)
                
                console.print()
                print_report_generated(paths)
            
            # Final status for this target
            console.print()
            if result.severity_score >= 7.0:
                console.print(f"[bold red]⚠️  {result.severity_level} RISK - Immediate action required![/]")
            elif result.severity_score >= 4.0:
                console.print(f"[bold yellow]⚠️  {result.severity_level} RISK - Review recommended[/]")
            else:
                console.print(f"[bold green]✓ {result.severity_level} RISK - Acceptable security posture[/]")
                
        except KeyboardInterrupt:
            print_warning("\nBatch scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            print_error(f"Scan failed for {current_target}: {e}")
            if ctx.obj.get('debug'):
                raise
            continue
            
    print_success(f"\nBatch scan complete. Processed {len(targets)} targets.")

# =============================================
# REPORT COMMAND
# =============================================

@cli.command(short_help='Generate reports from existing scan JSON data')
@click.option('--input', '-i', 'input_file', required=True, help='Input JSON file or directory')
@click.option('--output', '-o', default='./ares_reports', help='Output directory')
@click.option('--format', '-f', default='pdf,html,json', help='Report formats')
@click.pass_context
def report(ctx, input_file, output, format):
    """
    📄 Generate reports from existing scan data
    
    \b
    Examples:
        ares report -i scan_results.json -f pdf
        ares report -i ./scans/ -o ./reports -f html,pdf
    """
    import json
    
    config = ctx.obj['config']
    formats_list = [f.strip() for f in format.split(',')]
    
    # Load scan data
    if not Path(input_file).exists():
        print_error(f"Input file not found: {input_file}")
        sys.exit(1)
    
    try:
        with open(input_file, 'r') as f:
            scan_data = json.load(f)
        
        # Handle ARES format vs raw format
        if 'findings' in scan_data:
            # ARES JSON format
            results = {
                'target': scan_data['meta']['target'],
                'profile': scan_data['meta']['profile'],
                'duration': scan_data['meta']['duration'],
                'vulnerabilities': scan_data['findings'].get('vulnerabilities', []),
                'open_ports': scan_data['findings'].get('open_ports', []),
                'technologies': scan_data['findings'].get('technologies', []),
                'subdomains': scan_data['findings'].get('subdomains', []),
                'endpoints': [],
                'severity_score': scan_data['summary'].get('severity_score', 0),
                'severity_level': scan_data['summary'].get('severity_level', 'LOW'),
                'tools_used': scan_data.get('audit', {}).get('tools_used', []),
                'messages': [],
                'waf_detected': scan_data.get('audit', {}).get('waf_detected', False),
            }
        else:
            results = scan_data
        
        reporter = ReportGenerator(config)
        paths = reporter.generate(results, output, formats_list)
        
        print_report_generated(paths)
        
    except json.JSONDecodeError:
        print_error("Invalid JSON file")
        sys.exit(1)
    except Exception as e:
        print_error(f"Report generation failed: {e}")
        sys.exit(1)

# =============================================
# TOOLS COMMAND
# =============================================

@cli.command(short_help='Check or install required security tools')
@click.option('--check', is_flag=True, help='Check all tools availability')
@click.option('--install', is_flag=True, help='Show installation instructions')
@click.pass_context
def tools(ctx, check, install):
    """
    🔧 Manage and check security tools
    
    \b
    Examples:
        ares tools --check
        ares tools --install
    """
    if check or (not check and not install):
        console.print("\n[bold]Checking security tools...[/bold]\n")
        status = get_tools_status()
        print_tools_status(status)
        
        available = sum(1 for v in status.values() if v)
        total = len(status)
        console.print(f"\n[bold]Available: {available}/{total} tools[/bold]")
        
        if available < total:
            print_warning("Some tools are missing. Run 'ares tools --install' for instructions.")
    
    if install:
        console.print("\n[bold]Installation Instructions[/bold]\n")
        
        instructions = {
            "nmap": "sudo apt install nmap",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "whatweb": "sudo apt install whatweb",
            "sqlmap": "sudo apt install sqlmap",
            "nikto": "sudo apt install nikto",
            "gobuster": "go install github.com/OJ/gobuster/v3@latest",
            "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        }
        
        for tool, cmd in instructions.items():
            console.print(f"  [cyan]{tool:15}[/cyan] → [dim]{cmd}[/dim]")

# =============================================
# CONFIG COMMAND
# =============================================

@cli.command(short_help='View or initialize ARES configuration')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--init', is_flag=True, help='Create default config file')
@click.option('--profile', '-p', help='Show profile details')
@click.pass_context
def config(ctx, show, init, profile):
    """
    ⚙️  Manage ARES configuration
    
    \b
    Examples:
        ares config --show
        ares config --init
        ares config -p standard
    """
    cfg = ctx.obj['config']
    
    if show:
        console.print("\n[bold]Current Configuration[/bold]\n")
        for key, value in cfg.to_dict().items():
            console.print(f"  [cyan]{key:25}[/cyan] = {value}")
    
    if init:
        config_path = Path.home() / ".config" / "ares" / "config.yaml"
        cfg.save(str(config_path))
        print_success(f"Configuration saved to: {config_path}")
    
    if profile:
        if profile in SCAN_PROFILES:
            p = SCAN_PROFILES[profile]
            console.print(f"\n[bold]Profile: {p.name}[/bold]")
            console.print(f"Description: {p.description}")
            console.print(f"Timeout: {p.timeout_minutes} minutes")
            console.print(f"Nmap args: {p.nmap_args}")
            console.print()
            console.print("[bold]Features:[/bold]")
            console.print(f"  Subdomain enum: {'✓' if p.enable_subdomain else '✗'}")
            console.print(f"  Fingerprinting: {'✓' if p.enable_fingerprint else '✗'}")
            console.print(f"  Web crawling:   {'✓' if p.enable_crawl else '✗'}")
            console.print(f"  Web fuzzing:    {'✓' if p.enable_fuzzing else '✗'}")
            console.print(f"  Nuclei scan:    {'✓' if p.enable_nuclei else '✗'}")
            console.print(f"  Exploitation:   {'✓' if p.enable_exploitation else '✗'}")
            console.print(f"  Stealth mode:   {'✓' if p.stealth_mode else '✗'}")
        else:
            print_error(f"Unknown profile: {profile}")
            console.print(f"Available: {', '.join(get_available_profiles())}")

# =============================================
# STATUS COMMAND  
# =============================================

@cli.command(short_help='Show ARES system status, tools, and AI engine')
@click.pass_context
def status(ctx):
    """
    📊 Show ARES system status
    """
    from datetime import datetime
    
    console.print("\n[bold]ARES System Status[/bold]\n")
    console.print(f"  Version:    {__version__}")
    console.print(f"  Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"  Python:     {sys.version.split()[0]}")
    console.print(f"  Platform:   {sys.platform}")
    
    # Check Ollama
    console.print("\n[bold]AI Engine:[/bold]")
    try:
        import requests
        cfg = ctx.obj['config']
        resp = requests.get(f"{cfg.ollama_host}/api/tags", timeout=3)
        if resp.ok:
            models = resp.json().get("models", [])
            console.print(f"  [green]✓ Ollama available[/green] ({len(models)} models)")
        else:
            console.print("  [yellow]⚠ Ollama not responding[/yellow]")
    except:
        console.print("  [red]✗ Ollama not available[/red]")
    
    # Tools summary
    tools_status = get_tools_status()
    available = sum(1 for v in tools_status.values() if v)
    console.print(f"\n[bold]Security Tools:[/bold] {available}/{len(tools_status)} available")

# =============================================
# SERVE COMMAND
# =============================================

@cli.command(short_help='Serve scan reports over HTTP for remote access')
@click.option('--port', '-p', default=8888, help='Port to serve on')
@click.option('--bind', '-b', default='127.0.0.1', help='Bind address')
@click.option('--directory', '-d', default='./ares_results', help='Directory to serve')
def serve(port, bind, directory):
    """
    🌐 Serve scan results via HTTP
    
    Useful for accessing reports remotely or downloading files.
    """
    import http.server
    import socketserver
    
    if not os.path.exists(directory):
        print_error(f"Directory not found: {directory}")
        return
    
    os.chdir(directory)
    
    Handler = http.server.SimpleHTTPRequestHandler
    
    try:
        with socketserver.TCPServer((bind, port), Handler) as httpd:
            console.print(f"\n[bold green]✓ Serving {directory} at http://{bind}:{port}[/bold green]")
            console.print("[dim]Press Ctrl+C to stop[/dim]\n")
            httpd.serve_forever()
    except OSError as e:
        print_error(f"Failed to start server: {e}")
    except KeyboardInterrupt:
        print_warning("\nServer stopped")

# =============================================
# VIEW COMMAND
# =============================================

@cli.command(short_help='Open latest scan report in your browser')
@click.option('--target', '-t', help='Target name to open report for')
@click.option('--latest', '-l', is_flag=True, help='Open latest report')
def view(target, latest):
    """
    👀 View generated reports
    
    Opens the report in your default browser/viewer.
    """
    import glob
    
    base_dir = "./ares_results"
    
    if latest:
        # Find latest HTML file recursively
        files = glob.glob(f"{base_dir}/**/*.html", recursive=True)
        if not files:
            print_error("No reports found")
            return
        report_path = max(files, key=os.path.getctime)
    
    elif target:
        # Try to find target directory
        slug = target.replace('http://', '').replace('https://', '').split('/')[0]
        target_dir = os.path.join(base_dir, slug)
        
        if not os.path.exists(target_dir):
            print_error(f"No results found for {target}")
            return
            
        # Find HTML report in target dir
        files = glob.glob(f"{target_dir}/*.html")
        if not files:
            print_error(f"No HTML report found for {target}")
            return
        report_path = max(files, key=os.path.getctime)
    
    else:
        console.print("[yellow]Please specify --target or --latest[/yellow]")
        return
    
    console.print(f"[*] Opening {report_path}...")
    
    # Cross-platform open
    if sys.platform == 'darwin':
        subprocess.run(['open', report_path])
    elif sys.platform == 'win32':
        os.startfile(report_path)
    else:
        # Linux
        try:
            subprocess.run(['xdg-open', report_path], stderr=subprocess.DEVNULL)
        except:
             print_warning("Could not open automatically. Copy this link:")
             print_info(f"file://{os.path.abspath(report_path)}")

# =============================================
# GUIDE COMMAND (Comprehensive Help)
# =============================================

@cli.command(name="help", short_help='Show comprehensive interactive usage guide')
@click.option('--topic', '-t', type=click.Choice(['scan', 'profiles', 'reports', 'tools', 'examples', 'all']),
              default='all', help='Specific help topic')
def help_cmd(topic):
    """📖 Show comprehensive usage guide with examples"""
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    sections = {}

    # --- QUICK START ---
    sections['quick'] = Panel(
        "[bold white]Getting Started:[/]\n"
        "  [cyan]1.[/] Check tools:  [green]python ares.py tools --check[/]\n"
        "  [cyan]2.[/] Quick scan:   [green]python ares.py scan -t TARGET -p quick[/]\n"
        "  [cyan]3.[/] Full scan:    [green]python ares.py scan -t TARGET -p standard[/]\n"
        "  [cyan]4.[/] View report:  [green]python ares.py view --latest[/]\n"
        "  [cyan]5.[/] Serve report: [green]python ares.py serve --port 8888[/]",
        title="[bold #00ff41]⚡ Quick Start[/]",
        border_style="#00ff41",
        padding=(1, 2),
    )

    # --- COMMANDS TABLE ---
    cmd_table = Table(box=box.ROUNDED, border_style="cyan", title="[bold]Available Commands", show_lines=True)
    cmd_table.add_column("Command", style="bold green", width=22)
    cmd_table.add_column("Description", style="white")
    cmd_table.add_column("Key Options", style="dim cyan")

    cmd_table.add_row(
        "scan", "Run a security scan on a target",
        "-t TARGET  -p PROFILE  --dry-run  --output-dir DIR"
    )
    cmd_table.add_row(
        "tools", "Check/install security tools",
        "--check  --install"
    )
    cmd_table.add_row(
        "config", "Manage configuration",
        "--show  --init  -p PROFILE"
    )
    cmd_table.add_row(
        "view", "Open latest report in browser",
        "--latest  --format FORMAT"
    )
    cmd_table.add_row(
        "serve", "Start HTTP server for reports",
        "--port PORT  --bind ADDR"
    )
    cmd_table.add_row(
        "report", "Generate report from JSON data",
        "--input FILE  --format FMT"
    )
    cmd_table.add_row(
        "guide", "Show this help guide",
        "--topic TOPIC"
    )
    sections['commands'] = cmd_table

    # --- PROFILES TABLE ---
    prof_table = Table(box=box.ROUNDED, border_style="yellow", title="[bold]Scan Profiles", show_lines=True)
    prof_table.add_column("Profile", style="bold yellow", width=12)
    prof_table.add_column("Duration", style="white", width=10)
    prof_table.add_column("What It Does", style="white")
    prof_table.add_column("Tools Used", style="dim")

    prof_table.add_row(
        "[green]quick[/]", "~5 min",
        "Fast recon: top 100 ports + tech fingerprint",
        "nmap, whatweb"
    )
    prof_table.add_row(
        "[cyan]standard[/]", "~30 min",
        "Full recon + vuln scan: ports, subdomains, crawl, fuzz, nuclei",
        "nmap, subfinder, whatweb, katana, ffuf, nuclei, nikto"
    )
    prof_table.add_row(
        "[red]deep[/]", "2+ hrs",
        "Full pentest: everything + exploitation (SQLi, CMDi, brute-force)",
        "All tools + sqlmap, commix, hydra"
    )
    prof_table.add_row(
        "[#8B8000]stealth[/]", "~1 hr",
        "Evasive scan: slow timing, rate-limited, WAF bypass",
        "nmap (slow), subfinder, katana, nuclei (quiet)"
    )
    sections['profiles'] = prof_table

    # --- SCAN EXAMPLES ---
    sections['scan'] = Panel(
        "[bold white]Basic Scan:[/]\n"
        "  [green]python ares.py scan -t example.com -p standard[/]\n\n"
        "[bold white]Quick Recon (dry run):[/]\n"
        "  [green]python ares.py scan -t example.com -p quick --dry-run[/]\n\n"
        "[bold white]Full Pentest:[/]\n"
        "  [green]python ares.py scan -t target.com -p deep[/]\n\n"
        "[bold white]Stealth Mode:[/]\n"
        "  [green]python ares.py scan -t target.com -p stealth[/]\n\n"
        "[bold white]Custom Output Directory:[/]\n"
        "  [green]python ares.py scan -t target.com -p standard -o ./my-reports[/]\n\n"
        "[bold white]Batch Scan (file):[/]\n"
        "  [green]python ares.py scan -t targets.txt -p quick[/]\n\n"
        "[bold white]Batch Scan (comma-separated):[/]\n"
        "  [green]python ares.py scan -t \"site1.com,site2.com\" -p standard[/]",
        title="[bold cyan]🔍 Scan Examples[/]",
        border_style="cyan",
        padding=(1, 2),
    )

    # --- REPORT EXAMPLES ---
    sections['reports'] = Panel(
        "[bold white]View Latest Report:[/]\n"
        "  [green]python ares.py view --latest[/]\n\n"
        "[bold white]Serve Reports Over Network:[/]\n"
        "  [green]python ares.py serve --port 8888[/]\n"
        "  [dim]→ Open http://YOUR_IP:8888 from any device[/]\n\n"
        "[bold white]Open Reports Directly (Terminal):[/]\n"
        "  [green]xdg-open ./ares_results/TARGET/ares_report_*.html[/]   [dim]# HTML in browser[/]\n"
        "  [green]xdg-open ./ares_results/TARGET/ares_report_*.pdf[/]    [dim]# PDF in viewer[/]\n"
        "  [green]cat ./ares_results/TARGET/ares_report_*.json | python3 -m json.tool[/]  [dim]# JSON pretty print[/]\n"
        "  [green]python ares.py view --latest --format html[/]           [dim]# Auto-open latest HTML[/]\n"
        "  [green]python ares.py view --latest --format pdf[/]            [dim]# Auto-open latest PDF[/]\n\n"
        "[bold white]Report Formats Generated:[/]\n"
        "  [cyan]• JSON[/]  → Machine-readable, best for automation\n"
        "  [cyan]• PDF[/]   → Professional printable report\n"
        "  [cyan]• HTML[/]  → Interactive web report with charts\n\n"
        "[bold white]Report Contents:[/]\n"
        "  [dim]• Executive summary (AI-generated)\n"
        "  • CVSS 3.1 scores per vulnerability\n"
        "  • Quick Wins (low effort, high impact)\n"
        "  • Remediation Roadmap (prioritized timeline)\n"
        "  • MITRE ATT&CK mapping\n"
        "  • Compliance checks (PCI-DSS, HIPAA)[/]",
        title="[bold #e94560]📄 Reports[/]",
        border_style="#e94560",
        padding=(1, 2),
    )

    # --- TOOLS EXAMPLES ---
    sections['tools'] = Panel(
        "[bold white]Check Installed Tools:[/]\n"
        "  [green]python ares.py tools --check[/]\n\n"
        "[bold white]Install Missing Tools:[/]\n"
        "  [green]python ares.py tools --install[/]\n\n"
        "[bold white]Required Tools:[/]\n"
        "  [cyan]nmap[/]      - Port scanning & service detection\n"
        "  [cyan]nuclei[/]    - Vulnerability scanning\n"
        "  [cyan]subfinder[/] - Subdomain enumeration\n"
        "  [cyan]whatweb[/]   - Technology fingerprinting\n"
        "  [cyan]katana[/]    - Web crawling\n"
        "  [cyan]ffuf[/]      - Directory fuzzing\n"
        "  [cyan]nikto[/]     - Web server scanning\n"
        "  [cyan]sqlmap[/]    - SQL injection (deep profile)\n"
        "  [cyan]commix[/]    - Command injection (deep profile)\n"
        "  [cyan]hydra[/]     - Credential brute-force (deep profile)",
        title="[bold yellow]🔧 Tools[/]",
        border_style="yellow",
        padding=(1, 2),
    )

    # --- EXAMPLES ---
    sections['examples'] = Panel(
        "[bold white]Typical Workflow:[/]\n"
        "  [green]# 1. Check your tools are ready[/]\n"
        "  [white]python ares.py tools --check[/]\n\n"
        "  [green]# 2. Quick recon to scope the target[/]\n"
        "  [white]python ares.py scan -t target.com -p quick[/]\n\n"
        "  [green]# 3. Full assessment[/]\n"
        "  [white]python ares.py scan -t target.com -p standard[/]\n\n"
        "  [green]# 4. View the report[/]\n"
        "  [white]python ares.py view --latest[/]\n\n"
        "  [green]# 5. Share via network[/]\n"
        "  [white]python ares.py serve --port 8888[/]\n\n"
        "[bold white]Getting Help for Any Command:[/]\n"
        "  [green]python ares.py scan --help[/]\n"
        "  [green]python ares.py config --help[/]\n"
        "  [green]python ares.py --version[/]",
        title="[bold #00ff41]💡 Workflow & Tips[/]",
        border_style="#00ff41",
        padding=(1, 2),
    )

    # --- RENDER ---
    console.print()

    if topic == 'all':
        console.print(sections['quick'])
        console.print()
        console.print(sections['commands'])
        console.print()
        console.print(sections['profiles'])
        console.print()
        console.print(sections['scan'])
        console.print()
        console.print(sections['reports'])
        console.print()
        console.print(sections['tools'])
        console.print()
        console.print(sections['examples'])
    elif topic == 'scan':
        console.print(sections['scan'])
        console.print()
        console.print(sections['profiles'])
    elif topic == 'profiles':
        console.print(sections['profiles'])
    elif topic == 'reports':
        console.print(sections['reports'])
    elif topic == 'tools':
        console.print(sections['tools'])
    elif topic == 'examples':
        console.print(sections['examples'])

    console.print()
    console.print("[dim]Developed by [bold #00ff41]farixzz[/] — github.com/farixzz[/]")
    console.print()

def main():
    """Main entry point"""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]", markup=False)
        sys.exit(1)

if __name__ == '__main__':
    main()
