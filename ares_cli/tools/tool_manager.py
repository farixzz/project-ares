# backend/tools/tool_manager.py
import nmap
import subprocess
import shutil

class ReconTools:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except:
            self.nm = None

    def run_nmap(self, target: str):
        print(f"[*] TOOL: Nmap on {target}")
        if not self.nm: return {"error": "Nmap missing"}
        try:
            self.nm.scan(hosts=target, arguments='-sV -T4 --top-ports 1000')
            scan_data = []
            for host in self.nm.all_hosts():
                host_info = {"ip": host, "ports": []}
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            host_info["ports"].append({
                                "port": port,
                                "service": self.nm[host]['tcp'][port]['name']
                            })
                scan_data.append(host_info)
            return scan_data
        except Exception as e:
            return {"error": str(e)}

    def run_gobuster(self, target: str):
        print(f"[*] TOOL: Gobuster on {target}")
        url = f"http://{target}"
        try:
            cmd = ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "-z", "--no-error", "--timeout", "10s"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return {"directories": res.stdout.splitlines()[:15]}
        except:
            return {"directories": []}

    def run_nikto(self, target: str):
        print(f"[*] TOOL: Nikto on {target}")
        if not shutil.which("nikto"): return "Nikto missing"
        try:
            cmd = ["nikto", "-h", target, "-Tuning", "1", "-maxtime", "60s"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.stdout[:1000]
        except:
            return "Nikto Error"

    def run_sqlmap(self, url: str, stealth: bool = False):
        mode = "STEALTH" if stealth else "STANDARD"
        print(f"[*] TOOL: SQLMap ({mode}) on {url}")
        
        if not shutil.which("sqlmap"): return "SQLMap missing"
        
        try:
            cmd = ["sqlmap", "-u", url, "--batch", "--dbs", "--level", "1", "--timeout", "10"]
            
            # --- STEALTH LOGIC ---
            if stealth:
                # Add evasion techniques (WAF Bypass)
                # --tamper: obfuscates payloads to bypass firewalls
                # --random-agent: spoofs User-Agent header
                cmd.extend(["--tamper=space2comment", "--random-agent", "--delay=1"])
            
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.stdout[-1500:] # Capture more log data
            
        except:
            return "SQLMap Error"