# ares_cli/remediation_db.py
"""
Remediation Database for ARES
Actionable guidance for penetration testers and developers
"""
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class Remediation:
    """Remediation guidance for a vulnerability"""
    title: str
    description: str
    fix_steps: List[str]
    commands: List[str]  # Specific commands where applicable
    effort: str  # Low, Medium, High
    priority: str  # Critical, High, Medium, Low
    references: List[str]
    cwe_id: str
    owasp_category: str
    
    def to_dict(self) -> Dict:
        return {
            "title": self.title,
            "description": self.description,
            "fix_steps": self.fix_steps,
            "commands": self.commands,
            "effort": self.effort,
            "priority": self.priority,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


# Comprehensive remediation database
REMEDIATION_DB: Dict[str, Remediation] = {
    "sql-injection": Remediation(
        title="SQL Injection",
        description="Application is vulnerable to SQL injection, allowing attackers to manipulate database queries.",
        fix_steps=[
            "Use parameterized queries (prepared statements) for ALL database operations",
            "Implement input validation with whitelist approach",
            "Apply principle of least privilege to database accounts",
            "Enable WAF rules for SQL injection patterns",
            "Conduct code review focusing on database interaction points",
        ],
        commands=[
            "# Python (SQLAlchemy): cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "# PHP (PDO): $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');",
            "# Node.js: db.query('SELECT * FROM users WHERE id = $1', [userId])",
            "# Install ModSecurity: sudo apt install libapache2-mod-security2",
        ],
        effort="Medium",
        priority="Critical",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
        ],
        cwe_id="CWE-89",
        owasp_category="A03:2021 - Injection",
    ),
    
    "xss": Remediation(
        title="Cross-Site Scripting (XSS)",
        description="Application reflects or stores user input without proper encoding, enabling script injection.",
        fix_steps=[
            "Encode all output based on context (HTML, JavaScript, URL, CSS)",
            "Implement Content-Security-Policy (CSP) headers",
            "Use modern frameworks with automatic escaping (React, Vue, Angular)",
            "Validate and sanitize input on server-side",
            "Set HttpOnly and Secure flags on session cookies",
        ],
        commands=[
            "# Add CSP header (Apache): Header set Content-Security-Policy \"default-src 'self'\"",
            "# Add CSP header (Nginx): add_header Content-Security-Policy \"default-src 'self'\";",
            "# Python (Jinja2 auto-escaping): {% autoescape true %}",
            "# PHP: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
        ],
        effort="Medium",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://content-security-policy.com/",
        ],
        cwe_id="CWE-79",
        owasp_category="A03:2021 - Injection",
    ),
    
    "rce": Remediation(
        title="Remote Code Execution (RCE)",
        description="Critical vulnerability allowing attackers to execute arbitrary code on the server.",
        fix_steps=[
            "IMMEDIATE: Isolate affected system from network",
            "Patch vulnerable software immediately",
            "Never pass user input to system commands",
            "Use sandboxing and containerization",
            "Implement strict input validation",
            "Enable SELinux/AppArmor mandatory access controls",
        ],
        commands=[
            "# Isolate: sudo iptables -A INPUT -s 0.0.0.0/0 -j DROP; iptables -A INPUT -s YOUR_IP -j ACCEPT",
            "# Update packages: sudo apt update && sudo apt upgrade -y",
            "# Check for processes: ps aux | grep suspicious",
            "# Enable AppArmor: sudo systemctl enable apparmor && sudo systemctl start apparmor",
        ],
        effort="High",
        priority="Critical",
        references=[
            "https://owasp.org/www-community/attacks/Code_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        cwe_id="CWE-94",
        owasp_category="A03:2021 - Injection",
    ),
    
    "command-injection": Remediation(
        title="OS Command Injection",
        description="Application passes unsanitized input to system shell commands.",
        fix_steps=[
            "Replace shell commands with language-native libraries",
            "If shell commands necessary, use strict whitelisting",
            "Never concatenate user input into commands",
            "Use subprocess with shell=False (Python)",
            "Implement least privilege for application accounts",
        ],
        commands=[
            "# Python WRONG: os.system('ping ' + user_input)",
            "# Python RIGHT: subprocess.run(['ping', '-c', '1', validated_ip], shell=False)",
            "# PHP: Use escapeshellarg() and escapeshellcmd()",
            "# Restrict shell: sudo usermod -s /usr/sbin/nologin www-data",
        ],
        effort="Medium",
        priority="Critical",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
    ),
    
    "path-traversal": Remediation(
        title="Path Traversal / LFI",
        description="Application allows reading files outside intended directory via ../ sequences.",
        fix_steps=[
            "Use realpath() to resolve and validate paths",
            "Implement allowlist of permitted files/directories",
            "Chroot or jail the application",
            "Remove ../ and encoded variants from input",
            "Use framework file serving functions",
        ],
        commands=[
            "# Python: os.path.realpath(user_path).startswith(SAFE_DIR)",
            "# PHP: realpath($file) && strpos(realpath($file), $base_dir) === 0",
            "# Nginx: location /files { alias /safe/dir/; }",
            "# Apache: <Directory /> Options -Indexes -FollowSymLinks </Directory>",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
        cwe_id="CWE-22",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    
    "ssrf": Remediation(
        title="Server-Side Request Forgery (SSRF)",
        description="Application can be tricked into making requests to internal resources.",
        fix_steps=[
            "Validate and allowlist destination URLs/IPs",
            "Block requests to internal IP ranges (10.x, 192.168.x, 127.x)",
            "Disable unnecessary URL schemes (file://, gopher://)",
            "Use network segmentation",
            "Implement request timeouts and size limits",
        ],
        commands=[
            "# Block internal IPs (iptables): iptables -A OUTPUT -d 10.0.0.0/8 -j DROP",
            "# Python: ipaddress.ip_address(host).is_private  # Check before request",
            "# Nginx: deny 10.0.0.0/8; deny 192.168.0.0/16; deny 127.0.0.0/8;",
        ],
        effort="Medium",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-918",
        owasp_category="A10:2021 - SSRF",
    ),
    
    "weak-credentials": Remediation(
        title="Weak/Default Credentials",
        description="System uses easily guessable or default passwords.",
        fix_steps=[
            "Change ALL default passwords immediately",
            "Implement password complexity requirements (12+ chars, mixed)",
            "Enable multi-factor authentication (MFA)",
            "Implement account lockout after failed attempts",
            "Use password manager or secrets vault",
        ],
        commands=[
            "# Change password: passwd username",
            "# Set password policy (PAM): sudo vim /etc/pam.d/common-password",
            "# Install fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban",
            "# Check for default creds: grep -r 'admin:admin' /etc/",
        ],
        effort="Low",
        priority="Critical",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
        cwe_id="CWE-521",
        owasp_category="A07:2021 - Identification and Authentication Failures",
    ),
    
    "info-disclosure": Remediation(
        title="Information Disclosure",
        description="Application leaks sensitive information (stack traces, versions, internal paths).",
        fix_steps=[
            "Disable debug mode in production",
            "Configure custom error pages",
            "Remove version headers from server responses",
            "Sanitize error messages shown to users",
            "Review and secure backup files",
        ],
        commands=[
            "# Apache hide version: ServerTokens Prod; ServerSignature Off",
            "# Nginx hide version: server_tokens off;",
            "# PHP: display_errors = Off; log_errors = On",
            "# Django: DEBUG = False",
            "# Remove backup files: find /var/www -name '*.bak' -delete",
        ],
        effort="Low",
        priority="Medium",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
        ],
        cwe_id="CWE-200",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    
    "open-redirect": Remediation(
        title="Open Redirect",
        description="Application redirects to user-controlled URLs without validation.",
        fix_steps=[
            "Validate redirect URLs against allowlist",
            "Use relative URLs for internal redirects",
            "Don't pass redirect targets via user input",
            "If needed, map user input to predefined destinations",
        ],
        commands=[
            "# Python: urlparse(redirect_url).netloc in ALLOWED_DOMAINS",
            "# PHP: if (in_array($redirect, $allowed_urls)) header('Location: '.$redirect);",
        ],
        effort="Low",
        priority="Medium",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
        cwe_id="CWE-601",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    
    "missing-headers": Remediation(
        title="Missing Security Headers",
        description="HTTP security headers not configured, reducing defense-in-depth.",
        fix_steps=[
            "Add Content-Security-Policy header",
            "Add X-Frame-Options: DENY or SAMEORIGIN",
            "Add X-Content-Type-Options: nosniff",
            "Add Strict-Transport-Security (HSTS)",
            "Add Referrer-Policy header",
        ],
        commands=[
            "# Nginx all headers:",
            "add_header X-Frame-Options 'SAMEORIGIN' always;",
            "add_header X-Content-Type-Options 'nosniff' always;",
            "add_header X-XSS-Protection '1; mode=block' always;",
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
            "add_header Content-Security-Policy \"default-src 'self'\" always;",
        ],
        effort="Low",
        priority="Medium",
        references=[
            "https://securityheaders.com/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        ],
        cwe_id="CWE-693",
        owasp_category="A05:2021 - Security Misconfiguration",
    ),
    
    "outdated-software": Remediation(
        title="Outdated Software/Components",
        description="System running software with known vulnerabilities.",
        fix_steps=[
            "Inventory all software and versions",
            "Check versions against CVE databases",
            "Apply security patches immediately",
            "Enable automatic security updates",
            "Subscribe to vendor security advisories",
        ],
        commands=[
            "# Update all packages: sudo apt update && sudo apt upgrade -y",
            "# Check for security updates: sudo apt list --upgradable | grep security",
            "# Enable auto updates: sudo dpkg-reconfigure -plow unattended-upgrades",
            "# Scan for CVEs: sudo nmap --script vulners -sV target",
        ],
        effort="Medium",
        priority="High",
        references=[
            "https://nvd.nist.gov/",
            "https://www.cvedetails.com/",
        ],
        cwe_id="CWE-1104",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
    ),
    
    "php-eol": Remediation(
        title="PHP End-of-Life Version",
        description="Server running an unsupported PHP version with known RCE, type juggling, and memory corruption vulnerabilities.",
        fix_steps=[
            "Upgrade PHP to a supported version (8.2+ recommended)",
            "Test application compatibility with the new PHP version",
            "Update php.ini security settings (disable dangerous functions)",
            "Remove old PHP packages after migration",
        ],
        commands=[
            "# Check current version: php -v",
            "# Install PHP 8.2: sudo apt install php8.2 php8.2-fpm php8.2-cli",
            "# Switch Apache to PHP 8.2: sudo a2dismod php5.6 && sudo a2enmod php8.2",
            "# Switch Nginx (php-fpm): sudo systemctl restart php8.2-fpm",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://www.php.net/supported-versions.php",
            "https://www.php.net/eol.php",
            "https://www.cvedetails.com/product/128/PHP-PHP.html",
        ],
        cwe_id="CWE-1104",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
    ),
    
    "nginx-eol": Remediation(
        title="Nginx Outdated Version",
        description="Server running a legacy Nginx version that may have known HTTP request smuggling or buffer overflow vulnerabilities.",
        fix_steps=[
            "Upgrade Nginx to the latest stable version",
            "Review nginx.conf for deprecated directives",
            "Hide server version: set server_tokens off",
            "Enable automatic security updates for Nginx",
        ],
        commands=[
            "# Check current version: nginx -v",
            "# Update Nginx: sudo apt update && sudo apt install --only-upgrade nginx",
            "# Hide version: echo 'server_tokens off;' | sudo tee /etc/nginx/conf.d/security.conf",
            "# Restart: sudo systemctl restart nginx",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://nginx.org/en/security_advisories.html",
            "https://nginx.org/en/download.html",
        ],
        cwe_id="CWE-1104",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
    ),
    
    "apache-eol": Remediation(
        title="Apache HTTPD Outdated Version",
        description="Server running a legacy Apache HTTPD version with known path traversal and RCE vulnerabilities.",
        fix_steps=[
            "Upgrade Apache to the latest 2.4.x release",
            "Disable unnecessary modules (mod_cgi, mod_status)",
            "Hide server version: set ServerTokens Prod",
            "Enable automatic security updates",
        ],
        commands=[
            "# Check current version: apache2 -v",
            "# Update Apache: sudo apt update && sudo apt install --only-upgrade apache2",
            "# Hide version: echo 'ServerTokens Prod' >> /etc/apache2/conf-enabled/security.conf",
            "# Restart: sudo systemctl restart apache2",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://httpd.apache.org/download.cgi",
        ],
        cwe_id="CWE-1104",
        owasp_category="A06:2021 - Vulnerable and Outdated Components",
    ),
}


def get_remediation(vuln_name: str) -> Optional[Remediation]:
    """
    Get remediation guidance for a vulnerability
    
    Args:
        vuln_name: Vulnerability name or identifier
        
    Returns:
        Remediation object or None
    """
    vuln_lower = vuln_name.lower().replace(" ", "-").replace("_", "-")
    
    # Direct match
    if vuln_lower in REMEDIATION_DB:
        return REMEDIATION_DB[vuln_lower]
    
    # Pattern match
    for key, remediation in REMEDIATION_DB.items():
        if key in vuln_lower or vuln_lower in key:
            return remediation
    
    # Specific software EOL matching (checked first for precise routing)
    eol_patterns = {
        "php": "php-eol",
        "nginx": "nginx-eol",
        "apache": "apache-eol",
    }
    if any(eol_kw in vuln_lower for eol_kw in ["eol", "end-of-life", "outdated", "unsupported"]):
        for sw_name, rem_key in eol_patterns.items():
            if sw_name in vuln_lower:
                return REMEDIATION_DB.get(rem_key)
        # Fallback to generic
        return REMEDIATION_DB.get("outdated-software")
    
    # Keyword match
    keywords = {
        "sql": "sql-injection",
        "sqli": "sql-injection",
        "xss": "xss",
        "script": "xss",
        "rce": "rce",
        "remote code": "rce",
        "remote-code": "rce",
        "code-execution": "rce",
        "command": "command-injection",
        "traversal": "path-traversal",
        "lfi": "path-traversal",
        "ssrf": "ssrf",
        "password": "weak-credentials",
        "credential": "weak-credentials",
        "brute": "weak-credentials",
        "disclosure": "info-disclosure",
        "leak": "info-disclosure",
        "redirect": "open-redirect",
        "header": "missing-headers",
        "outdated": "outdated-software",
        "version": "outdated-software",
        "cve": "outdated-software",
        "eol": "outdated-software",
        "end-of-life": "outdated-software",
    }
    
    for keyword, remediation_key in keywords.items():
        if keyword in vuln_lower:
            return REMEDIATION_DB.get(remediation_key)
    
    return None


def get_quick_wins(vulnerabilities: list) -> List[Dict]:
    """
    Identify quick wins - low effort, high impact fixes
    
    Args:
        vulnerabilities: List of vulnerability dicts
        
    Returns:
        List of quick win recommendations
    """
    quick_wins = []
    
    for vuln in vulnerabilities:
        name = vuln.get("name", "")
        remediation = get_remediation(name)
        
        if remediation and remediation.effort == "Low" and remediation.priority in ["Critical", "High"]:
            quick_wins.append({
                "vulnerability": name,
                "title": remediation.title,
                "fix": remediation.fix_steps[0] if remediation.fix_steps else "",
                "command": remediation.commands[0] if remediation.commands else "",
                "priority": remediation.priority,
            })
    
    return quick_wins


def generate_remediation_roadmap(vulnerabilities: list) -> List[Dict]:
    """
    Generate prioritized remediation roadmap
    
    Args:
        vulnerabilities: List of vulnerability dicts
        
    Returns:
        Ordered list of remediation tasks
    """
    roadmap = []
    seen = set()
    
    # Priority order
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    
    for vuln in vulnerabilities:
        name = vuln.get("name", "")
        remediation = get_remediation(name)
        
        if remediation and remediation.title not in seen:
            seen.add(remediation.title)
            roadmap.append({
                "phase": priority_order.get(remediation.priority, 4),
                "priority": remediation.priority,
                "title": remediation.title,
                "effort": remediation.effort,
                "steps": remediation.fix_steps[:3],
                "cwe": remediation.cwe_id,
                "owasp": remediation.owasp_category,
            })
    
    # Sort by priority
    roadmap.sort(key=lambda x: x["phase"])
    
    # Add phase labels
    phase_labels = {0: "Immediate (24-48hrs)", 1: "Short-term (1 week)", 2: "Medium-term (1 month)", 3: "Long-term"}
    for item in roadmap:
        item["timeline"] = phase_labels.get(item["phase"], "As needed")
    
    return roadmap
