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
    
    "csrf": Remediation(
        title="Cross-Site Request Forgery (CSRF)",
        description="Application does not validate request origin, allowing attackers to forge requests on behalf of authenticated users.",
        fix_steps=[
            "Implement anti-CSRF tokens (synchronizer token pattern)",
            "Use SameSite cookie attribute (Strict or Lax)",
            "Verify Origin and Referer headers on state-changing requests",
            "Use framework-provided CSRF protection (Django, Rails, etc.)",
        ],
        commands=[
            "# Django: {% csrf_token %} in forms, CsrfViewMiddleware enabled",
            "# Express.js: npm install csurf && app.use(csrf())",
            "# Set SameSite cookie: Set-Cookie: session=abc; SameSite=Strict; Secure",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-352",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    
    "cors-misconfiguration": Remediation(
        title="CORS Misconfiguration",
        description="Overly permissive CORS policy allows untrusted origins to access sensitive resources.",
        fix_steps=[
            "Remove 'Access-Control-Allow-Origin: *' on authenticated endpoints",
            "Whitelist specific trusted origins instead of reflecting the Origin header",
            "Never allow credentials with wildcard origins",
            "Validate the Origin header server-side before reflecting",
        ],
        commands=[
            "# Nginx: add_header Access-Control-Allow-Origin 'https://trusted.com';",
            "# Apache: Header set Access-Control-Allow-Origin 'https://trusted.com'",
            "# Express.js: cors({ origin: ['https://trusted.com'], credentials: true })",
        ],
        effort="Low",
        priority="Medium",
        references=[
            "https://portswigger.net/web-security/cors",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing",
        ],
        cwe_id="CWE-942",
        owasp_category="A05:2021 - Security Misconfiguration",
    ),
    
    "clickjacking": Remediation(
        title="Clickjacking / UI Redress",
        description="Application can be framed by malicious sites, tricking users into unintended actions.",
        fix_steps=[
            "Set X-Frame-Options header to DENY or SAMEORIGIN",
            "Implement Content-Security-Policy frame-ancestors directive",
            "Use frame-busting JavaScript as defense-in-depth",
        ],
        commands=[
            "# Nginx: add_header X-Frame-Options 'DENY' always;",
            "# Apache: Header always set X-Frame-Options 'DENY'",
            "# CSP: Content-Security-Policy: frame-ancestors 'none';",
        ],
        effort="Low",
        priority="Medium",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
        cwe_id="CWE-1021",
        owasp_category="A01:2021 - Broken Access Control",
    ),
    
    "cookie-issues": Remediation(
        title="Insecure Cookie Configuration",
        description="Session cookies lack security flags, making them vulnerable to interception or XSS theft.",
        fix_steps=[
            "Set HttpOnly flag on all session cookies",
            "Set Secure flag to prevent transmission over HTTP",
            "Set SameSite attribute to Strict or Lax",
            "Use __Host- or __Secure- cookie prefixes for additional protection",
        ],
        commands=[
            "# PHP: session.cookie_httponly = 1; session.cookie_secure = 1",
            "# Express.js: { httpOnly: true, secure: true, sameSite: 'strict' }",
            "# Django: SESSION_COOKIE_HTTPONLY = True; SESSION_COOKIE_SECURE = True",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
        cwe_id="CWE-614",
        owasp_category="A07:2021 - Identification and Authentication Failures",
    ),
    
    "file-upload": Remediation(
        title="Unrestricted File Upload",
        description="Application allows uploading malicious files (web shells, executables) without proper validation.",
        fix_steps=[
            "Validate file type by content (magic bytes), not just extension",
            "Store uploads outside web root or on a separate domain",
            "Rename uploaded files to random names",
            "Set size limits and scan with antivirus",
            "Disable script execution in upload directories",
        ],
        commands=[
            "# Nginx disable PHP in uploads: location /uploads/ { location ~ \\.php$ { deny all; } }",
            "# Apache: <Directory /uploads> php_flag engine off </Directory>",
            "# Python: imghdr.what(file) to verify image type",
        ],
        effort="Medium",
        priority="Critical",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
        cwe_id="CWE-434",
        owasp_category="A04:2021 - Insecure Design",
    ),
    
    "deserialization": Remediation(
        title="Insecure Deserialization",
        description="Application deserializes untrusted data, enabling remote code execution or privilege escalation.",
        fix_steps=[
            "Never deserialize untrusted data",
            "Use safe serialization formats (JSON) instead of native object serialization",
            "Implement integrity checks (HMAC) on serialized objects",
            "Restrict deserialization classes via allowlists",
            "Monitor deserialization exceptions for attack patterns",
        ],
        commands=[
            "# Python: Use json.loads() instead of pickle.loads()",
            "# Java: Use ObjectInputFilter to whitelist classes",
            "# PHP: Use json_decode() instead of unserialize()",
        ],
        effort="High",
        priority="Critical",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
        ],
        cwe_id="CWE-502",
        owasp_category="A08:2021 - Software and Data Integrity Failures",
    ),
    
    "xxe": Remediation(
        title="XML External Entity (XXE) Injection",
        description="Application processes XML input with external entity references, enabling file disclosure or SSRF.",
        fix_steps=[
            "Disable external entity processing in XML parsers",
            "Use less complex data formats (JSON) where possible",
            "Validate and sanitize XML input",
            "Update XML processing libraries to latest versions",
        ],
        commands=[
            "# Python (lxml): parser = etree.XMLParser(resolve_entities=False)",
            "# Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
            "# PHP: libxml_disable_entity_loader(true)",
        ],
        effort="Low",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-611",
        owasp_category="A05:2021 - Security Misconfiguration",
    ),
    
    "idor": Remediation(
        title="Insecure Direct Object Reference (IDOR)",
        description="Application exposes internal object references, allowing unauthorized access to other users' data.",
        fix_steps=[
            "Implement proper authorization checks on every data access",
            "Use indirect references (UUIDs) instead of sequential IDs",
            "Validate that the authenticated user owns the requested resource",
            "Log and alert on access pattern anomalies",
        ],
        commands=[
            "# Python: if obj.owner_id != current_user.id: abort(403)",
            "# Use UUIDs: import uuid; resource_id = str(uuid.uuid4())",
            "# Django: queryset.filter(owner=request.user)",
        ],
        effort="Medium",
        priority="High",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-639",
        owasp_category="A01:2021 - Broken Access Control",
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
        "csrf": "csrf",
        "cross-site-request": "csrf",
        "request-forgery": "csrf",
        "cors": "cors-misconfiguration",
        "cross-origin": "cors-misconfiguration",
        "clickjack": "clickjacking",
        "x-frame": "clickjacking",
        "frame-options": "clickjacking",
        "cookie": "cookie-issues",
        "httponly": "cookie-issues",
        "samesite": "cookie-issues",
        "upload": "file-upload",
        "unrestricted-file": "file-upload",
        "deserialization": "deserialization",
        "deserializ": "deserialization",
        "pickle": "deserialization",
        "xxe": "xxe",
        "xml-external": "xxe",
        "external-entity": "xxe",
        "idor": "idor",
        "insecure-direct": "idor",
        "object-reference": "idor",
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
        # Nikto generic finding names
        "web-server-finding": "web-server-finding",
        "web server finding": "web-server-finding",
        "server finding": "web-server-finding",
        "misconfiguration": "web-server-misconfiguration",
        "web server misconfiguration": "web-server-misconfiguration",
        "critical web vulnerability": "critical-web-vulnerability",
        "critical-web-vulnerability": "critical-web-vulnerability",
        "high risk web vulnerability": "high-risk-web-vulnerability",
        "high-risk-web-vulnerability": "high-risk-web-vulnerability",
        "osvdb": "osvdb-listed-vulnerability",
        "osvdb-listed": "osvdb-listed-vulnerability",
        "finding": "web-server-finding",
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

# ── Fallback entries for generic Nikto / scanner finding names ──────────────

REMEDIATION_DB["web-server-finding"] = Remediation(
    title="Web Server Security Finding",
    description="The web server has a configuration or disclosure issue detected during automated scanning.",
    fix_steps=[
        "Review the specific finding details and apply vendor hardening guidelines",
        "Disable unnecessary features, modules, and default pages on the web server",
        "Remove server version disclosure from HTTP response headers",
        "Apply CIS Benchmark hardening for your web server (Apache/Nginx/IIS)",
        "Run a manual review of server configuration files",
    ],
    commands=[
        "# Apache — remove server version: ServerTokens Prod",
        "# Apache — remove OS info: ServerSignature Off",
        "# Nginx — remove version: server_tokens off;",
        "# Check current headers: curl -I http://target.com",
    ],
    effort="Low",
    priority="Low",
    references=[
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
        "https://www.cisecurity.org/benchmark/apache_http_server",
    ],
    cwe_id="CWE-16",
    owasp_category="A05:2021 - Security Misconfiguration",
)

REMEDIATION_DB["web-server-misconfiguration"] = Remediation(
    title="Web Server Misconfiguration",
    description="A web server misconfiguration was detected that could expose sensitive information or enable attacks.",
    fix_steps=[
        "Identify the specific misconfiguration from the finding details",
        "Apply the principle of least privilege to web server directories",
        "Disable directory listing if enabled",
        "Ensure security headers are present: X-Frame-Options, X-Content-Type-Options, CSP",
        "Review and tighten file permissions on web root",
    ],
    commands=[
        "# Apache — disable directory listing: Options -Indexes",
        "# Nginx — disable autoindex: autoindex off;",
        "# Add security headers (Apache): Header always set X-Frame-Options DENY",
        "# Test headers: curl -I https://target.com | grep -i 'x-frame\\|x-content\\|strict'",
    ],
    effort="Low",
    priority="Medium",
    references=[
        "https://owasp.org/www-project-secure-headers/",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ],
    cwe_id="CWE-16",
    owasp_category="A05:2021 - Security Misconfiguration",
)

REMEDIATION_DB["critical-web-vulnerability"] = Remediation(
    title="Critical Web Vulnerability",
    description="A critical severity vulnerability was identified by automated scanning. Immediate review required.",
    fix_steps=[
        "IMMEDIATE: Identify the exact vulnerability from scanner output details",
        "Apply vendor patches or workarounds immediately",
        "Isolate affected service if active exploitation is suspected",
        "Conduct manual verification of the finding",
        "Review access logs for signs of exploitation",
    ],
    commands=[
        "# Check logs for exploitation attempts:",
        "grep -i 'cmd=\\|exec(\\|system(\\|passthru(' /var/log/apache2/access.log",
        "# Monitor live traffic: tcpdump -i eth0 port 80 -A",
    ],
    effort="Medium",
    priority="Critical",
    references=[
        "https://owasp.org/www-community/vulnerabilities/",
        "https://nvd.nist.gov/",
    ],
    cwe_id="CWE-20",
    owasp_category="A03:2021 - Injection",
)

REMEDIATION_DB["high-risk-web-vulnerability"] = Remediation(
    title="High Risk Web Vulnerability",
    description="A high severity web vulnerability was detected. Prioritise remediation within 1 week.",
    fix_steps=[
        "Review the vulnerability details from the scanner output",
        "Apply available patches or implement compensating controls",
        "Validate all user-controlled input strictly on server side",
        "Implement WAF rules targeting the identified vulnerability class",
        "Retest after remediation to confirm fix",
    ],
    commands=[
        "# Deploy ModSecurity WAF (Apache):",
        "sudo apt install libapache2-mod-security2",
        "sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf",
    ],
    effort="Medium",
    priority="High",
    references=[
        "https://owasp.org/www-project-web-security-testing-guide/",
    ],
    cwe_id="CWE-20",
    owasp_category="A03:2021 - Injection",
)

REMEDIATION_DB["osvdb-listed-vulnerability"] = Remediation(
    title="OSVDB Listed Vulnerability",
    description="A vulnerability listed in the OSVDB database was detected. Review the specific OSVDB entry for details.",
    fix_steps=[
        "Look up the specific OSVDB ID in NVD or CVE databases for current patch status",
        "Apply the relevant vendor patch or upgrade to a patched version",
        "If no patch exists, implement compensating controls (WAF, firewall rules)",
        "Monitor vendor security advisories for updates",
    ],
    commands=[
        "# Search NVD for CVE details: https://nvd.nist.gov/vuln/search",
        "# Check installed package version: dpkg -l | grep <package>",
        "# Update all packages: sudo apt update && sudo apt upgrade",
    ],
    effort="Medium",
    priority="Medium",
    references=[
        "https://nvd.nist.gov/",
        "https://www.cve.org/",
    ],
    cwe_id="CWE-1104",
    owasp_category="A06:2021 - Vulnerable and Outdated Components",
)