# 🎯 ARES Scan Profiles Documentation

This document provides detailed information about each scan profile available in ARES. Each profile is designed for specific use cases, balancing thoroughness, speed, and stealth.

---

## Profile Comparison Matrix

| Feature | Quick | Standard | Deep | Stealth |
|---------|-------|----------|------|---------|
| **Duration** | ~5 min | ~30 min | 2+ hrs | ~1 hr |
| **Port Scan** | Top 100 | Top 1000 | All 65535 | Top 1000 (slow) |
| **Subdomain Enum** | ❌ | ✅ | ✅ | ✅ (passive) |
| **Technology Fingerprint** | Basic | Full | Full + Deep | Minimal |
| **Web Crawling** | ❌ | ✅ | ✅ (aggressive) | ✅ (limited) |
| **Directory Fuzzing** | ❌ | ✅ | ✅ | ❌ |
| **Vulnerability Scan** | ❌ | ✅ (Nuclei) | ✅ (Nuclei + Nikto) | ✅ (quiet templates) |
| **Exploitation** | ❌ | ❌ | ✅ (SQLMap, Commix, Hydra) | ❌ |
| **WAF Bypass** | ❌ | ❌ | ❌ | ✅ |
| **Recommended For** | Quick recon | Standard pentests | Full assessments | IDS/WAF environments |

---

## 🚀 Quick Profile

**Use Case**: Rapid reconnaissance for time-sensitive situations or initial target assessment.

### What It Does
- Scans top 100 most common ports
- Basic technology fingerprinting with WhatWeb
- Minimal network footprint

### Nmap Arguments
```
-sS -T4 --top-ports 100 --open
```

### Tools Used
1. **Nmap** - Fast SYN scan
2. **WhatWeb** - Technology detection (aggression level 1)

### When to Use
- Initial scoping of unknown targets
- Time-limited engagements
- CTF competitions
- Checking if a host is alive

### Example
```bash
python ares.py scan -t target.com -p quick
```

---

## ⚙️ Standard Profile

**Use Case**: Balanced assessment suitable for most penetration tests.

### What It Does
- Comprehensive port scanning (top 1000 ports)
- Full subdomain enumeration
- Deep technology fingerprinting
- Web crawling and endpoint discovery
- Directory fuzzing
- Automated vulnerability scanning

### Nmap Arguments
```
-sS -sV -sC -T3 --top-ports 1000
```

### Tools Used
1. **Subfinder** - Subdomain discovery
2. **Nmap** - Port scan with service detection and scripts
3. **WhatWeb** - Technology fingerprinting (aggression level 3)
4. **Katana** - Web crawling
5. **FFUF** - Directory/file fuzzing
6. **Nuclei** - Vulnerability scanning

### When to Use
- Standard web application assessments
- Network penetration tests
- Bug bounty hunting
- Compliance audits

### Example
```bash
python ares.py scan -t target.com -p standard
```

---

## 🔥 Deep Profile

**Use Case**: Comprehensive security assessment with exploitation capabilities.

### What It Does
- **Full port scan** (all 65535 ports)
- Aggressive subdomain enumeration
- Deep technology fingerprinting
- Extensive web crawling
- Multi-wordlist directory fuzzing
- Full vulnerability scanning (Nuclei + Nikto)
- **Active exploitation attempts**:
  - SQL injection testing (SQLMap)
  - Command injection testing (Commix)
  - Credential brute-forcing (Hydra)

### Nmap Arguments
```
-sS -sV -sC -p- -T4 --script vuln,vulners
```

### Tools Used
1. **Subfinder** - Subdomain discovery
2. **Nmap** - Full port scan with vulnerability scripts
3. **WhatWeb** - Aggressive fingerprinting (level 4)
4. **Katana** - Deep web crawling
5. **FFUF** - Extended fuzzing
6. **Nuclei** - Full template scanning
7. **Nikto** - Web server vulnerability scan
8. **SQLMap** - SQL injection exploitation
9. **Commix** - Command injection exploitation
10. **Hydra** - Credential brute-forcing (SSH, FTP, Telnet)

### ⚠️ Warnings
- **LOUD**: Generates significant network traffic and logs
- **TIME**: Can take 2+ hours depending on target size
- **EXPLOITATION**: May modify target state (use with caution)
- Only use with **explicit written authorization**

### When to Use
- Full-scope penetration tests
- Red team engagements
- Security assessments with exploitation scope
- Pre-production security validation

### Example
```bash
python ares.py scan -t target.com -p deep
```

---

## 🥷 Stealth Profile

**Use Case**: Evading intrusion detection systems and web application firewalls.

### What It Does
- Slow, evasive port scanning
- Passive subdomain enumeration only
- Minimal technology fingerprinting
- Rate-limited web crawling
- No directory fuzzing (too noisy)
- Quiet vulnerability templates only
- WAF detection and bypass attempts

### Nmap Arguments
```
-sS -T1 --top-ports 1000 --scan-delay 500ms --randomize-hosts
```

### Tools Used
1. **Subfinder** - Passive subdomain enumeration
2. **Nmap** - Slow, randomized scanning
3. **WhatWeb** - Passive fingerprinting (level 1)
4. **Katana** - Rate-limited crawling
5. **Nuclei** - Quiet/safe templates only

### Evasion Techniques
- Randomized timing between requests
- Fragmented packets
- Common user-agent rotation
- Rate limiting (max 1 request/second)
- No aggressive fuzzing

### When to Use
- Targets with known IDS/IPS
- WAF-protected applications
- Situations requiring minimal detection
- Initial recon in red team ops

### Example
```bash
python ares.py scan -t target.com -p stealth
```

---

## 🎛️ Customizing Profiles

You can customize profile behavior via the configuration file:

```bash
python ares.py config --init
vim ~/.config/ares/config.yaml
```

### Configuration Options

```yaml
profiles:
  custom:
    name: "Custom Profile"
    timeout_minutes: 60
    nmap_args: "-sS -sV -T3 --top-ports 500"
    enable_subdomain: true
    enable_fingerprint: true
    enable_crawl: true
    enable_fuzzing: false
    enable_nuclei: true
    enable_exploitation: false
    stealth_mode: false
```

---

## 🔐 Security Considerations

1. **Authorization**: Always obtain written permission before scanning
2. **Scope**: Ensure targets are in-scope for your engagement
3. **Data Handling**: Secure scan results appropriately
4. **Exploitation**: The `deep` profile can modify target state
5. **Rate Limiting**: Be mindful of target bandwidth and availability

---

## 📊 CVSS Scoring

ARES v4.0 uses **CVSS 3.1** scoring with Base and Temporal metrics:

- **Base Score**: Attack vector, complexity, privileges, impact
- **Temporal Score**: Exploit Code Maturity (focus on "hackability")

This means vulnerabilities with known exploits are prioritized over theoretical ones.

### Severity Levels

| Score | Level | Action |
|-------|-------|--------|
| 9.0 - 10.0 | CRITICAL | Immediate remediation required |
| 7.0 - 8.9 | HIGH | Prioritize in next sprint |
| 4.0 - 6.9 | MEDIUM | Schedule remediation |
| 0.1 - 3.9 | LOW | Address when convenient |
| 0.0 | NONE | Informational only |

---

*Developed by [farixzz](https://github.com/farixzz)*
