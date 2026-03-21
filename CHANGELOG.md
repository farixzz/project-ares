# Changelog

All notable changes to ARES will be documented in this file.

## [2.0.1] - 2026-03-21

### Added
- **27 EOL technology patterns** with CVE mappings (PHP 5.x–8.0, Nginx, Apache, OpenSSL, IIS, Node.js, jQuery)
- **Quick Wins** section now populated for EOL findings (PHP, Nginx, Apache)
- **Unit test suite** with 38 tests covering technology analysis, Nikto parsing, CVSS scoring, and remediation DB
- **CVSS/CVE display** in terminal, HTML, and PDF reports
- **Remediation Roadmap** with EOL-specific actionable guidance
- `.gitignore` and `.dockerignore` for clean repo hygiene

### Fixed
- WhatWeb `--wait` parameter misused as timeout (now uses `--open-timeout`/`--read-timeout`)
- Rich markup crashes from invalid closing tags (`[/bold red]` → `[/]`)
- Technology analysis now runs in all scan profiles (was only in `standard`/`deep`)
- CVSS/CVE fields correctly propagated through all report formats
- RCE pattern matching in CVSS scorer and remediation DB
- Unused imports cleaned across tool wrapper modules

### Changed
- Renamed `cli.py` → `ares.py` for cleaner CLI experience
- Improved `--help` output with clear command descriptions and Quick Start guide
- Version badge in README corrected to `2.0.1`

## [2.0.0] - 2026-02-01

### Added
- Initial release with autonomous scanning engine
- Multi-tool integration (Nmap, Nuclei, Nikto, SQLMap, WhatWeb, Katana, FFUF)
- CVSS 3.1 Base + Temporal scoring
- PDF, HTML, JSON report generation
- 4 scan profiles: quick, standard, deep, stealth
- Remediation database with OWASP/CWE mappings
