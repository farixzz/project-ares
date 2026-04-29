# Changelog

## [v2.0.3] — 2026-04-02
### Security
- CVE-2025-68664 (CVSS 9.3) — Updated LangChain to >=0.3.81
- Fixed serve command default bind from 0.0.0.0 to 127.0.0.1

### Fixed
- Apache 2.4.x EOL versions now flagged as HIGH severity
- Version banner updated to v2.0.2 across all files

## [v2.0.2] — 2026-03-26
### Fixed
- 0-vulnerability bug on standard profile
- Nuclei -je race condition replaced with -json-export
- Nikto output truncation at 2000 chars removed
- Nikto tuning expanded from 1 to all classes
- Ollama silent failure now shows loud warning
- Report false-positive "target appears secure" message
- Remediation empty for Nikto findings — added 5 entries

## [v2.0.1] — 2026-03-25
### Initial public release
- Autonomous scanning engine with state machine workflow
- CVSS 3.1 scoring engine built from scratch
- 10 tool integrations
- 4 scan profiles: quick, standard, deep, stealth
- PDF, HTML, JSON reports
- MITRE ATT&CK mapping
- Docker multi-stage build
