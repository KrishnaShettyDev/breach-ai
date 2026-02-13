# BREACH

**Autonomous Security Scanner with Proof-by-Exploitation**

BREACH is an AI-powered security scanner that goes beyond detection - it proves vulnerabilities by safely exploiting them. Unlike traditional scanners that generate false positives, BREACH provides concrete evidence of exploitability.

## Features

- **60+ Attack Modules** - SQL injection, XSS, SSRF, authentication bypass, and more
- **Proof-by-Exploitation** - Every finding includes working proof-of-concept
- **AI-Powered Analysis** - Optional Claude integration for intelligent attack planning
- **Multiple Scan Modes** - From quick recon to comprehensive chaos testing
- **Beautiful Reports** - JSON, Markdown, and HTML output formats

## Installation

```bash
pip install breach-ai
```

For AI-powered features:
```bash
pip install breach-ai[ai]
```

For browser-based testing:
```bash
pip install breach-ai[browser]
```

For everything:
```bash
pip install breach-ai[full]
```

## Quick Start

```bash
# Basic scan
breach https://example.com

# Quick reconnaissance
breach https://example.com --mode quick

# Deep comprehensive scan
breach https://example.com --mode deep

# Only proven/exploited vulnerabilities
breach https://example.com --mode proven

# All 60+ modules (chaos mode)
breach https://example.com --mode chaos
```

## Scan Modes

| Mode | Description | Duration |
|------|-------------|----------|
| `quick` | Fast recon and common vulnerabilities | ~5 min |
| `deep` | Comprehensive testing with all checks | ~30 min |
| `proven` | Only report exploited vulnerabilities | ~20 min |
| `chaos` | Run all 60+ attack modules | ~45 min |

## Output Formats

```bash
# JSON output
breach https://example.com -o report.json

# Markdown report
breach https://example.com -o report.md

# HTML report
breach https://example.com -o report.html
```

## Commands

```bash
# Show version
breach --version

# List all attack modules
breach list-modules

# System diagnostics
breach doctor

# Show help
breach --help
```

## Attack Modules

BREACH includes 60+ attack modules covering:

### Injection
- SQL Injection (error-based, blind, time-based)
- NoSQL Injection (MongoDB operators)
- Command Injection
- LDAP Injection
- XPath Injection

### Cross-Site Scripting (XSS)
- Reflected XSS
- Stored XSS
- DOM-based XSS

### Authentication
- Brute Force
- Credential Stuffing
- Password Reset Flaws
- Session Fixation
- JWT Attacks

### Authorization
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Access Control Bypass

### Server-Side
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- SSTI (Server-Side Template Injection)
- Path Traversal
- File Inclusion (LFI/RFI)

### API Security
- GraphQL Introspection
- REST API Enumeration
- Rate Limiting Bypass
- Mass Assignment

### Infrastructure
- Subdomain Takeover
- DNS Zone Transfer
- SSL/TLS Misconfigurations
- Information Disclosure

## Configuration

Create a `.env` file or set environment variables:

```bash
# Optional: AI-powered analysis
ANTHROPIC_API_KEY=sk-ant-...

# Optional: Custom settings
BREACH_TIMEOUT=30
BREACH_RATE_LIMIT=50
BREACH_OUTPUT_DIR=./reports
```

## Example Output

```
BREACH v2.0.0 - Autonomous Security Scanner
============================================

Target: https://example.com
Mode: deep
Started: 2024-01-15 10:30:00

[*] Reconnaissance Phase
    - Discovered 45 endpoints
    - Found 12 parameters
    - Identified technologies: PHP, MySQL, nginx

[*] Attack Phase
    - Testing SQL Injection...
      CRITICAL: SQLi found in /api/users?id=
    - Testing XSS...
      HIGH: Reflected XSS in /search?q=
    - Testing SSRF...
      CRITICAL: SSRF in /fetch?url=

[*] Exploitation Phase
    - Exploiting SQLi... SUCCESS
      Extracted: 1,247 user records
    - Exploiting SSRF... SUCCESS
      Accessed internal endpoint: http://169.254.169.254/

============================================
Scan Complete: 3 vulnerabilities (2 critical, 1 high)
Report saved: report.json
```

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/breach.git
cd breach

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[full]"

# Run tests
pytest

# Run the CLI
breach --help
```

## Legal Disclaimer

BREACH is designed for **authorized security testing only**.

- Only scan targets you own or have explicit written permission to test
- Unauthorized scanning may violate computer crime laws
- The authors are not responsible for misuse of this tool

By using BREACH, you agree to use it responsibly and legally.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## Acknowledgments

Inspired by the security research community and tools like:
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)
- [Shannon](https://github.com/KeygraphHQ/shannon)
