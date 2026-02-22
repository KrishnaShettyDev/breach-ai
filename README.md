# BREACH

[![PyPI](https://img.shields.io/pypi/v/aibreach)](https://pypi.org/project/aibreach/)
[![Python](https://img.shields.io/pypi/pyversions/aibreach)](https://pypi.org/project/aibreach/)
[![License](https://img.shields.io/github/license/KrishnaShettyDev/breach-ai)](https://github.com/KrishnaShettyDev/breach-ai/blob/main/LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/aibreach)](https://pypi.org/project/aibreach/)

AI-powered security scanner that proves vulnerabilities by exploiting them. No false positives.

## Install

```bash
pip install aibreach
```

With AI features:
```bash
pip install aibreach[full]
```

## Usage

```bash
# Scan a target
breach scan https://example.com

# AI autonomous mode
breach god https://example.com

# Source code analysis
breach analyze ./src

# List modules
breach modules
```

## Attack Modules

| Module | Type | Severity |
|--------|------|----------|
| `sqli` | SQL Injection | Critical |
| `nosql` | NoSQL Injection | Critical |
| `cmdi` | Command Injection | Critical |
| `ssti` | Template Injection | Critical |
| `ssrf` | Server-Side Request Forgery | Critical |
| `xss` | Cross-Site Scripting | High |
| `auth` | Authentication Bypass | Critical |
| `jwt` | JWT Attacks | Critical |
| `idor` | Insecure Direct Object Reference | High |
| `lfi` | Local File Inclusion | High |

## Requirements

- Python 3.11+
- `ANTHROPIC_API_KEY` for AI features

## License

AGPL-3.0

## Disclaimer

For authorized security testing only.
