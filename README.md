# BREACH

**Autonomous Security Scanner with Proof-by-Exploitation**

BREACH is an AI-powered security scanner that proves vulnerabilities by exploiting them. No false positives - every finding includes working proof.

## Install

```bash
pip install breach-ai
```

With AI + Browser:
```bash
pip install breach-ai[full]
```

## Usage

```bash
# Scan a target
breach scan https://example.com

# AI God Mode (3-4 hours autonomous)
breach god https://example.com

# Source code analysis
breach analyze ./myapp

# List modules
breach modules
```

## Core Attack Modules

10 battle-tested modules. AI handles the rest.

| Module | Type | Severity |
|--------|------|----------|
| `sqli` | SQL Injection | CRITICAL |
| `nosql` | NoSQL Injection | CRITICAL |
| `cmdi` | Command Injection | CRITICAL |
| `ssti` | Template Injection | CRITICAL |
| `ssrf` | Server-Side Request Forgery | CRITICAL |
| `xss` | Cross-Site Scripting | HIGH |
| `auth` | Authentication Attacks | CRITICAL |
| `jwt` | JWT Attacks | CRITICAL |
| `idor` | Insecure Direct Object Reference | HIGH |
| `lfi` | File Inclusion/Traversal | HIGH |

## Commands

```bash
breach scan <url>      # 4-phase security scan
breach god <url>       # AI autonomous mode
breach analyze <path>  # Source code analysis
breach modules         # List attack modules
breach doctor          # Check dependencies
breach version         # Show version
```

## Environment

```bash
# Required for AI features
ANTHROPIC_API_KEY=sk-ant-...

# Optional for multi-LLM
OPENAI_API_KEY=sk-...
```

## License

[AGPL-3.0](LICENSE)

## Disclaimer

For authorized security testing only. You must own the target or have written permission.
