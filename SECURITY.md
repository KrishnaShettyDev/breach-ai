# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| 2.x.x   | :x:                |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities in BREACH seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/KrishnaShettyDev/breach-ai/security/advisories)
   - Click "Report a vulnerability"
   - Fill out the form with details

2. **Email**
   - Send details to: security@breach-ai.dev (if available)
   - Use PGP encryption if possible

### What to Include

Please include the following in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Affected versions** of BREACH
- **Potential impact** assessment
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial Response | 48 hours |
| Vulnerability Confirmation | 7 days |
| Fix Development | 14-30 days (severity dependent) |
| Public Disclosure | After fix is released |

### What to Expect

1. **Acknowledgment** - We'll confirm receipt within 48 hours
2. **Assessment** - We'll evaluate severity and impact
3. **Updates** - We'll keep you informed of progress
4. **Credit** - We'll credit you in the security advisory (unless you prefer anonymity)
5. **Fix** - We'll develop and release a patch

## Security Considerations for Users

### Before Using BREACH

1. **Authorization** - Only scan targets you own or have explicit written permission to test
2. **Environment** - Run in isolated environments when possible
3. **API Keys** - Never commit API keys; use environment variables
4. **Reports** - Handle vulnerability reports as confidential

### Safe Usage

```bash
# Use environment variables for sensitive data
export ANTHROPIC_API_KEY="sk-ant-..."

# Never use on production systems without explicit authorization
breach https://staging.yourapp.com  # OK if authorized
breach https://production.yourapp.com  # DANGEROUS

# Use isolated Docker environment
docker run --rm breach-ai scan https://authorized-target.com
```

### Known Limitations

BREACH is a security testing tool with inherent risks:

- **False Negatives** - Not finding a vulnerability doesn't mean one doesn't exist
- **Destructive Potential** - Some attack modules may modify data
- **Rate Limiting** - Aggressive scanning may trigger security controls
- **Legal Liability** - Users are responsible for authorized use

## Security Features

### Built-in Protections

- **Authorization Prompt** - Requires explicit confirmation before scanning
- **Rate Limiting** - Configurable request throttling
- **Safe Payloads** - Designed to prove exploitability without permanent damage
- **No Data Exfiltration** - Proves access without stealing data

### Recommended Configuration

```yaml
# config.yaml
scan:
  rate_limit: 50  # Requests per second
  timeout_minutes: 30
  respect_robots_txt: true

# Exclude sensitive paths
exclude:
  - /admin/delete
  - /api/destroy
```

## Dependencies

We regularly audit dependencies for vulnerabilities:

- **Dependabot** - Automated security updates
- **pip-audit** - Python dependency scanning
- **Regular reviews** - Manual security reviews

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter notifies us privately
2. We confirm and assess the issue
3. We develop a fix
4. We release the fix
5. We publish a security advisory
6. Reporter may publish details (after fix release)

## Hall of Fame

We thank the following security researchers for responsibly disclosing vulnerabilities:

*No vulnerabilities reported yet - be the first!*

---

Thank you for helping keep BREACH and its users secure.
