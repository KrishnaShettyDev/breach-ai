# Vulnerability Coverage

BREACH detects and exploits the following vulnerability classes.

## Injection (OWASP A03:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| SQL Injection (Error-based) | Yes | Yes | Yes |
| SQL Injection (Blind) | Yes | Yes | Yes |
| SQL Injection (Time-based) | Yes | Yes | Yes |
| NoSQL Injection (MongoDB) | Yes | Yes | Yes |
| Command Injection | Yes | Yes | Yes |
| LDAP Injection | Yes | Yes | Yes |
| XPath Injection | Yes | Yes | Yes |
| Template Injection (SSTI) | Yes | Yes | Yes |

## Cross-Site Scripting (OWASP A03:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| Reflected XSS | Yes | Yes | Yes |
| Stored XSS | Yes | Yes | Yes |
| DOM-based XSS | Yes | Yes | Yes |
| XSS via File Upload | Yes | Yes | Yes |

## Broken Authentication (OWASP A07:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| JWT Algorithm Confusion | Yes | Yes | Yes |
| JWT None Algorithm | Yes | Yes | Yes |
| JWT Key Brute Force | Yes | Yes | Yes |
| OAuth Token Theft | Yes | Yes | Yes |
| Session Fixation | Yes | Yes | Yes |
| Password Reset Flaws | Yes | Yes | Yes |
| MFA Bypass | Yes | Yes | Yes |
| SAML Signature Bypass | Yes | Yes | Yes |

## Broken Access Control (OWASP A01:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| IDOR | Yes | Yes | Yes |
| Privilege Escalation | Yes | Yes | Yes |
| Forced Browsing | Yes | Yes | Yes |
| Directory Traversal | Yes | Yes | Yes |

## Server-Side Request Forgery (OWASP A10:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| SSRF to Internal Services | Yes | Yes | Yes |
| SSRF to Cloud Metadata | Yes | Yes | Yes |
| SSRF via Redirects | Yes | Yes | Yes |
| Blind SSRF | Yes | Yes | Yes |

## XML External Entity (OWASP A05:2021)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| XXE File Read | Yes | Yes | Yes |
| XXE SSRF | Yes | Yes | Yes |
| Blind XXE | Yes | Yes | Yes |

## API Security (OWASP API Top 10)

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| API Key Leakage | Yes | Yes | Yes |
| Mass Assignment | Yes | Yes | Yes |
| Rate Limiting Bypass | Yes | Yes | Yes |
| GraphQL Introspection | Yes | Yes | Yes |
| GraphQL Injection | Yes | Yes | Yes |
| REST API Enumeration | Yes | Yes | Yes |

## Modern Stack

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| Next.js/Nuxt Misconfig | Yes | Yes | Yes |
| Vercel/Netlify Secrets | Yes | Yes | Yes |
| Supabase RLS Bypass | Yes | Yes | Yes |
| Firebase Rules Bypass | Yes | Yes | Yes |
| Exposed Environment Vars | Yes | Yes | Yes |

## Cloud Security

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| S3 Bucket Misconfiguration | Yes | Yes | Yes |
| Azure Blob Exposure | Yes | Yes | Yes |
| GCP Storage Misconfiguration | Yes | Yes | Yes |
| Cloud Metadata Access | Yes | Yes | Yes |
| Subdomain Takeover | Yes | Yes | Yes |

## Infrastructure

| Vulnerability | Detection | Exploitation | Auto-PoC |
|---------------|-----------|--------------|----------|
| File Upload Bypass | Yes | Yes | Yes |
| LFI/RFI | Yes | Yes | Yes |
| Docker Socket Exposure | Yes | Yes | Yes |
| Kubernetes API Exposure | Yes | Yes | Yes |

## Total: 60+ Vulnerability Types

All findings include:
- Working proof-of-concept
- Reproduction steps (curl command)
- Exploitation evidence
- Remediation guidance
- OWASP/CWE references
