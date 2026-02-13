# BREACH Open Source Launch Checklist

A comprehensive checklist for launching BREACH as a secure, professional open-source security tool.

---

## 1. Code Security Audit

### 1.1 Secrets & Credentials
- [ ] **Scan git history for secrets** - Use tools like `trufflehog` or `gitleaks`
  ```bash
  trufflehog git file://. --since-commit HEAD~100
  gitleaks detect --source . -v
  ```
- [ ] **Remove any hardcoded API keys** - Search for patterns like `sk-`, `api_key`, `password`
- [ ] **Check .env files are gitignored** - Verify `.env` is in `.gitignore`
- [ ] **Audit .env.example** - Ensure no real values, only placeholders
- [ ] **Review config.py** - No hardcoded secrets or internal URLs

### 1.2 Code Quality & Security
- [ ] **Run static analysis** - Use `bandit` for Python security issues
  ```bash
  pip install bandit
  bandit -r src/ -ll
  ```
- [ ] **Check for SQL injection** - Even in attack payloads, ensure safe patterns
- [ ] **Review all `eval()` and `exec()` usage** - Ensure sandboxed properly
- [ ] **Audit subprocess calls** - Check for command injection in our own code
- [ ] **Review HTTP client** - Ensure SSRF protections when scanning
- [ ] **Check file operations** - Path traversal protections in place
- [ ] **Audit dependencies** - Run `pip-audit` or `safety check`
  ```bash
  pip install pip-audit
  pip-audit
  ```

### 1.3 Sensitive Data Handling
- [ ] **Review logging** - No sensitive data logged (passwords, tokens, API keys)
- [ ] **Check error messages** - No stack traces exposing internals
- [ ] **Audit report generation** - Sanitize output, no internal paths exposed
- [ ] **Review sample payloads** - Remove any real target data

---

## 2. Repository Security

### 2.1 Branch Protection
- [ ] **Protect main branch** - Require PR reviews
- [ ] **Require signed commits** - Enable commit signature verification
- [ ] **Enable status checks** - CI must pass before merge
- [ ] **Disable force push** - Prevent history rewriting on main

### 2.2 GitHub Security Features
- [ ] **Enable Dependabot** - Automated dependency updates
  ```yaml
  # .github/dependabot.yml
  version: 2
  updates:
    - package-ecosystem: "pip"
      directory: "/"
      schedule:
        interval: "weekly"
  ```
- [ ] **Enable secret scanning** - GitHub Settings → Security
- [ ] **Enable code scanning** - Set up CodeQL
- [ ] **Configure security advisories** - Enable private vulnerability reporting

### 2.3 Access Control
- [ ] **Review collaborators** - Remove unnecessary access
- [ ] **Audit deploy keys** - Remove unused keys
- [ ] **Review GitHub Apps** - Remove unnecessary integrations
- [ ] **Enable 2FA requirement** - For all contributors

---

## 3. Documentation

### 3.1 Essential Files
- [x] **README.md** - Installation, usage, features
- [x] **LICENSE** - AGPL-3.0
- [x] **CONTRIBUTING.md** - How to contribute
- [x] **SECURITY.md** - Security policy & reporting
- [ ] **CODE_OF_CONDUCT.md** - Community standards
- [ ] **CHANGELOG.md** - Version history

### 3.2 Technical Documentation
- [ ] **API/Module documentation** - Document attack modules
- [ ] **Architecture overview** - How the scanner works
- [ ] **Configuration guide** - All options explained
- [ ] **Output format docs** - JSON/MD/HTML schema

### 3.3 Legal Documentation
- [ ] **Terms of use** - Authorized testing only
- [ ] **Disclaimer** - Liability limitations
- [ ] **Third-party licenses** - Attribution for dependencies

---

## 4. CI/CD Pipeline

### 4.1 GitHub Actions Workflows
- [ ] **Create test workflow** - Run tests on PR
  ```yaml
  # .github/workflows/test.yml
  name: Tests
  on: [push, pull_request]
  jobs:
    test:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: '3.11'
        - run: pip install -e ".[full]"
        - run: pytest
  ```

- [ ] **Create security scan workflow**
  ```yaml
  # .github/workflows/security.yml
  name: Security
  on: [push, pull_request]
  jobs:
    security:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - run: pip install bandit safety
        - run: bandit -r src/ -ll
        - run: safety check
  ```

- [ ] **Create lint workflow** - Code quality checks
- [ ] **Create release workflow** - Auto-publish to PyPI

### 4.2 Pre-commit Hooks
- [ ] **Set up pre-commit**
  ```yaml
  # .pre-commit-config.yaml
  repos:
    - repo: https://github.com/pre-commit/pre-commit-hooks
      rev: v4.5.0
      hooks:
        - id: check-yaml
        - id: end-of-file-fixer
        - id: trailing-whitespace
        - id: check-added-large-files
        - id: detect-private-key
    - repo: https://github.com/PyCQA/bandit
      rev: 1.7.7
      hooks:
        - id: bandit
          args: ["-ll", "-r", "src/"]
  ```

---

## 5. Package Distribution

### 5.1 PyPI Preparation
- [ ] **Verify package name available** - Check `breach-ai` on PyPI
- [ ] **Create PyPI account** - https://pypi.org/account/register/
- [ ] **Set up API token** - For automated publishing
- [ ] **Test on TestPyPI first**
  ```bash
  pip install build twine
  python -m build
  twine upload --repository testpypi dist/*
  ```

### 5.2 Package Metadata
- [ ] **Verify pyproject.toml** - All fields correct
- [ ] **Add classifiers** - Development status, audience, license
- [ ] **Set project URLs** - Homepage, docs, issues
- [ ] **Verify entry points** - `breach` command works

### 5.3 Release Process
- [ ] **Create release tags** - Semantic versioning (v2.0.0)
- [ ] **Write release notes** - Features, fixes, breaking changes
- [ ] **Generate changelog** - From commits or manually

---

## 6. Community & Support

### 6.1 Issue Templates
- [ ] **Bug report template**
  ```markdown
  <!-- .github/ISSUE_TEMPLATE/bug_report.md -->
  ---
  name: Bug Report
  about: Report a bug in BREACH
  ---

  **Describe the bug**

  **To Reproduce**

  **Expected behavior**

  **Environment**
  - OS:
  - Python version:
  - BREACH version:
  ```

- [ ] **Feature request template**
- [ ] **Security vulnerability template** (private)

### 6.2 Pull Request Template
- [ ] **Create PR template**
  ```markdown
  <!-- .github/PULL_REQUEST_TEMPLATE.md -->
  ## Description

  ## Type of Change
  - [ ] Bug fix
  - [ ] New feature
  - [ ] Breaking change
  - [ ] Documentation

  ## Checklist
  - [ ] Tests pass
  - [ ] Documentation updated
  - [ ] No secrets committed
  ```

### 6.3 Community Channels
- [ ] **GitHub Discussions** - Enable for Q&A
- [ ] **Discord server** (optional) - Real-time community
- [ ] **Twitter/X account** (optional) - Announcements

---

## 7. Security Policies

### 7.1 Vulnerability Disclosure
- [ ] **Private vulnerability reporting** - GitHub security advisories
- [ ] **Security contact** - security@yourdomain.com or GitHub
- [ ] **Response SLA** - Define response times (48h acknowledgment)
- [ ] **Bug bounty** (optional) - Consider for critical findings

### 7.2 Responsible Use
- [ ] **Terms of service** - Legal use only
- [ ] **Rate limiting guidance** - Don't abuse targets
- [ ] **Scope limitations** - What NOT to scan
- [ ] **Reporting requirements** - Coordinate disclosure

### 7.3 Supply Chain Security
- [ ] **Pin dependencies** - Use exact versions in pyproject.toml
- [ ] **Verify checksums** - For critical dependencies
- [ ] **SBOM generation** - Software Bill of Materials
- [ ] **Sign releases** - GPG signed tags

---

## 8. Pre-Launch Testing

### 8.1 Functionality Testing
- [ ] **Test installation** - Fresh virtualenv
  ```bash
  python -m venv test_env
  source test_env/bin/activate
  pip install breach-ai
  breach --help
  ```
- [ ] **Test all commands** - `scan`, `doctor`, `list-modules`, `version`
- [ ] **Test scan modes** - quick, deep, proven, chaos
- [ ] **Test output formats** - JSON, Markdown, HTML
- [ ] **Test on different OS** - macOS, Linux, Windows

### 8.2 Security Testing
- [ ] **Scan own test target** - Verify findings are accurate
- [ ] **Test with no API key** - Graceful degradation
- [ ] **Test error handling** - Invalid URLs, network errors
- [ ] **Test rate limiting** - Verify we don't overwhelm targets

### 8.3 Documentation Testing
- [ ] **Follow README instructions** - Fresh install works
- [ ] **Verify all examples** - Commands work as documented
- [ ] **Check all links** - No broken links

---

## 9. Launch Preparation

### 9.1 Marketing Materials
- [ ] **Logo/branding** (optional) - ASCII art or image
- [ ] **Demo GIF/video** - Show scanner in action
- [ ] **Feature comparison** - vs other tools
- [ ] **Blog post** - Introduction & motivation

### 9.2 Launch Platforms
- [ ] **GitHub release** - Tag v2.0.0 with release notes
- [ ] **PyPI publish** - `pip install breach-ai`
- [ ] **Hacker News** - "Show HN: BREACH - AI Security Scanner"
- [ ] **Reddit** - r/netsec, r/hacking, r/python
- [ ] **Twitter/X** - Announcement thread
- [ ] **LinkedIn** - Professional announcement
- [ ] **Dev.to / Medium** - Technical blog post

### 9.3 SEO & Discoverability
- [ ] **GitHub topics** - Add relevant topics (security, scanner, pentesting)
- [ ] **Description** - Clear, keyword-rich repository description
- [ ] **Social preview** - Custom image for link sharing

---

## 10. Post-Launch

### 10.1 Monitoring
- [ ] **Watch GitHub issues** - Respond within 24-48h
- [ ] **Monitor PyPI downloads** - Track adoption
- [ ] **Track GitHub stars** - Engagement metric
- [ ] **Monitor security reports** - Act on vulnerabilities

### 10.2 Maintenance Plan
- [ ] **Weekly dependency updates** - Review Dependabot PRs
- [ ] **Monthly security audit** - Run security scans
- [ ] **Quarterly releases** - New features, fixes
- [ ] **Annual major review** - Architecture, dependencies

### 10.3 Community Growth
- [ ] **Respond to contributions** - Review PRs promptly
- [ ] **Recognize contributors** - CONTRIBUTORS.md or README
- [ ] **Write good first issues** - Help newcomers
- [ ] **Document internals** - Help contributors understand code

---

## Quick Reference Commands

```bash
# Security scanning
bandit -r src/ -ll                    # Python security
pip-audit                             # Dependency vulnerabilities
gitleaks detect --source . -v         # Secrets in git
trufflehog git file://.               # More secret scanning

# Testing
pip install -e ".[full]"              # Install in dev mode
pytest                                # Run tests
breach doctor                         # Check dependencies

# Building & Publishing
python -m build                       # Build package
twine check dist/*                    # Verify package
twine upload --repository testpypi dist/*  # Test upload
twine upload dist/*                   # Production upload

# Git operations
git tag -s v2.0.0 -m "Release v2.0.0" # Signed tag
git push origin v2.0.0                # Push tag
```

---

## Security Scan Results (Run: 2026-02-13)

### Bandit Findings (Python Security)

| Severity | Issue | Location | Action |
|----------|-------|----------|--------|
| Medium | Permissive chmod 0o755 | autonomous_brain.py:505 | Review - may be intentional |
| Medium | Hardcoded /tmp directory | living_off_the_land.py:115 | Expected - attack payload |
| Medium | XML parsing with ElementTree | saml_destroyer.py:251 | Consider defusedxml |
| Medium | Binding to 0.0.0.0 | ssrf.py:38, config.py:47,287 | Expected - SSRF payloads |
| Medium | Pickle usage | learning_engine.py:213 | Review - potential risk |

**Note:** Most findings are expected for a security testing tool (SSRF payloads, temp files).
Only `saml_destroyer.py` XML parsing and `learning_engine.py` pickle need review.

### Dependency Vulnerabilities (pip-audit)

| Package | Version | CVE | Fix Version | Priority |
|---------|---------|-----|-------------|----------|
| cryptography | 46.0.3 | CVE-2026-26007 | 46.0.5 | High |
| ecdsa | 0.19.1 | CVE-2024-23342 | - | Medium |
| pip | 25.1.1 | CVE-2025-8869, CVE-2026-1703 | 26.0 | Low |
| pyasn1 | 0.6.1 | CVE-2026-23490 | 0.6.2 | Medium |
| python-multipart | 0.0.21 | CVE-2026-24486 | 0.0.22 | Medium |

**Action Required:** Update dependencies before release.

---

## Status Summary

| Category | Status | Notes |
|----------|--------|-------|
| Code Security Audit | ✅ Done | Bandit scan complete, minor issues |
| Repository Security | ✅ Done | Workflows, templates created |
| Documentation | ✅ Done | All docs created |
| CI/CD Pipeline | ✅ Done | test.yml, security.yml, release.yml |
| Package Distribution | ⏳ Pending | Test PyPI upload |
| Community Setup | ✅ Done | Issue templates, PR template |
| Security Policies | ✅ Done | SECURITY.md, CODE_OF_CONDUCT.md |
| Pre-Launch Testing | ⏳ Pending | Full test pass |
| Launch Preparation | ⏳ Pending | Marketing materials |
| Post-Launch Plan | ⏳ Pending | Define process |

---

## Pre-Launch Action Items

1. [ ] **Update vulnerable dependencies**
   ```bash
   pip install --upgrade cryptography pyasn1 python-multipart
   ```

2. [ ] **Review pickle usage** in learning_engine.py - consider safer alternatives

3. [ ] **Use defusedxml** for SAML parsing in saml_destroyer.py

4. [ ] **Test PyPI upload** on TestPyPI

5. [ ] **Create demo video/GIF** for README

---

**Target Launch Date:** _______________

**Launch Owner:** _______________

**Security Reviewer:** _______________
