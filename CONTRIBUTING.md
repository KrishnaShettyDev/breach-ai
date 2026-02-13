# Contributing to BREACH

Thank you for your interest in contributing to BREACH! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/yourusername/breach/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with:
   - Clear description of the feature
   - Use case / motivation
   - Proposed implementation (optional)

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Write/update tests as needed
5. Ensure all tests pass: `pytest`
6. Commit with clear messages
7. Push and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/breach.git
cd breach

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode with all dependencies
pip install -e ".[full]"

# Run tests
pytest

# Run linting
ruff check src/
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions focused and small

## Adding Attack Modules

New attack modules should:

1. Inherit from `BaseAttack` or `InjectionAttack`
2. Implement required methods: `check()`, `exploit()`, `get_payloads()`
3. Include proper OWASP/CWE references
4. Add tests for the module

Example structure:
```python
from breach.attacks.base import BaseAttack, AttackResult

class MyNewAttack(BaseAttack):
    name = "My Attack"
    attack_type = "my_attack"
    description = "Description of what this tests"
    owasp_category = "A01:2021"
    cwe_id = 123

    async def check(self, url, parameter=None, method="GET", **kwargs) -> bool:
        # Quick vulnerability check
        pass

    async def exploit(self, url, parameter=None, method="GET", **kwargs) -> AttackResult:
        # Full exploitation
        pass

    def get_payloads(self) -> list[str]:
        return ["payload1", "payload2"]
```

## Testing

- Write tests for new features
- Ensure existing tests pass
- Use pytest fixtures for common setups

## Questions?

Open an issue or reach out to the maintainers.

Thank you for contributing!
