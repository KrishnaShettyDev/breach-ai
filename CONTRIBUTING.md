# Contributing to BREACH

Thank you for your interest in contributing to BREACH! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** - Search [GitHub Issues](https://github.com/KrishnaShettyDev/breach-ai/issues) to avoid duplicates
2. **Use the bug template** - Fill out all required fields
3. **Include reproduction steps** - Minimal steps to reproduce the issue
4. **Share environment details** - Python version, OS, BREACH version

### Suggesting Features

1. **Check existing discussions** - Your idea may already be proposed
2. **Use the feature template** - Describe the use case clearly
3. **Explain the value** - How does this help security testing?

### Contributing Code

#### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/breach-ai.git
cd breach-ai

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev,full]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Install playwright browsers (for browser-based tests)
playwright install chromium
```

#### Development Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

2. **Make your changes** following our coding standards

3. **Write tests** for new functionality:
   ```bash
   pytest tests/ -v
   ```

4. **Run linting and formatting**:
   ```bash
   ruff check src/
   black src/ tests/
   ```

5. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add GraphQL introspection attack module"
   git commit -m "fix: handle timeout in SSRF validation"
   ```

6. **Push and open a Pull Request**

#### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### Contributing Attack Modules

Attack modules are the core of BREACH. To add a new module:

1. **Create module file** in `src/breach/attacks/`:
   ```python
   # src/breach/attacks/your_attack.py
   from breach.attacks.base import BaseAttackModule, AttackResult

   class YourAttackModule(BaseAttackModule):
       """Description of your attack module."""

       name = "your_attack"
       category = "injection"  # injection, auth, xss, ssrf, etc.

       async def execute(self, target, endpoint) -> list[AttackResult]:
           # Your attack logic here
           pass
   ```

2. **Register in `__init__.py`**

3. **Add tests** in `tests/attacks/test_your_attack.py`

4. **Add recommendations** in `src/breach/recommendations/`

5. **Document** the attack in your PR description

### Pull Request Guidelines

- **One PR per feature/fix** - Keep changes focused
- **Update tests** - All new code needs test coverage
- **Update documentation** - If you change behavior, update docs
- **Pass CI checks** - All tests and linting must pass
- **Request review** - Tag maintainers for review

## Development Guidelines

### Code Style

- **Python 3.11+** features are welcome
- **Type hints** for all function signatures
- **Docstrings** for public functions and classes
- **100 character** line limit
- **Use async/await** for I/O operations

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=breach --cov-report=html

# Run specific test file
pytest tests/test_cli.py -v

# Run tests matching pattern
pytest tests/ -k "sqli" -v
```

### Security Considerations

When contributing attack modules:

1. **Never include real credentials** or sensitive data
2. **Use safe payloads** that prove exploitability without damage
3. **Respect rate limits** and implement delays
4. **Document risks** in the module docstring
5. **Test against authorized targets only** (use OWASP WebGoat, DVWA, etc.)

## Project Structure

```
breach/
├── src/breach/
│   ├── attacks/        # Attack modules (SQLi, XSS, SSRF, etc.)
│   ├── recon/          # Reconnaissance modules
│   ├── exploitation/   # Exploitation validation
│   ├── phases/         # 4-phase workflow
│   ├── workflow/       # Orchestration engine
│   ├── output/         # Report formatters
│   ├── recommendations/# Fix recommendations
│   ├── ai/             # AI integration
│   └── cli.py          # CLI entry point
├── tests/              # Test suite
├── configs/            # Example configurations
└── docs/               # Documentation
```

## Getting Help

- **GitHub Issues** - For bugs and feature requests
- **GitHub Discussions** - For questions and ideas
- **Security Issues** - See [SECURITY.md](SECURITY.md)

## Recognition

Contributors are recognized in:
- GitHub Contributors page
- Release notes for significant contributions
- README acknowledgments for major features

Thank you for helping make BREACH better!
