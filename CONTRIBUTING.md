# Contributing to BREACH

Thanks for your interest in contributing!

## How to Contribute

1. Fork the repo
2. Create a branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/KrishnaShettyDev/breach-ai.git
cd breach-ai
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Code Style

- Use `ruff` for linting
- Keep it simple
- No over-engineering

## Adding Attack Modules

New modules go in `src/breach/attacks/`. See existing modules for examples.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior
- Actual behavior

## Security Issues

For security vulnerabilities, email krishnashettydev@gmail.com instead of opening a public issue.
