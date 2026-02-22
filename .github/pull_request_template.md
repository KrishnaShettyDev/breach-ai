## Description

<!-- Describe your changes in detail -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New attack module
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)

## Related Issues

<!-- Link any related issues here -->
Fixes #

## How Has This Been Tested?

<!-- Describe how you tested your changes -->

- [ ] Unit tests pass (`pytest tests/ -v`)
- [ ] Linting passes (`ruff check src/`)
- [ ] Tested manually against [target]

## Attack Module Checklist (if applicable)

- [ ] Module follows `BaseAttackModule` interface
- [ ] Module registered in `__init__.py`
- [ ] Tests added in `tests/attacks/`
- [ ] Recommendations added in `recommendations/`
- [ ] Safe payloads used (no destructive actions)
- [ ] Documentation updated

## General Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have added tests that prove my fix/feature works
- [ ] I have updated documentation as needed
- [ ] I have added type hints to new functions
- [ ] All new and existing tests pass
