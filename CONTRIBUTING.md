# Contributing Guide

Thank you for considering contributing to the Cyber Risk Intelligence & Adaptive Defense Platform!

## Getting Started

1. **Fork** the repository and clone your fork
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Set up your development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Project Structure

Each module lives in `src/<module>/`. When adding a new detection technique or rule:
- Add ML models to `src/detection/`
- Add privacy rules to `src/privacy/privacy_monitor.py`
- Add defense actions to `src/advisor/defense_advisor.py`

## Running Tests

```bash
pytest tests/ -v --cov=src
```

All PRs must pass the full test suite.

## Coding Standards

- Follow PEP 8
- Use type hints for all function signatures
- Add docstrings to all classes and public methods
- Keep modules focused — one responsibility per file

## Submitting a PR

1. Ensure tests pass locally
2. Update `docs/architecture.md` if you add a new module
3. Add test coverage for new functionality
4. Open a PR with a clear description of what changes and why

## Reporting Issues

Use the GitHub Issues tab. Include:
- Python version
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output
