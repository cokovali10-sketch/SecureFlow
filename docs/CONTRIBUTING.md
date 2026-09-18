# Contributing

## Development Setup

```bash
# Clone
git clone https://github.com/cokovali10-sketch/SecureFlow.git
cd SecureFlow

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check .
ruff format .
```

## Code Style

- Python 3.12+
- Type hints required
- Ruff for linting/formatting
- Maximum line length: 100

## Adding a Scanner

1. Create directory `secureflow/scanners/my_scanner/`
2. Implement `ScannerBase` subclass
3. Register with `@ScannerRegistry.register`
4. Add tests in `tests/unit/test_my_scanner.py`
5. Register in `Config.scanners`

## Testing

- Unit tests in `tests/unit/`
- Integration tests in `tests/integration/`
- Test fixtures in `tests/fixtures/`
- Aim for meaningful coverage, not just high percentage

## Pull Requests

1. Create feature branch
2. Write tests for new functionality
3. Ensure all tests pass
4. Update documentation if needed
5. Submit PR with clear description
