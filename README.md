# SecureFlow

> Security platform for analyzing software projects and CI/CD pipelines

[![CI](https://github.com/cokovali10-sketch/SecureFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/cokovali10-sketch/SecureFlow/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is SecureFlow?

SecureFlow is a security platform that detects vulnerabilities early — before insecure code reaches production. It combines multiple security scanners into a unified system with consistent findings, risk scoring, and policy gates.

## Features

- **Secrets Detection** — Hardcoded API keys, tokens, passwords, private keys
- **SAST** — Static analysis for dangerous code patterns (Bandit integration)
- **SCA** — Dependency vulnerability scanning (pip-audit, OSV)
- **Container Security** — Dockerfile analysis, Docker Compose checks, Trivy integration
- **Risk Engine** — Severity × confidence scoring, letter grades, pass/fail gates
- **CLI** — `secureflow scan ./project` with JSON and human-readable output
- **API** — FastAPI REST API for integration with CI/CD pipelines
- **Deduplication** — Fingerprint-based finding deduplication
- **Policy Gates** — Fail CI/CD on critical/high findings

## Quick Start

### Installation

```bash
pip install -e .
```

### First Scan

```bash
# Scan a project
secureflow scan ./my-project

# JSON output
secureflow scan ./my-project --output json

# Specific scanners
secureflow scan ./my-project --scanners secrets sast

# Fail on high severity
secureflow scan ./my-project --fail-on high
```

### Check Dependencies

```bash
secureflow doctor
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `secureflow scan <target>` | Scan a project for security issues |
| `secureflow scanners` | List available scanners |
| `secureflow doctor` | Check system dependencies |
| `secureflow version` | Show version |

## API

```bash
# Start API server
uvicorn secureflow.api.app:app --host 0.0.0.0 --port 8000

# Health check
curl http://localhost:8000/api/health

# Run scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "/path/to/project"}'
```

## Docker

```bash
docker build -t secureflow .
docker run -v ./my-project:/scan-targets:ro secureflow scan /scan-targets
```

## Configuration

Create `secureflow.toml`:

```toml
[scanners]
secrets.enabled = true
sast.enabled = true
sca.enabled = true
containers.enabled = false

[risk]
critical_weight = 10.0
high_weight = 7.0
medium_weight = 4.0
low_weight = 1.0
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=secureflow --cov-report=term-missing

# Lint
ruff check .
ruff format .
```

## Architecture

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## Security

See [SECURITY.md](docs/SECURITY.md) for security policy and threat model.

## License

MIT
