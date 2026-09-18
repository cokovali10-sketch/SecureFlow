# Architecture

## Overview

SecureFlow is a modular monolith with a plugin-based scanner architecture. All security findings are normalized into a unified format, enabling consistent risk scoring and reporting.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI / API Layer                       │
│  secureflow scan ./project  │  FastAPI REST endpoints   │
└──────────────┬──────────────┴──────────────┬────────────┘
               │                             │
               ▼                             ▼
┌─────────────────────────────────────────────────────────┐
│                  Scan Orchestrator                       │
│  Coordinates scanners, deduplicates, manages lifecycle  │
└──────────────────────────┬──────────────────────────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
        ┌────────────┐ ┌────────┐ ┌────────┐ ┌──────────┐
        │  Secrets   │ │  SAST  │ │  SCA   │ │Container │
        │  Scanner   │ │Scanner │ │Scanner │ │ Scanner  │
        │ (built-in) │ │(Bandit)│ │(pip-   │ │ (Docker- │
        │            │ │        │ │ audit) │ │  file)   │
        └─────┬──────┘ └───┬────┘ └───┬────┘ └────┬─────┘
              │            │          │            │
              └────────────┼──────────┼────────────┘
                           ▼          ▼
                    ┌──────────────────────┐
                    │   Findings Model     │
                    │  (unified format)    │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │    Risk Engine       │
                    │  scoring + grading   │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │      Reports         │
                    │  JSON / Human / HTML │
                    └──────────────────────┘
```

## Core Components

### Findings Model (`secureflow/findings/models.py`)

The central data model. Every scanner produces `Finding` objects with:
- Severity (critical/high/medium/low/info)
- Confidence (high/medium/low)
- Location (file, line, column)
- Fingerprint (for deduplication)
- Status lifecycle (open → confirmed → resolved/suppressed/false_positive)

### Scanner Framework (`secureflow/scanners/base/scanner.py`)

Plugin architecture:
- `ScannerBase` — abstract base class all scanners implement
- `ScannerRegistry` — auto-registration via `@ScannerRegistry.register` decorator
- `ScannerConfig` — per-scanner configuration (enabled, timeout, extra_args)

### Risk Engine (`secureflow/risk/engine.py`)

Calculates risk scores:
- `score = 100 - Σ(severity_weight × confidence_weight)`
- Letter grades: A (90+), B (75+), C (60+), D (40+), F (<40)
- Pass/fail for CI/CD gates

### Scan Orchestrator (`secureflow/scanners/orchestrator.py`)

Coordinates the scan pipeline:
1. Resolve target path
2. Run enabled scanners in sequence
3. Collect findings
4. Deduplicate by fingerprint
5. Return unified `ScanResult`

## Scanner Types

| Scanner | Purpose | Tool |
|---------|---------|------|
| `secrets` | Hardcoded credentials | Built-in regex patterns |
| `sast` | Code vulnerability patterns | Bandit / built-in |
| `sca` | Dependency vulnerabilities | pip-audit / OSV / built-in |
| `containers` | Dockerfile/container security | Built-in + Trivy |

## Security Design

### Input Validation
- All file paths resolved and validated against allowed roots
- Pydantic models for all API inputs
- Parameterized database queries (SQLAlchemy)

### Subprocess Safety
- Shell=False for all subprocess calls
- Command allowlisting
- Timeout enforcement
- Output size limits

### Data Handling
- Findings sanitized before display
- Secrets in scanned code never logged
- Temporary files cleaned up after scan

## Adding a New Scanner

1. Create `secureflow/scanners/my_scanner/scanner.py`
2. Subclass `ScannerBase`
3. Decorate with `@ScannerRegistry.register`
4. Implement `scan(target, options) -> list[Finding]`
5. Register in `Config.scanners`

```python
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry
from secureflow.findings.models import ScannerType

@ScannerRegistry.register
class MyScanner(ScannerBase):
    scanner_type = ScannerType.CUSTOM
    name = "my_scanner"
    description = "My custom scanner"

    def scan(self, target, options=None):
        findings = []
        # Your scanning logic here
        return findings
```
