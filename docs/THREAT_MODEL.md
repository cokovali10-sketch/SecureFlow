# Threat Model — SecureFlow

## Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Source code | Code being scanned | High — may contain secrets, proprietary logic |
| Scan results | Findings, vulnerability data | Medium — reveals security posture |
| Dependencies | Project dependency lists | Medium — reveals attack surface |
| Configuration | SecureFlow config files | Low-Medium — may contain scan paths |
| API endpoints | REST API surface | Medium — potential for abuse |

## Trust Boundaries

```
┌─────────────────────────────────────────────┐
│              User's Machine                  │
│                                              │
│  ┌──────────┐    ┌───────────────────────┐  │
│  │  User /   │───▶│     SecureFlow        │  │
│  │  CI/CD    │    │  (CLI / API)          │  │
│  └──────────┘    └───────────┬───────────┘  │
│                              │               │
│                    ┌─────────▼─────────┐    │
│                    │  External Tools   │    │
│                    │  Bandit, Trivy,   │    │
│                    │  pip-audit        │    │
│                    └───────────────────┘    │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │         File System                  │   │
│  │    (scan targets, temp files)        │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| Malicious contributor | Inject secrets/backdoors into scanned projects | Code access |
| Attacker exploiting API | Command injection, path traversal, SSRF | Network access |
| Supply chain attacker | Compromise scanner dependencies | Package publishing |
| Insider threat | Exfiltrate scan results, source code | Legitimate access |

## Attack Surface

### 1. User Input
- **CLI arguments**: Target paths, scanner selections
- **API requests**: JSON payloads with scan targets
- **Config files**: YAML/TOML configuration

### 2. External Scanner Execution
- **Bandit**: Subprocess execution for SAST
- **Trivy**: Subprocess execution for container scanning
- **pip-audit**: Subprocess execution for dependency scanning

### 3. File System Access
- Reading source files for scanning
- Writing temporary files (DB, scan outputs)
- Storing scan results

### 4. Network (API mode)
- HTTP requests to FastAPI endpoints
- CORS configuration
- No authentication by default

## Threats & Mitigations

### T1: Command Injection via Scanner Arguments
- **Threat**: Attacker crafts input that injects shell commands
- **Impact**: Remote code execution
- **Mitigation**:
  - All subprocess calls use `shell=False`
  - Arguments validated and sanitized
  - Command allowlisting in scanner base
  - No user input passed directly to shell

### T2: Path Traversal
- **Threat**: Attacker specifies paths outside allowed directories
- **Impact**: Unauthorized file access
- **Mitigation**:
  - All paths resolved via `Path.resolve()`
  - Target validation against allowed roots
  - Blocked paths list (.git, .env, etc.)

### T3: SSRF via API
- **Threat**: Attacker makes API scan remote URLs
- **Impact**: Internal network scanning
- **Mitigation**:
  - API accepts local paths only
  - No URL-based scan targets
  - Path existence validation

### T4: Secret Leakage in Reports
- **Threat**: Scanned secrets appear in logs/reports
- **Impact**: Credential exposure
- **Mitigation**:
  - Evidence truncated to 200 chars
  - Secrets not logged
  - Sanitized output mode available

### T5: Malicious Scan Targets
- **Threat**: Attacker provides crafted files that exploit scanner parsers
- **Impact**: Code execution via parser vulnerability
- **Mitigation**:
  - File size limits (50MB)
  - Scan depth limits (20 levels)
  - Timeout enforcement
  - Scanner failures caught and logged

### T6: Dependency Confusion
- **Threat**: Attacker publishes malicious package with same name as internal
- **Impact**: Code execution during install
- **Mitigation**:
  - Dependencies pinned
  - SCA scanning of requirements
  - No automatic package installation

### T7: API Abuse / DoS
- **Threat**: Attacker floods API with scan requests
- **Impact**: Resource exhaustion
- **Mitigation**:
  - Scan timeout limits
  - File size limits
  - Rate limiting (recommended for production)

### T8: Insecure Deserialization
- **Threat**: Attacker crafts malicious JSON/YAML input
- **Impact**: Code execution
- **Mitigation**:
  - Pydantic validation on all inputs
  - `yaml.safe_load()` used (not `yaml.load()`)
  - No pickle deserialization of user input

## Security Assumptions

1. The machine running SecureFlow is trusted
2. External scanners (Bandit, Trivy) are from trusted sources
3. File system permissions are properly configured
4. Network access is restricted in production

## Residual Risks

- Regex-based secrets detection may miss novel patterns
- Built-in SAST checks are limited compared to full Bandit
- API has no authentication by default
- Container image scanning requires Trivy binary
