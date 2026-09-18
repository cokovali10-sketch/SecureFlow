# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in SecureFlow, please report it responsibly:

1. **Email**: cokovali10@gmail.com
2. **GitHub Issues**: For non-security bugs only

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Controls

### SecureFlow's Own Security

SecureFlow is a security tool and must itself be secure:

- **No shell injection**: All subprocess calls use `shell=False` with argument lists
- **Path traversal protection**: All file paths validated and resolved
- **Input validation**: Pydantic models validate all inputs
- **No hardcoded secrets**: SecureFlow never hardcodes credentials
- **Safe logging**: Secrets in scanned code are never logged
- **Least privilege**: Runs as non-root in Docker

### Data Handling

- Scan targets are read-only
- Findings are stored locally (SQLite)
- No data sent externally unless explicitly configured
- Temporary files cleaned up after scan

### Dependency Security

- Dependencies pinned in pyproject.toml
- Regular dependency updates
- Security audit via `bandit` and `pip-audit`

## Known Limitations

- Secrets scanner uses regex patterns (may have false positives/negatives)
- SAST built-in checks are limited (Bandit recommended for full coverage)
- Container scanning requires Trivy for image vulnerability scanning
- No authentication on API by default (add middleware for production)

## Threat Model

See [THREAT_MODEL.md](THREAT_MODEL.md) for complete threat model.
