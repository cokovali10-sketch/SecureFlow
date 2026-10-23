"""Secrets scanner — detects hardcoded secrets, API keys, tokens, and credentials.

Uses pattern matching (regex) to find potential secrets in source code.
This is the built-in scanner; for production use, integrate Gitleaks or TruffleHog.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from secureflow.findings.models import ScannerType
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry


# Pattern definitions: (rule_id, severity, confidence, title, description, regex, remediation)
SECRET_PATTERNS: list[tuple[str, str, str, str, str, str, str]] = [
    (
        "hardcoded-aws-access-key",
        "high",
        "high",
        "AWS Access Key",
        "Hardcoded AWS access key detected",
        r"(?:^|[^A-Za-z0-9/+=])(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}(?:[^A-Za-z0-9/+=]|$)",
        "Use environment variables or AWS IAM roles instead of hardcoded keys.",
    ),
    (
        "hardcoded-aws-secret-key",
        "high",
        "medium",
        "AWS Secret Key",
        "Potential AWS secret key detected",
        r"(?i)(?:aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        "Use environment variables or AWS IAM roles instead of hardcoded keys.",
    ),
    (
        "hardcoded-api-key",
        "high",
        "medium",
        "Hardcoded API Key",
        "Potential hardcoded API key detected",
        r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?",
        "Store API keys in environment variables or a secrets manager.",
    ),
    (
        "generic-secret",
        "high",
        "medium",
        "Hardcoded Secret",
        "Potential hardcoded secret or password detected",
        r"(?i)(?:password|passwd|pwd|secret|token|auth[_\-]?token|access[_\-]?token|private[_\-]?key)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?",
        "Use environment variables or a secrets manager for sensitive values.",
    ),
    (
        "private-key-header",
        "critical",
        "high",
        "Private Key",
        "Private key header detected",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Never commit private keys. Add them to .gitignore and use a secrets manager.",
    ),
    (
        "hardcoded-jwt",
        "high",
        "medium",
        "Hardcoded JWT",
        "Potential hardcoded JWT token detected",
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
        "Store JWT secrets in environment variables, not in code.",
    ),
    (
        "hardcoded-password-assignment",
        "high",
        "high",
        "Password Assignment",
        "Direct password assignment in code",
        r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",
        "Never hardcode passwords. Use environment variables or a vault.",
    ),
    (
        "connection-string",
        "high",
        "medium",
        "Database Connection String",
        "Potential database connection string with credentials",
        r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s]+:[^\s]+@[^\s]+",
        "Store connection strings in environment variables, not in code.",
    ),
    (
        "hardcoded-ip-port",
        "medium",
        "low",
        "Hardcoded IP:Port",
        "Hardcoded internal IP address with port",
        r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}:\d{1,5}\b",
        "Avoid hardcoding internal IPs. Use configuration files or environment variables.",
    ),
    (
        "slack-webhook",
        "high",
        "high",
        "Slack Webhook URL",
        "Slack webhook URL detected",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "Store Slack webhook URLs in environment variables.",
    ),
    (
        "github-token",
        "high",
        "high",
        "GitHub Token",
        "Potential GitHub personal access token detected",
        r"ghp_[A-Za-z0-9]{36}",
        "Use GitHub Actions secrets or environment variables for tokens.",
    ),
    (
        "github-fine-grained-token",
        "high",
        "high",
        "GitHub Fine-Grained Token",
        "Potential GitHub fine-grained token detected",
        r"github_pat_[A-Za-z0-9_]{82}",
        "Use GitHub Actions secrets or environment variables for tokens.",
    ),
]


@ScannerRegistry.register
class SecretsScanner(ScannerBase):
    """Scanner for hardcoded secrets and credentials."""

    scanner_type = ScannerType.SECRETS
    name = "secrets"
    description = "Detects hardcoded secrets, API keys, tokens, and credentials"

    def scan(self, target: Path, options: dict[str, Any] | None = None) -> list:
        """Scan target for hardcoded secrets."""
        from secureflow.findings.models import Finding

        target = self._validate_target(target)
        findings: list[Finding] = []

        files_to_scan = self._get_source_files(target)
        exclude_dirs = set(self.config.extra_args) if self.config.extra_args else set()

        for file_path in files_to_scan:
            if self._should_exclude(file_path, exclude_dirs):
                continue
            try:
                file_findings = self._scan_file(file_path, target)
                findings.extend(file_findings)
            except Exception as e:
                logger.warning("Failed to scan %s: %s", file_path, e)

        return findings

    def _get_source_files(self, target: Path) -> list[Path]:
        """Get all source files to scan."""
        if target.is_file():
            return [target]

        extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
            ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp", ".sh",
            ".bash", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
            ".conf", ".env", ".config", ".xml", ".sql", ".gradle",
            ".tf", ".hcl", ".dockerfile", ".md",
        }

        files: list[Path] = []
        for path in target.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                files.append(path)
        return files

    def _should_exclude(self, path: Path, extra_exclude: set[str]) -> bool:
        """Check if path should be excluded."""
        blocked = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        }
        blocked.update(extra_exclude)

        for part in path.parts:
            if part in blocked:
                return True
        return False

    def _scan_file(self, file_path: Path, root: Path) -> list:
        """Scan a single file for secrets."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return findings

        lines = content.splitlines()
        relative_path = str(file_path.relative_to(root)).replace("\\", "/")

        for line_num, line in enumerate(lines, start=1):
            for rule_id, severity, confidence, title, desc, pattern, remediation in SECRET_PATTERNS:
                if re.search(pattern, line):
                    finding = self._make_finding(
                        rule=rule_id,
                        severity=severity,
                        confidence=confidence,
                        title=title,
                        description=desc,
                        file_path=relative_path,
                        line=line_num,
                        evidence=line.strip()[:200],
                        remediation=remediation,
                        metadata={"file_size": file_path.stat().st_size},
                        tags=["secret", "credential"],
                    )
                    findings.append(finding)

        return findings


import logging

logger = logging.getLogger(__name__)
