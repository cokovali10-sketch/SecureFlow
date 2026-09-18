"""SAST scanner — static application security testing.

Wraps Bandit for Python code analysis. Falls back to built-in checks
if Bandit is not installed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, ClassVar

from secureflow.findings.models import ScannerType
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry, ScanError


BANDIT_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "UNDEFINED": "info",
}

BANDIT_CONFIDENCE_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "UNDEFINED": "low",
}


@ScannerRegistry.register
class SastScanner(ScannerBase):
    """SAST scanner using Bandit for Python code."""

    scanner_type = ScannerType.SAST
    name = "sast"
    description = "Static application security testing (Bandit for Python)"

    def is_available(self) -> bool:
        """Check if Bandit is installed."""
        return shutil.which("bandit") is not None

    def scan(self, target: Path, options: dict[str, Any] | None = None) -> list:
        """Run Bandit SAST scan."""
        from secureflow.findings.models import Finding

        target = self._validate_target(target)
        findings: list[Finding] = []

        if not self.is_available():
            logger.warning("Bandit not installed, using built-in SAST checks")
            return self._builtin_scan(target)

        try:
            findings = self._run_bandit(target)
        except ScanError as e:
            logger.warning("Bandit scan failed: %s, falling back to built-in", e)
            findings = self._builtin_scan(target)

        return findings

    def _run_bandit(self, target: Path) -> list:
        """Execute Bandit and parse results."""
        from secureflow.findings.models import Confidence, Location, Severity

        output_file = target / ".secureflow_bandit.json"

        cmd = [
            "bandit",
            "-r", str(target),
            "-f", "json",
            "-o", str(output_file),
            "--severity-level", "low",
            "--confidence-level", "low",
        ]
        cmd.extend(self.config.extra_args)

        result = self._run_subprocess(cmd, cwd=target)

        if not output_file.exists():
            return []

        try:
            data = json.loads(output_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        finally:
            output_file.unlink(missing_ok=True)

        findings = []
        for issue in data.get("results", []):
            severity = BANDIT_SEVERITY_MAP.get(issue.get("issue_severity", ""), "info")
            confidence = BANDIT_CONFIDENCE_MAP.get(issue.get("issue_confidence", ""), "low")

            finding = self._make_finding(
                rule=issue.get("test_id", "unknown"),
                severity=severity,
                confidence=confidence,
                title=issue.get("issue_text", "Bandit finding"),
                description=issue.get("issue_text", ""),
                file_path=issue.get("filename", ""),
                line=issue.get("line_number", 0),
                evidence=issue.get("code", "")[:200],
                remediation=issue.get("more_info", ""),
                metadata={
                    "test_name": issue.get("test_name", ""),
                    "test_node": issue.get("test_node", ""),
                },
                tags=["sast", "bandit"],
            )
            findings.append(finding)

        return findings

    def _builtin_scan(self, target: Path) -> list:
        """Built-in basic SAST checks when Bandit is not available."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        dangerous_patterns = [
            (
                "eval-usage",
                "high",
                "high",
                "Use of eval()",
                "eval() can execute arbitrary code",
                r"\beval\s*\(",
                "Avoid eval(). Use ast.literal_eval() for data parsing.",
            ),
            (
                "exec-usage",
                "critical",
                "high",
                "Use of exec()",
                "exec() can execute arbitrary code",
                r"\bexec\s*\(",
                "Avoid exec(). Use subprocess with proper argument handling.",
            ),
            (
                "subprocess-shell-true",
                "high",
                "high",
                "Subprocess with shell=True",
                "subprocess with shell=True enables command injection",
                r"subprocess\.\w+\([^)]*shell\s*=\s*True",
                "Use shell=False and pass arguments as a list.",
            ),
            (
                "pickle-usage",
                "medium",
                "medium",
                "Use of pickle",
                "pickle.load() can execute arbitrary code",
                r"\bpickle\.load(?:s)?\s*\(",
                "Avoid unpickling untrusted data. Use JSON instead.",
            ),
            (
                "yaml-load-unsafe",
                "high",
                "high",
                "Unsafe YAML loading",
                "yaml.load() without Loader can execute arbitrary code",
                r"yaml\.load\s*\([^)]*\)",
                "Use yaml.safe_load() instead of yaml.load().",
            ),
            (
                "hardcoded-tmp-path",
                "low",
                "medium",
                "Hardcoded temp path",
                "Using hardcoded /tmp path",
                r"['\"]/(?:tmp|var/tmp)/",
                "Use tempfile.mkdtemp() for secure temporary directories.",
            ),
            (
                "assert-in-production",
                "low",
                "low",
                "Assert in code",
                "assert statements can be disabled with -O flag",
                r"^\s*assert\s+",
                "Don't rely on assert for security checks. Use proper validation.",
            ),
            (
                "md5-usage",
                "medium",
                "medium",
                "MD5 hash usage",
                "MD5 is cryptographically broken",
                r"\bhashlib\.md5\s*\(",
                "Use SHA-256 or stronger for security-sensitive hashing.",
            ),
            (
                "insecure-random",
                "medium",
                "medium",
                "Insecure random number generator",
                "random module is not cryptographically secure",
                r"\brandom\.(?:random|randint|choice|shuffle)\s*\(",
                "Use secrets module for cryptographic randomness.",
            ),
            (
                "debug-true",
                "medium",
                "medium",
                "Debug mode enabled",
                "DEBUG=True in code",
                r"DEBUG\s*=\s*True",
                "Disable debug mode in production.",
            ),
        ]

        python_files = list(target.rglob("*.py"))
        for py_file in python_files:
            if self._should_exclude_file(py_file):
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            lines = content.splitlines()
            relative_path = str(py_file.relative_to(target)).replace("\\", "/")

            for line_num, line in enumerate(lines, start=1):
                for rule_id, severity, conf, title, desc, pattern, remediation in dangerous_patterns:
                    import re
                    if re.search(pattern, line):
                        finding = self._make_finding(
                            rule=rule_id,
                            severity=severity,
                            confidence=conf,
                            title=title,
                            description=desc,
                            file_path=relative_path,
                            line=line_num,
                            evidence=line.strip()[:200],
                            remediation=remediation,
                            tags=["sast", "builtin"],
                        )
                        findings.append(finding)

        return findings

    def _should_exclude_file(self, path: Path) -> bool:
        blocked = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
        for part in path.parts:
            if part in blocked:
                return True
        return False


import logging

logger = logging.getLogger(__name__)
