"""SCA scanner — software composition analysis for dependency vulnerabilities.

Detects known vulnerabilities in project dependencies using pip-audit,
OSV database, or built-in requirements parsing.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from secureflow.findings.models import ScannerType
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry, ScanError


# Known vulnerable packages (subset for built-in detection)
KNOWN_VULNERABLE: dict[str, dict[str, str]] = {
    "django": {"<4.2.0": "CVE-2023-31047: File upload validation bypass"},
    "flask": {"<2.3.0": "CVE-2023-30861: Session cookie handling"},
    "requests": {"<2.31.0": "CVE-2023-32681: Leak of Proxy-Authorization header"},
    "pillow": {"<10.0.0": "CVE-2023-44271: DoS via large images"},
    "cryptography": {"<41.0.0": "CVE-2023-38325: PKCS12 serialization"},
    "pyjwt": {"<2.8.0": "CVE-2022-29217: Algorithm confusion"},
    "aiohttp": {"<3.9.0": "CVE-2023-49082: HTTP request smuggling"},
    "jinja2": {"<3.1.3": "CVE-2024-22195: XSS in xmlattr filter"},
    "werkzeug": {"<3.0.0": "CVE-2023-46136: DoS via multipart parsing"},
    "gunicorn": {"<22.0.0": "CVE-2024-1135: HTTP request smuggling"},
    "urllib3": {"<2.0.7": "CVE-2023-45803: Request body not stripped on redirect"},
    "certifi": {"<2023.7.22": "CVE-2023-37920: Removal of e-Tugra root CA"},
    "setuptools": {"<70.0.0": "CVE-2024-6345: Remote code execution via download functions"},
    "pip": {"<23.3.1": "CVE-2023-5752: Arbitrary code execution via wheel filename"},
}


@ScannerRegistry.register
class ScaScanner(ScannerBase):
    """SCA scanner for dependency vulnerabilities."""

    scanner_type = ScannerType.SCA
    name = "sca"
    description = "Software composition analysis for dependency vulnerabilities"

    def is_available(self) -> bool:
        """SCA scanner always available (built-in + optional pip-audit)."""
        return True

    def scan(self, target: Path, options: dict[str, Any] | None = None) -> list:
        """Scan dependencies for known vulnerabilities."""
        from secureflow.findings.models import Finding

        target = self._validate_target(target)
        findings: list[Finding] = []

        findings.extend(self._scan_requirements(target))
        findings.extend(self._scan_pyproject(target))
        findings.extend(self._scan_package_json(target))

        if shutil.which("pip-audit"):
            findings.extend(self._run_pip_audit(target))

        return findings

    def _scan_requirements(self, target: Path) -> list:
        """Parse requirements.txt files for vulnerable packages."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []
        req_files = list(target.rglob("requirements*.txt"))

        for req_file in req_files:
            if self._should_exclude(req_file):
                continue

            try:
                content = req_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            relative_path = str(req_file.relative_to(target)).replace("\\", "/")

            for line_num, line in enumerate(content.splitlines(), start=1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                pkg_name, version = self._parse_requirement(line)
                if not pkg_name:
                    continue

                vuln = self._check_vulnerability(pkg_name, version)
                if vuln:
                    finding = self._make_finding(
                        rule=f"vulnerable-dependency-{pkg_name}",
                        severity="high",
                        confidence="high",
                        title=f"Vulnerable dependency: {pkg_name}",
                        description=vuln,
                        file_path=relative_path,
                        line=line_num,
                        evidence=line,
                        remediation=f"Upgrade {pkg_name} to the latest secure version.",
                        metadata={"package": pkg_name, "version": version or "unknown"},
                        tags=["sca", "dependency", "vulnerability"],
                    )
                    findings.append(finding)

        return findings

    def _scan_pyproject(self, target: Path) -> list:
        """Parse pyproject.toml for dependencies."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []
        pyproject = target / "pyproject.toml"

        if not pyproject.exists():
            return findings

        try:
            import tomllib
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            return findings

        deps = data.get("project", {}).get("dependencies", [])
        for i, dep in enumerate(deps):
            pkg_name, version = self._parse_requirement(dep)
            if not pkg_name:
                continue

            vuln = self._check_vulnerability(pkg_name, version)
            if vuln:
                finding = self._make_finding(
                    rule=f"vulnerable-dependency-{pkg_name}",
                    severity="high",
                    confidence="high",
                    title=f"Vulnerable dependency: {pkg_name}",
                    description=vuln,
                    file_path="pyproject.toml",
                    line=i + 1,
                    evidence=dep,
                    remediation=f"Upgrade {pkg_name} to the latest secure version.",
                    metadata={"package": pkg_name, "version": version or "unknown"},
                    tags=["sca", "dependency", "vulnerability"],
                )
                findings.append(finding)

        return findings

    def _scan_package_json(self, target: Path) -> list:
        """Parse package.json for vulnerable npm dependencies."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        for pkg_file in target.rglob("package.json"):
            if self._should_exclude(pkg_file):
                continue

            try:
                data = json.loads(pkg_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            relative_path = str(pkg_file.relative_to(target)).replace("\\", "/")

            for pkg_name, version_spec in all_deps.items():
                version = re.sub(r"[^0-9.]", "", str(version_spec))
                vuln = self._check_vulnerability_npm(pkg_name, version)
                if vuln:
                    finding = self._make_finding(
                        rule=f"vulnerable-npm-{pkg_name}",
                        severity="high",
                        confidence="medium",
                        title=f"Vulnerable npm package: {pkg_name}",
                        description=vuln,
                        file_path=relative_path,
                        evidence=f"{pkg_name}: {version_spec}",
                        remediation=f"Upgrade {pkg_name} to a patched version.",
                        metadata={"package": pkg_name, "version": version, "ecosystem": "npm"},
                        tags=["sca", "dependency", "npm", "vulnerability"],
                    )
                    findings.append(finding)

        return findings

    def _run_pip_audit(self, target: Path) -> list:
        """Run pip-audit for comprehensive Python vulnerability scanning."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []
        req_files = list(target.rglob("requirements*.txt"))

        for req_file in req_files:
            if self._should_exclude(req_file):
                continue

            cmd = ["pip-audit", "-r", str(req_file), "--format", "json"]
            try:
                result = self._run_subprocess(cmd)
                if result.returncode == 0 or result.stdout:
                    data = json.loads(result.stdout)
                    for vuln in data.get("dependencies", []):
                        if vuln.get("vulns"):
                            for v in vuln["vulns"]:
                                finding = self._make_finding(
                                    rule=f"pip-audit-{vuln['name']}",
                                    severity="high",
                                    confidence="high",
                                    title=f"Vulnerable package: {vuln['name']}",
                                    description=v.get("description", v.get("id", "")),
                                    file_path=str(req_file.relative_to(target)).replace("\\", "/"),
                                    evidence=f"{vuln['name']}=={vuln.get('version', '?')}",
                                    remediation=f"Upgrade {vuln['name']} to a patched version.",
                                    metadata={
                                        "package": vuln["name"],
                                        "version": vuln.get("version", ""),
                                        "vuln_id": v.get("id", ""),
                                        "fix_versions": v.get("fix_versions", []),
                                    },
                                    tags=["sca", "pip-audit", "vulnerability"],
                                )
                                findings.append(finding)
            except ScanError:
                continue

        return findings

    def _parse_requirement(self, line: str) -> tuple[str, str]:
        """Parse a requirement line into (name, version)."""
        line = line.strip()
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*[=><~!]+\s*([0-9.+a-zA-Z-]*)", line)
        if match:
            return match.group(1).lower(), match.group(2)
        match = re.match(r"^([a-zA-Z0-9_-]+)", line)
        if match:
            return match.group(1).lower(), ""
        return "", ""

    def _check_vulnerability(self, pkg_name: str, version: str) -> str:
        """Check if a Python package version is known vulnerable."""
        if pkg_name not in KNOWN_VULNERABLE:
            return ""
        if not version:
            return ""

        for vuln_range, description in KNOWN_VULNERABLE[pkg_name].items():
            if self._version_in_range(version, vuln_range):
                return description
        return ""

    def _check_vulnerability_npm(self, pkg_name: str, version: str) -> str:
        """Check npm package vulnerabilities."""
        npm_vulns = {
            "minimist": {"<1.2.6": "CVE-2021-44906: Prototype pollution"},
            "node-fetch": {"<2.6.7": "CVE-2022-0235: Exposure of sensitive information"},
            "glob-parent": {"<5.1.2": "CVE-2020-28469: ReDoS vulnerability"},
            "json5": {"<1.0.2": "CVE-2022-46175: Prototype pollution"},
            "loader-utils": {"<1.4.2": "CVE-2022-37601: Prototype pollution"},
        }
        if pkg_name not in npm_vulns:
            return ""
        if not version:
            return ""
        for vuln_range, desc in npm_vulns[pkg_name].items():
            if self._version_in_range(version, vuln_range):
                return desc
        return ""

    def _version_in_range(self, version: str, vuln_range: str) -> bool:
        """Check if version falls within vulnerable range."""
        try:
            import packaging.version
            import packaging.specifiers
            spec = packaging.specifiers.SpecifierSet(f"<{vuln_range.lstrip('<>!=~')}")
            return packaging.version.parse(version) in spec
        except Exception:
            pass

        if vuln_range.startswith("<"):
            vuln_ver = vuln_range[1:]
            return self._simple_version_lt(version, vuln_ver)
        return False

    def _simple_version_lt(self, v1: str, v2: str) -> bool:
        """Simple version comparison: v1 < v2."""
        try:
            parts1 = [int(x) for x in v1.split(".") if x.isdigit()]
            parts2 = [int(x) for x in v2.split(".") if x.isdigit()]
            return parts1 < parts2
        except (ValueError, AttributeError):
            return False

    def _should_exclude(self, path: Path) -> bool:
        blocked = {".git", "node_modules", "__pycache__", ".venv", "venv"}
        for part in path.parts:
            if part in blocked:
                return True
        return False


import logging

logger = logging.getLogger(__name__)
