"""Container scanner — analyzes Dockerfiles and container images for security issues.

Checks Dockerfile best practices, detects secrets, and optionally runs Trivy
for vulnerability scanning.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, ClassVar

from secureflow.findings.models import ScannerType
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry, ScanError


DOCKERFILE_RULES = [
    (
        "running-as-root",
        "high",
        "high",
        "Container runs as root",
        "No USER directive found. Container will run as root.",
        r"^(?!.*USER\s)",
        "Add 'USER nonroot' or a dedicated user before CMD/ENTRYPOINT.",
    ),
    (
        "latest-tag",
        "medium",
        "high",
        "Using :latest tag",
        "Base image uses :latest tag which is unstable and unreproducible",
        r"FROM\s+[\w\-]+(?::latest)?(?:\s|$)",
        "Pin base images to specific versions: FROM image:1.2.3",
    ),
    (
        "no-healthcheck",
        "low",
        "medium",
        "No HEALTHCHECK",
        "Dockerfile has no HEALTHCHECK instruction",
        r"^(?!.*HEALTHCHECK)",
        "Add HEALTHCHECK for container orchestration and monitoring.",
    ),
    (
        "add-curl-wget",
        "medium",
        "medium",
        "ADD/CURL for remote files",
        "Using ADD or curl to fetch remote files without verification",
        r"(?:ADD\s+https?://|curl\s+.*\|\s*(?:bash|sh))",
        "Download, verify checksum, then ADD the file. Avoid piping curl to shell.",
    ),
    (
        "exposed-ssh-port",
        "high",
        "high",
        "SSH port exposed",
        "Container exposes SSH port 22",
        r"EXPOSE\s+22(?:\s|$)",
        "Don't expose SSH. Use docker exec or kubectl exec for access.",
    ),
    (
        "sensitive-env",
        "high",
        "medium",
        "Sensitive env var in Dockerfile",
        "Sensitive data in ENV instruction",
        r"ENV\s+(?:.*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL).*=)",
        "Use runtime secrets (Docker secrets, env vars at runtime) instead of ENV.",
    ),
    (
        "apt-no-clean",
        "low",
        "low",
        "apt-get without clean",
        "apt-get install without cleanup increases image size",
        r"apt-get\s+install\s+(?!.*&&.*apt-get\s+clean)",
        "Combine RUN layers and clean apt cache: RUN apt-get install ... && rm -rf /var/lib/apt/lists/*",
    ),
    (
        "chmod-777",
        "high",
        "high",
        "chmod 777",
        "World-writable permissions detected",
        r"chmod\s+777",
        "Use least-privilege permissions. chmod 755 or more restrictive.",
    ),
]


@ScannerRegistry.register
class ContainerScanner(ScannerBase):
    """Container security scanner for Dockerfiles and images."""

    scanner_type = ScannerType.CONTAINER
    name = "containers"
    description = "Dockerfile security analysis and container vulnerability scanning"

    def scan(self, target: Path, options: dict[str, Any] | None = None) -> list:
        """Scan Dockerfiles and optionally container images."""
        from secureflow.findings.models import Finding

        target = self._validate_target(target)
        findings: list[Finding] = []

        findings.extend(self._scan_dockerfiles(target))
        findings.extend(self._scan_docker_compose(target))

        if shutil.which("trivy") and options and options.get("scan_image"):
            findings.extend(self._run_trivy(target, options["scan_image"]))

        return findings

    def _scan_dockerfiles(self, target: Path) -> list:
        """Scan all Dockerfiles for security issues."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        dockerfiles = list(target.rglob("Dockerfile*"))
        dockerfiles.extend(target.rglob("*.dockerfile"))

        for dockerfile in dockerfiles:
            if self._should_exclude(dockerfile):
                continue

            try:
                content = dockerfile.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            relative_path = str(dockerfile.relative_to(target)).replace("\\", "/")
            findings.extend(self._analyze_dockerfile(content, relative_path))

        return findings

    def _analyze_dockerfile(self, content: str, file_path: str) -> list:
        """Analyze Dockerfile content for security issues."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for rule_id, severity, conf, title, desc, pattern, remediation in DOCKERFILE_RULES:
                if re.search(pattern, stripped, re.IGNORECASE):
                    finding = self._make_finding(
                        rule=rule_id,
                        severity=severity,
                        confidence=conf,
                        title=title,
                        description=desc,
                        file_path=file_path,
                        line=line_num,
                        evidence=stripped[:200],
                        remediation=remediation,
                        tags=["container", "dockerfile"],
                    )
                    findings.append(finding)

        return findings

    def _scan_docker_compose(self, target: Path) -> list:
        """Scan docker-compose files for security issues."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        compose_files = list(target.rglob("docker-compose*.yml"))
        compose_files.extend(target.rglob("docker-compose*.yaml"))
        compose_files.extend(target.rglob("compose*.yml"))
        compose_files.extend(target.rglob("compose*.yaml"))

        for compose_file in compose_files:
            if self._should_exclude(compose_file):
                continue

            try:
                import yaml
                content = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
            except Exception:
                continue

            if not isinstance(content, dict):
                continue

            relative_path = str(compose_file.relative_to(target)).replace("\\", "/")
            findings.extend(self._analyze_compose(content, relative_path))

        return findings

    def _analyze_compose(self, data: dict, file_path: str) -> list:
        """Analyze docker-compose data for security issues."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []
        services = data.get("services", {})

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue

            # Check for privileged containers
            if svc_config.get("privileged"):
                finding = self._make_finding(
                    rule="privileged-container",
                    severity="critical",
                    confidence="high",
                    title=f"Privileged container: {svc_name}",
                    description="Service runs in privileged mode, granting full host access.",
                    file_path=file_path,
                    evidence=f"privileged: true in service {svc_name}",
                    remediation="Remove privileged mode. Use specific capabilities instead.",
                    tags=["container", "docker-compose", "privilege-escalation"],
                )
                findings.append(finding)

            # Check for host network mode
            network_mode = svc_config.get("network_mode", "")
            if network_mode == "host":
                finding = self._make_finding(
                    rule="host-network-mode",
                    severity="high",
                    confidence="high",
                    title=f"Host network mode: {svc_name}",
                    description="Service uses host network, bypassing network isolation.",
                    file_path=file_path,
                    evidence=f"network_mode: host in service {svc_name}",
                    remediation="Use bridge networking with explicit port mappings.",
                    tags=["container", "docker-compose", "network"],
                )
                findings.append(finding)

            # Check for Docker socket mount
            volumes = svc_config.get("volumes", [])
            for vol in volumes:
                if isinstance(vol, str) and "docker.sock" in vol:
                    finding = self._make_finding(
                        rule="docker-socket-mount",
                        severity="critical",
                        confidence="high",
                        title=f"Docker socket mounted: {svc_name}",
                        description="Docker socket is mounted, giving container full Docker API access.",
                        file_path=file_path,
                        evidence=f"Volume mount: {vol}",
                        remediation="Don't mount Docker socket. Use Docker-in-Docker or build tools.",
                        tags=["container", "docker-compose", "privilege-escalation"],
                    )
                    findings.append(finding)

        return findings

    def _run_trivy(self, target: Path, image: str) -> list:
        """Run Trivy for container image vulnerability scanning."""
        from secureflow.findings.models import Finding

        findings: list[Finding] = []

        cmd = ["trivy", "image", "--format", "json", image]
        try:
            result = self._run_subprocess(cmd)
            data = json.loads(result.stdout)

            for result_item in data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "UNKNOWN").lower()
                    if severity not in ("critical", "high", "medium", "low"):
                        severity = "info"

                    finding = self._make_finding(
                        rule=f"trivy-{vuln.get('VulnerabilityID', 'unknown')}",
                        severity=severity,
                        confidence="high",
                        title=f"{vuln.get('VulnerabilityID', 'Unknown')}: {vuln.get('PkgName', '')}",
                        description=vuln.get("Title", vuln.get("Description", "")[:200]),
                        evidence=f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}",
                        remediation=f"Upgrade {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}.",
                        metadata={
                            "cve_id": vuln.get("VulnerabilityID", ""),
                            "package": vuln.get("PkgName", ""),
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                        },
                        tags=["container", "trivy", "vulnerability"],
                    )
                    findings.append(finding)
        except ScanError as e:
            logger.warning("Trivy scan failed: %s", e)

        return findings

    def _should_exclude(self, path: Path) -> bool:
        blocked = {".git", "node_modules", "__pycache__", ".venv"}
        for part in path.parts:
            if part in blocked:
                return True
        return False


import logging

logger = logging.getLogger(__name__)
