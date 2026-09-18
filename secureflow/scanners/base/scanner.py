"""Base scanner interface for SecureFlow.

All scanners implement this interface. The framework handles
registration, lifecycle, and result normalization.
"""

from __future__ import annotations

import logging
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

from secureflow.core.config import ScannerConfig
from secureflow.findings.models import Finding, ScannerType

logger = logging.getLogger(__name__)


class ScanError(Exception):
    """Error during scanning."""


class ScannerBase(ABC):
    """Base class for all security scanners.

    Subclasses must implement:
    - scanner_type: ClassVar[ScannerType]
    - name: ClassVar[str]
    - scan(): Core scanning logic
    """

    scanner_type: ClassVar[ScannerType]
    name: ClassVar[str]
    description: ClassVar[str] = ""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate scanner configuration."""
        if self.config.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.config.timeout}")
        if self.config.timeout > 3600:
            raise ValueError(f"Timeout too large: {self.config.timeout}s (max 3600s)")

    @abstractmethod
    def scan(self, target: Path, options: dict[str, Any] | None = None) -> list[Finding]:
        """Scan a target path and return findings.

        Args:
            target: Directory or file to scan.
            options: Scanner-specific options.

        Returns:
            List of findings discovered.

        Raises:
            ScanError: If scanning fails.
        """
        ...

    def is_available(self) -> bool:
        """Check if this scanner's dependencies are available."""
        return True

    def _run_subprocess(
        self,
        cmd: list[str],
        timeout: int | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a subprocess with security constraints.

        Validates command, applies timeout, and captures output safely.
        """
        if not cmd:
            raise ScanError("Empty command")

        timeout = timeout or self.config.timeout
        logger.debug("Running: %s (timeout=%ds)", " ".join(cmd), timeout)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False,
                shell=False,
            )
            return result
        except subprocess.TimeoutExpired:
            raise ScanError(f"Command timed out after {timeout}s: {cmd[0]}")
        except FileNotFoundError:
            raise ScanError(f"Command not found: {cmd[0]}")
        except OSError as e:
            raise ScanError(f"Failed to execute {cmd[0]}: {e}")

    def _validate_target(self, target: Path) -> Path:
        """Validate and resolve scan target."""
        if not target.exists():
            raise ScanError(f"Target does not exist: {target}")

        resolved = target.resolve()

        if not resolved.is_dir() and not resolved.is_file():
            raise ScanError(f"Target is not a file or directory: {target}")

        return resolved

    def _make_finding(
        self,
        rule: str,
        severity: str,
        confidence: str,
        title: str,
        description: str,
        file_path: str = "",
        line: int = 0,
        evidence: str = "",
        remediation: str = "",
        **kwargs: Any,
    ) -> Finding:
        """Create a finding with this scanner's type pre-filled."""
        from secureflow.findings.models import Confidence, Location, Severity

        return Finding(
            scanner=self.scanner_type,
            rule=rule,
            severity=Severity(severity),
            confidence=Confidence(confidence),
            title=title,
            description=description,
            location=Location(file_path=file_path, line=line),
            evidence=evidence,
            remediation=remediation,
            metadata=kwargs.get("metadata", {}),
            tags=kwargs.get("tags", []),
        )


class ScannerRegistry:
    """Registry for scanner plugins."""

    _scanners: ClassVar[dict[str, type[ScannerBase]]] = {}

    @classmethod
    def register(cls, scanner_cls: type[ScannerBase]) -> type[ScannerBase]:
        """Register a scanner class."""
        cls._scanners[scanner_cls.name] = scanner_cls
        logger.debug("Registered scanner: %s", scanner_cls.name)
        return scanner_cls

    @classmethod
    def get(cls, name: str) -> type[ScannerBase] | None:
        """Get a scanner by name."""
        return cls._scanners.get(name)

    @classmethod
    def get_all(cls) -> dict[str, type[ScannerBase]]:
        """Get all registered scanners."""
        return dict(cls._scanners)

    @classmethod
    def get_enabled(cls, enabled_names: set[str]) -> list[type[ScannerBase]]:
        """Get scanners that are enabled in config."""
        return [s for name, s in cls._scanners.items() if name in enabled_names]

    @classmethod
    def list_names(cls) -> list[str]:
        """List all registered scanner names."""
        return list(cls._scanners.keys())
