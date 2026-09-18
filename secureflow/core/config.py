"""Core configuration for SecureFlow."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for a single scanner."""

    enabled: bool = True
    timeout: int = 300
    extra_args: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RiskConfig:
    """Risk engine configuration."""

    critical_weight: float = 10.0
    high_weight: float = 7.0
    medium_weight: float = 4.0
    low_weight: float = 1.0
    info_weight: float = 0.0
    fail_threshold: float = 5.0


@dataclass(frozen=True)
class DatabaseConfig:
    """Database configuration."""

    url: str = "sqlite+aiosqlite:///secureflow.db"
    echo: bool = False


@dataclass(frozen=True)
class SecurityConfig:
    """Security constraints for SecureFlow itself."""

    max_file_size_mb: int = 50
    max_scan_depth: int = 20
    allowed_scan_roots: tuple[str, ...] = ()
    blocked_paths: tuple[str, ...] = (
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
    )
    max_subprocess_timeout: int = 600
    sanitize_logs: bool = True


@dataclass(frozen=True)
class Config:
    """Root configuration for SecureFlow."""

    project_name: str = "secureflow"
    version: str = "0.1.0"
    scanners: dict[str, ScannerConfig] = field(default_factory=lambda: {
        "secrets": ScannerConfig(),
        "sast": ScannerConfig(),
        "sca": ScannerConfig(),
        "containers": ScannerConfig(enabled=False),
    })
    risk: RiskConfig = field(default_factory=RiskConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    output_format: str = "human"
    verbose: bool = False
    quiet: bool = False

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables."""
        return cls(
            verbose=os.environ.get("SECUREFLOW_VERBOSE", "0") == "1",
            quiet=os.environ.get("SECUREFLOW_QUIET", "0") == "1",
            output_format=os.environ.get("SECUREFLOW_OUTPUT", "human"),
        )

    @classmethod
    def from_file(cls, path: Path) -> Config:
        """Load configuration from a YAML/TOML file."""
        if not path.exists():
            return cls()

        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)

        scanners = {}
        for name, settings in data.get("scanners", {}).items():
            scanners[name] = ScannerConfig(**settings)

        return cls(
            scanners=scanners if scanners else cls().scanners,
            verbose=data.get("verbose", False),
            quiet=data.get("quiet", False),
            output_format=data.get("output_format", "human"),
        )
