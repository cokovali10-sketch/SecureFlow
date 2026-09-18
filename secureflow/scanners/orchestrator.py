"""Scan orchestrator — coordinates scanners and produces unified results."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from secureflow.core.config import Config
from secureflow.findings.models import Finding, ScanResult
from secureflow.risk.engine import RiskAssessment, RiskEngine
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates multiple scanners against a target."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.risk_engine = RiskEngine(self.config.risk)

    def scan(
        self,
        target: Path,
        scanners: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> ScanResult:
        """Run all enabled scanners against target.

        Args:
            target: Directory or file to scan.
            scanners: Specific scanners to run (None = all enabled).
            options: Global scan options.

        Returns:
            Unified scan result with all findings.
        """
        target = target.resolve()
        if not target.exists():
            return ScanResult(
                target=str(target),
                error=f"Target does not exist: {target}",
            )

        enabled = scanners or list(self.config.scanners.keys())
        result = ScanResult(target=str(target))

        start_time = time.time()

        for scanner_name in enabled:
            scanner_config = self.config.scanners.get(scanner_name)
            if scanner_config and not scanner_config.enabled:
                logger.debug("Scanner %s is disabled, skipping", scanner_name)
                continue

            scanner_cls = ScannerRegistry.get(scanner_name)
            if not scanner_cls:
                logger.warning("Unknown scanner: %s", scanner_name)
                continue

            scanner = scanner_cls(config=scanner_config)
            if not scanner.is_available():
                logger.info("Scanner %s dependencies not available, skipping", scanner_name)
                continue

            logger.info("Running scanner: %s", scanner_name)
            result.scanner_used.append(scanner_name)

            try:
                findings = scanner.scan(target, options)
                result.findings.extend(findings)
                logger.info("Scanner %s found %d issues", scanner_name, len(findings))
            except Exception as e:
                logger.error("Scanner %s failed: %s", scanner_name, e)

        result.deduplicate()
        result.completed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        result.duration_seconds = time.time() - start_time

        return result

    def scan_with_assessment(
        self,
        target: Path,
        scanners: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[ScanResult, RiskAssessment]:
        """Run scan and perform risk assessment."""
        result = self.scan(target, scanners, options)
        assessment = self.risk_engine.assess(result)
        return result, assessment

    @staticmethod
    def list_scanners() -> dict[str, dict[str, str]]:
        """List all available scanners with metadata."""
        scanners = ScannerRegistry.get_all()
        return {
            name: {
                "name": cls.name,
                "description": cls.description,
                "type": cls.scanner_type.value,
            }
            for name, cls in scanners.items()
        }
