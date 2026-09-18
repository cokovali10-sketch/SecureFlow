"""Unified findings model for SecureFlow.

All scanners produce findings in this normalized format.
Supports deduplication, lifecycle management, and severity/confidence scoring.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }[self]


class Confidence(str, Enum):
    """Finding confidence levels."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> float:
        return {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
        }[self]


class FindingStatus(str, Enum):
    """Finding lifecycle status."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class ScannerType(str, Enum):
    """Types of security scanners."""

    SECRETS = "secrets"
    SAST = "sast"
    SCA = "sca"
    CONTAINER = "container"
    CONFIG = "config"
    CUSTOM = "custom"


class Location(BaseModel):
    """Source location of a finding."""

    file_path: str = ""
    line: int = 0
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None

    @field_validator("file_path")
    @classmethod
    def normalize_path(cls, v: str) -> str:
        return v.replace("\\", "/")


class Reference(BaseModel):
    """External reference for a finding."""

    url: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    rule_id: Optional[str] = None
    description: Optional[str] = None


class Finding(BaseModel):
    """Unified security finding from any scanner."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    scanner: ScannerType
    rule: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    location: Location = Field(default_factory=Location)
    evidence: str = ""
    remediation: str = ""
    references: list[Reference] = Field(default_factory=list)
    fingerprint: str = ""
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        """Compute a deterministic fingerprint for deduplication."""
        raw = f"{self.scanner.value}:{self.rule}:{self.location.file_path}:{self.location.line}:{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def suppress(self, reason: str = "") -> None:
        """Suppress this finding."""
        self.status = FindingStatus.SUPPRESSED
        self.updated_at = datetime.now(timezone.utc)
        if reason:
            self.metadata["suppress_reason"] = reason

    def resolve(self) -> None:
        """Mark finding as resolved."""
        self.status = FindingStatus.RESOLVED
        self.updated_at = datetime.now(timezone.utc)

    def confirm(self) -> None:
        """Confirm this finding is a true positive."""
        self.status = FindingStatus.CONFIRMED
        self.updated_at = datetime.now(timezone.utc)

    def mark_false_positive(self) -> None:
        """Mark as false positive."""
        self.status = FindingStatus.FALSE_POSITIVE
        self.updated_at = datetime.now(timezone.utc)

    @property
    def is_active(self) -> bool:
        """Check if finding is still active (not resolved/suppressed/FP)."""
        return self.status in (FindingStatus.OPEN, FindingStatus.CONFIRMED)

    @property
    def risk_score(self) -> float:
        """Calculate risk score = severity × confidence."""
        return self.severity.weight * self.confidence.weight


class ScanResult(BaseModel):
    """Result of a complete scan."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    target: str
    findings: list[Finding] = Field(default_factory=list)
    scanner_used: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def active_findings(self) -> int:
        return sum(1 for f in self.findings if f.is_active)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            if f.is_active:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @property
    def findings_by_scanner(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            if f.is_active:
                counts[f.scanner.value] = counts.get(f.scanner.value, 0) + 1
        return counts

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        return sum(f.risk_score for f in self.findings if f.is_active)

    def deduplicate(self) -> int:
        """Remove duplicate findings by fingerprint. Returns count removed."""
        seen: dict[str, Finding] = {}
        original_count = len(self.findings)
        for finding in self.findings:
            if finding.fingerprint in seen:
                existing = seen[finding.fingerprint]
                if finding.severity.weight > existing.severity.weight:
                    seen[finding.fingerprint] = finding
            else:
                seen[finding.fingerprint] = finding
        self.findings = list(seen.values())
        return original_count - len(self.findings)
