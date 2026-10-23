"""Tests for the findings model."""

import pytest
from secureflow.findings.models import (
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Reference,
    ScanResult,
    ScannerType,
    Severity,
)
# --- константы вынесены FORGE refactor ---
CONST_7 = 7.0



class TestSeverity:
    def test_weight_values(self):
        assert Severity.CRITICAL.weight == 10.0
        assert Severity.HIGH.weight == CONST_7
        assert Severity.MEDIUM.weight == 4.0
        assert Severity.LOW.weight == 1.0
        assert Severity.INFO.weight == 0.0

    def test_from_string_invalid(self):
        with pytest.raises(ValueError):
            Severity("invalid")


class TestConfidence:
    def test_weight_values(self):
        assert Confidence.HIGH.weight == 1.0
        assert Confidence.MEDIUM.weight == 0.6
        assert Confidence.LOW.weight == 0.3


class TestLocation:
    def test_normalize_path(self):
        loc = Location(file_path="src\\main.py", line=10)
        assert loc.file_path == "src/main.py"

    def test_defaults(self):
        loc = Location()
        assert loc.file_path == ""
        assert loc.line == 0
        assert loc.column == 0
        assert loc.end_line is None


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test-rule",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test Finding",
            description="A test finding",
        )
        assert f.scanner == ScannerType.SECRETS
        assert f.severity == Severity.HIGH
        assert f.status == FindingStatus.OPEN
        assert len(f.fingerprint) == 16

    def test_fingerprint_deterministic(self):
        f1 = Finding(
            scanner=ScannerType.SECRETS,
            rule="test-rule",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
            location=Location(file_path="test.py", line=10),
        )
        f2 = Finding(
            scanner=ScannerType.SECRETS,
            rule="test-rule",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
            location=Location(file_path="test.py", line=10),
        )
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_different(self):
        f1 = Finding(
            scanner=ScannerType.SECRETS,
            rule="rule1",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test1",
            description="Desc",
        )
        f2 = Finding(
            scanner=ScannerType.SECRETS,
            rule="rule2",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test2",
            description="Desc",
        )
        assert f1.fingerprint != f2.fingerprint

    def test_suppress(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
        )
        f.suppress("Not applicable")
        assert f.status == FindingStatus.SUPPRESSED
        assert f.metadata["suppress_reason"] == "Not applicable"

    def test_resolve(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
        )
        f.resolve()
        assert f.status == FindingStatus.RESOLVED

    def test_is_active(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
        )
        assert f.is_active is True
        f.resolve()
        assert f.is_active is False

    def test_risk_score(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test",
            description="Desc",
        )
        assert f.risk_score == CONST_7  # 7.0 * 1.0

    def test_risk_score_medium_low(self):
        f = Finding(
            scanner=ScannerType.SECRETS,
            rule="test",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            title="Test",
            description="Desc",
        )
        assert f.risk_score == pytest.approx(1.2)  # 4.0 * 0.3


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult(target="/test")
        assert r.total_findings == 0
        assert r.risk_score == 0.0

    def test_findings_by_severity(self):
        r = ScanResult(target="/test")
        r.findings = [
            Finding(scanner=ScannerType.SECRETS, rule="a", severity=Severity.HIGH, confidence=Confidence.HIGH, title="A", description=""),
            Finding(scanner=ScannerType.SECRETS, rule="b", severity=Severity.HIGH, confidence=Confidence.HIGH, title="B", description=""),
            Finding(scanner=ScannerType.SECRETS, rule="c", severity=Severity.LOW, confidence=Confidence.HIGH, title="C", description=""),
        ]
        counts = r.findings_by_severity
        assert counts["high"] == 2
        assert counts["low"] == 1

    def test_deduplicate(self):
        r = ScanResult(target="/test")
        f1 = Finding(
            scanner=ScannerType.SECRETS, rule="rule", severity=Severity.HIGH,
            confidence=Confidence.HIGH, title="Title", description="",
            location=Location(file_path="a.py", line=10),
        )
        f2 = Finding(
            scanner=ScannerType.SECRETS, rule="rule", severity=Severity.MEDIUM,
            confidence=Confidence.HIGH, title="Title", description="",
            location=Location(file_path="a.py", line=10),
        )
        r.findings = [f1, f2]
        removed = r.deduplicate()
        assert removed == 1
        assert len(r.findings) == 1
        assert r.findings[0].severity == Severity.HIGH  # Higher severity kept
