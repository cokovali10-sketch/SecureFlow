"""Tests for the risk engine."""

from secureflow.core.config import RiskConfig
from secureflow.findings.models import (
    Confidence,
    Finding,
    Location,
    ScanResult,
    ScannerType,
    Severity,
)
from secureflow.risk.engine import RiskEngine
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_90 = 90.0



class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine(RiskConfig())

    def test_empty_scan(self):
        result = ScanResult(target="/test")
        assessment = self.engine.assess(result)
        assert assessment.score == 100.0
        assert assessment.grade == "A"
        assert assessment.pass_fail is True

    def test_critical_finding(self):
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SECRETS,
                rule="critical-rule",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Critical Issue",
                description="",
            )
        ]
        assessment = self.engine.assess(result)
        assert assessment.score < 100.0
        assert assessment.score == CONST_90  # 100 - (10.0 * 1.0) = 90
        # Score 90 = grade A (passes threshold)
        # But with more findings it should fail

    def test_medium_finding(self):
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SAST,
                rule="medium-rule",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Medium Issue",
                description="",
            )
        ]
        assessment = self.engine.assess(result)
        assert assessment.score < 100.0
        assert assessment.score > CONST_90  # 4.0 * 0.6 = 2.4 penalty

    def test_grade_thresholds(self):
        engine = RiskEngine(RiskConfig(
            critical_weight=15.0,
            high_weight=10.0,
            medium_weight=CONST_5,
            low_weight=2.0,
        ))
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SECRETS,
                rule="r",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="T",
                description="",
            )
            for _ in range(10)
        ]
        assessment = engine.assess(result)
        assert assessment.grade == "F"
        assert assessment.pass_fail is False

    def test_recommendations(self):
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SECRETS,
                rule="secret",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Secret",
                description="",
            ),
            Finding(
                scanner=ScannerType.SCA,
                rule="dep",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Dep",
                description="",
            ),
        ]
        assessment = self.engine.assess(result)
        assert len(assessment.recommendations) > 0
        has_secret_rec = any("credential" in r.lower() or "secret" in r.lower() for r in assessment.recommendations)
        has_dep_rec = any("dependenc" in r.lower() or "update" in r.lower() for r in assessment.recommendations)
        assert has_secret_rec
        assert has_dep_rec

    def test_should_fail(self):
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SECRETS,
                rule="r",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="T",
                description="",
            )
            for _ in range(CONST_5)  # 5 critical = 50 penalty, score = 50 = grade D = fail
        ]
        assert self.engine.should_fail(result) is True

    def test_should_pass_clean(self):
        result = ScanResult(target="/test")
        assert self.engine.should_fail(result) is False

    def test_top_risks(self):
        result = ScanResult(target="/test")
        result.findings = [
            Finding(
                scanner=ScannerType.SECRETS,
                rule=f"rule-{i}",
                severity=sev,
                confidence=conf,
                title=f"Finding {i}",
                description="",
                location=Location(file_path=f"file{i}.py", line=i),
            )
            for i, (sev, conf) in enumerate([
                (Severity.LOW, Confidence.LOW),
                (Severity.MEDIUM, Confidence.MEDIUM),
                (Severity.HIGH, Confidence.HIGH),
                (Severity.CRITICAL, Confidence.HIGH),
            ])
        ]
        assessment = self.engine.assess(result)
        top = assessment.summary["top_risks"]
        assert len(top) <= CONST_5
        assert top[0]["severity"] == "critical"
