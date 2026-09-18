"""Risk scoring engine for SecureFlow.

Calculates overall risk scores, determines pass/fail based on policy,
and provides risk categorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secureflow.core.config import RiskConfig
from secureflow.findings.models import Finding, ScanResult, Severity


@dataclass
class RiskAssessment:
    """Result of risk assessment."""

    score: float
    max_possible: float
    grade: str
    pass_fail: bool
    summary: dict[str, Any]
    recommendations: list[str]

    @property
    def score_percentage(self) -> float:
        if self.max_possible == 0:
            return 0.0
        return (self.score / self.max_possible) * 100


class RiskEngine:
    """Calculates risk scores and determines pass/fail policy gates."""

    GRADE_THRESHOLDS = [
        (90, "A", True),
        (75, "B", True),
        (60, "C", True),
        (40, "D", False),
        (0, "F", False),
    ]

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def assess(self, result: ScanResult) -> RiskAssessment:
        """Perform risk assessment on a scan result."""
        active_findings = [f for f in result.findings if f.is_active]

        if not active_findings:
            return RiskAssessment(
                score=100.0,
                max_possible=100.0,
                grade="A",
                pass_fail=True,
                summary={"total_findings": 0, "by_severity": {}},
                recommendations=["No security issues found. Code looks clean."],
            )

        score = self._calculate_score(active_findings)
        max_score = 100.0
        grade, pass_fail = self._determine_grade(score)

        summary = {
            "total_findings": len(active_findings),
            "by_severity": self._count_by_severity(active_findings),
            "by_scanner": self._count_by_scanner(active_findings),
            "top_risks": self._top_risks(active_findings),
        }

        recommendations = self._generate_recommendations(active_findings)

        return RiskAssessment(
            score=score,
            max_possible=max_score,
            grade=grade,
            pass_fail=pass_fail,
            summary=summary,
            recommendations=recommendations,
        )

    def _calculate_score(self, findings: list[Finding]) -> float:
        """Calculate risk score (lower is worse, 100 = no findings)."""
        penalty = 0.0
        weights = {
            Severity.CRITICAL: self.config.critical_weight,
            Severity.HIGH: self.config.high_weight,
            Severity.MEDIUM: self.config.medium_weight,
            Severity.LOW: self.config.low_weight,
            Severity.INFO: self.config.info_weight,
        }

        for finding in findings:
            severity_weight = weights.get(finding.severity, 0.0)
            confidence_weight = finding.confidence.weight
            penalty += severity_weight * confidence_weight

        return max(0.0, 100.0 - penalty)

    def _determine_grade(self, score: float) -> tuple[str, bool]:
        """Determine letter grade and pass/fail."""
        for threshold, grade, passes in self.GRADE_THRESHOLDS:
            if score >= threshold:
                return grade, passes
        return "F", False

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def _count_by_scanner(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.scanner.value] = counts.get(f.scanner.value, 0) + 1
        return counts

    def _top_risks(self, findings: list[Finding], limit: int = 5) -> list[dict[str, Any]]:
        """Get top N highest-risk findings."""
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        return [
            {
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "risk_score": f.risk_score,
                "file": f.location.file_path,
                "line": f.location.line,
                "scanner": f.scanner.value,
            }
            for f in sorted_findings[:limit]
        ]

    def _generate_recommendations(self, findings: list[Finding]) -> list[str]:
        """Generate actionable recommendations based on findings."""
        recommendations: list[str] = []
        severity_counts = self._count_by_severity(findings)

        if severity_counts.get("critical", 0) > 0:
            recommendations.append(
                f"URGENT: {severity_counts['critical']} critical findings require immediate attention."
            )

        if severity_counts.get("high", 0) > 0:
            recommendations.append(
                f"Address {severity_counts['high']} high-severity findings before deployment."
            )

        scanner_counts = self._count_by_scanner(findings)
        if scanner_counts.get("secrets", 0) > 0:
            recommendations.append(
                "Rotate any exposed credentials and move secrets to a vault."
            )
        if scanner_counts.get("sca", 0) > 0:
            recommendations.append(
                "Update vulnerable dependencies to patched versions."
            )
        if scanner_counts.get("sast", 0) > 0:
            recommendations.append(
                "Review flagged code patterns for security best practices."
            )
        if scanner_counts.get("container", 0) > 0:
            recommendations.append(
                "Harden container configurations following CIS Docker Benchmark."
            )

        if not recommendations:
            recommendations.append("Review findings and address as appropriate.")

        return recommendations

    def should_fail(self, result: ScanResult) -> bool:
        """Determine if the scan should cause a CI/CD pipeline failure."""
        assessment = self.assess(result)
        return not assessment.pass_fail
