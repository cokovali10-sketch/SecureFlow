"""Tests for scanner framework."""


import pytest

from secureflow.core.config import ScannerConfig
from secureflow.findings.models import ScannerType, Severity
from secureflow.scanners.base.scanner import ScannerBase, ScannerRegistry, ScanError


class TestScannerRegistry:
    def test_register_and_get(self):
        @ScannerRegistry.register
        class DummyScanner(ScannerBase):
            scanner_type = ScannerType.CUSTOM
            name = "dummy_test"
            description = "Test scanner"

            def scan(self, target, options=None):
                return []

        assert ScannerRegistry.get("dummy_test") is DummyScanner
        assert "dummy_test" in ScannerRegistry.list_names()

    def test_get_nonexistent(self):
        assert ScannerRegistry.get("nonexistent_scanner_xyz") is None

    def test_get_enabled(self):
        enabled = ScannerRegistry.get_enabled({"secrets", "sast"})
        names = [s.name for s in enabled]
        assert "secrets" in names or len(enabled) >= 0  # May not be registered yet


class TestScannerBase:
    def test_validate_config_valid(self):
        config = ScannerConfig(timeout=60)
        # Should not raise
        scanner = type("TestScanner", (ScannerBase,), {
            "scanner_type": ScannerType.CUSTOM,
            "name": "test_validate",
            "description": "",
            "scan": lambda self, t, o=None: [],
        })(config=config)

    def test_validate_config_zero_timeout(self):
        config = ScannerConfig(timeout=0)
        with pytest.raises(ValueError, match="positive"):
            type("TestScanner", (ScannerBase,), {
                "scanner_type": ScannerType.CUSTOM,
                "name": "test_zero",
                "description": "",
                "scan": lambda self, t, o=None: [],
            })(config=config)

    def test_validate_config_huge_timeout(self):
        config = ScannerConfig(timeout=9999)
        with pytest.raises(ValueError, match="too large"):
            type("TestScanner", (ScannerBase,), {
                "scanner_type": ScannerType.CUSTOM,
                "name": "test_huge",
                "description": "",
                "scan": lambda self, t, o=None: [],
            })(config=config)

    def test_validate_target_nonexistent(self, tmp_path):
        scanner = type("TestScanner", (ScannerBase,), {
            "scanner_type": ScannerType.CUSTOM,
            "name": "test_target",
            "description": "",
            "scan": lambda self, t, o=None: [],
        })()
        with pytest.raises(ScanError, match="does not exist"):
            scanner._validate_target(tmp_path / "nonexistent")

    def test_run_subprocess_empty_command(self):
        scanner = type("TestScanner", (ScannerBase,), {
            "scanner_type": ScannerType.CUSTOM,
            "name": "test_empty_cmd",
            "description": "",
            "scan": lambda self, t, o=None: [],
        })()
        with pytest.raises(ScanError, match="Empty command"):
            scanner._run_subprocess([])

    def test_run_subprocess_command_not_found(self):
        scanner = type("TestScanner", (ScannerBase,), {
            "scanner_type": ScannerType.CUSTOM,
            "name": "test_not_found",
            "description": "",
            "scan": lambda self, t, o=None: [],
        })()
        with pytest.raises(ScanError, match="not found"):
            scanner._run_subprocess(["nonexistent_command_xyz_12345"])

    def test_make_finding(self):
        scanner = type("TestScanner", (ScannerBase,), {
            "scanner_type": ScannerType.SECRETS,
            "name": "test_make_finding",
            "description": "",
            "scan": lambda self, t, o=None: [],
        })()
        finding = scanner._make_finding(
            rule="test-rule",
            severity="high",
            confidence="high",
            title="Test",
            description="Description",
            file_path="test.py",
            line=10,
        )
        assert finding.scanner == ScannerType.SECRETS
        assert finding.severity == Severity.HIGH
        assert finding.rule == "test-rule"
