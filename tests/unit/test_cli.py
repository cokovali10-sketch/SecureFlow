"""CLI tests for SecureFlow."""

import pytest
from click.testing import CliRunner

from secureflow.cli.main import main


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scanners(self, runner):
        result = runner.invoke(main, ["scanners"])
        assert result.exit_code == 0
        assert "secrets" in result.output

    def test_scan_nonexistent(self, runner):
        result = runner.invoke(main, ["/nonexistent/path/xyz"])
        assert result.exit_code != 0

    def test_scan_empty_dir(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No security findings" in result.output or "Risk Score" in result.output

    def test_scan_json_output(self, runner, tmp_path):
        result = runner.invoke(main, ["scan", str(tmp_path), "--output", "json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert "scan" in data
        assert "risk" in data

    def test_doctor(self, runner):
        result = runner.invoke(main, ["doctor"])
        assert result.exit_code == 0
        assert "Python" in result.output

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "SecureFlow" in result.output
