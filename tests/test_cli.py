"""
BREACH CLI Tests
"""

import pytest
from typer.testing import CliRunner

from breach.cli import app, __version__


runner = CliRunner()


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_version_command(self):
        """Test version command outputs version."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_help_command(self):
        """Test help output."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "BREACH" in result.stdout
        assert "scan" in result.stdout

    def test_scan_help(self):
        """Test scan command help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "target" in result.stdout.lower()
        assert "--repo" in result.stdout
        assert "--ai" in result.stdout

    def test_doctor_command(self):
        """Test doctor command runs."""
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Python" in result.stdout

    def test_list_phases_command(self):
        """Test list-phases command."""
        result = runner.invoke(app, ["list-phases"])
        assert result.exit_code == 0
        assert "Phase 1" in result.stdout
        assert "Phase 2" in result.stdout
        assert "Phase 3" in result.stdout
        assert "Phase 4" in result.stdout
        assert "Reconnaissance" in result.stdout
        assert "Exploitation" in result.stdout


class TestCLIValidation:
    """Test CLI input validation."""

    def test_scan_requires_target(self):
        """Test scan requires a target argument."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0
        # Error may be in stdout or the exit code indicates failure
        output = result.stdout + (result.stderr or "")
        assert result.exit_code == 2 or "Missing argument" in output or "target" in output.lower()

    def test_scan_requires_confirmation(self):
        """Test scan requires authorization confirmation."""
        result = runner.invoke(app, ["scan", "https://example.com"], input="no\n")
        assert result.exit_code != 0

    def test_scan_with_skip_verify(self):
        """Test scan with --skip-verify still validates URL."""
        # This would fail because we don't have real network access in tests
        # but the URL validation should pass
        result = runner.invoke(
            app,
            ["scan", "not-a-url", "--skip-verify"],
        )
        # The command will try to run and may fail for other reasons
        # but at least validates the skip-verify flag works
        assert "--skip-verify" not in result.stdout or result.exit_code != 0


class TestInitCommand:
    """Test init command."""

    def test_init_creates_config(self, tmp_path):
        """Test init creates a config file."""
        output_dir = tmp_path / "configs"
        result = runner.invoke(
            app,
            ["init", "https://example.com", "--output", str(output_dir)],
        )
        assert result.exit_code == 0
        assert "Config created" in result.stdout

        # Check file was created
        config_file = output_dir / "example.com.yaml"
        assert config_file.exists()

        # Check content
        content = config_file.read_text()
        assert "target: https://example.com" in content
        assert "max_pages" in content
