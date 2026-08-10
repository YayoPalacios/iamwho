"""Tests for the `checks` discovery command.

`analyze --check` accepts "chain" as a valid value, but the `checks` command
that lists available checks for discovery had its own hard-coded list that
was never updated to include it - a user running `iamwho checks` would never
learn the chain check exists.
"""

from typer.testing import CliRunner

from iamwho.cli import app

runner = CliRunner()


def test_checks_command_lists_chain():
    result = runner.invoke(app, ["checks"])

    assert result.exit_code == 0
    assert "chain" in result.output
