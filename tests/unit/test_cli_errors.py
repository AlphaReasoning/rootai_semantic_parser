"""The CLI must fail with a message, not a traceback.

A bad query expression or an unreadable file is an operator mistake. Reporting
it as a Python stack trace tells them nothing actionable and looks like a crash.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rootai_semantic_parser.cli import main


def _repo(tmp_path: Path) -> str:
    (tmp_path / "a.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    return str(tmp_path)


def test_unknown_query_reference_reports_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    code = main(["--no-cache", _repo(tmp_path), "query", "--expr", "cone source=does_not_exist"])
    captured = capsys.readouterr()
    assert code == 2
    assert "query error" in captured.err
    assert "Traceback" not in captured.err


def test_malformed_query_reports_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    code = main(["--no-cache", _repo(tmp_path), "query", "--expr", "not-a-real-command"])
    captured = capsys.readouterr()
    assert code == 2
    assert "query error" in captured.err


def test_missing_config_file_reports_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    code = main(["--no-cache", "--config", str(tmp_path / "nope.json"), _repo(tmp_path), "scan"])
    captured = capsys.readouterr()
    assert code == 2
    assert "file not found" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_json_config_reports_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    code = main(["--no-cache", "--config", str(bad), _repo(tmp_path), "scan"])
    captured = capsys.readouterr()
    assert code == 2
    assert "invalid JSON" in captured.err


def test_successful_scan_still_returns_zero(tmp_path: Path) -> None:
    assert main(["--no-cache", _repo(tmp_path), "scan", "--format", "json"]) == 0


def test_api_module_imports() -> None:
    """The README advertises FastAPI endpoints; the dependency must be installed."""
    from rootai_semantic_parser import api

    assert api.app.title
    routes = {getattr(r, "path", "") for r in api.app.routes}
    assert {"/parse", "/query"} <= routes
