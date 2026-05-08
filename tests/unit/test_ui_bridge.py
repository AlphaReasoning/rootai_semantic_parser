"""UI bridge tests for the Streamlit-facing scan helper."""

from __future__ import annotations

from pathlib import Path

from async_parse import scan_async


def test_scan_async_emits_report_bounty_and_exports(tmp_path: Path) -> None:
    """Run the UI bridge on a tiny repository and emit the core payloads."""
    source = tmp_path / "sample.py"
    source.write_text(
        "import os\n"
        "def handler(user_input):\n"
        "    os.system(user_input)\n",
        encoding="utf-8",
    )

    result = scan_async(str(tmp_path), profile="bugbounty", min_score=0.0, quick_mode=False, use_cache=False)

    assert "report" in result
    assert "bounty" in result
    assert "exports" in result
    assert "snapshot" in result
    assert result["report"]["node_count"] >= 1
    assert "scan_json" in result["exports"]
    assert "bounty_html" in result["exports"]
    assert "sarif" in result["exports"]
