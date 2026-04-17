"""Report rendering tests."""

from __future__ import annotations

from rootai_semantic_parser.models import BountyReport
from rootai_semantic_parser.reports import bounty_report_to_sarif
from rootai_semantic_parser.reports.markdown import findings_markdown_table


def test_markdown_table_renders_headers() -> None:
    """Render a markdown table for report consumers."""
    report = BountyReport(
        root=".",
        profile="bugbounty",
        quick_mode=True,
        generated_at=0.0,
        summary={},
        findings=[
            {
                "score": 95.0,
                "severity": "critical",
                "impact": "RCE",
                "reachable": True,
                "sanitized": False,
                "source_location": "a.py:1",
                "sink_location": "a.py:2",
                "path_labels": ["request", "eval"],
                "payload_hints": ["id"],
            }
        ],
        graph={"nodes": [], "edges": []},
    )
    markdown = findings_markdown_table(report)
    assert "| Score | Confidence | Severity | Potential Impact |" in markdown
    assert "RCE" in markdown


def test_html_report_escapes_script_close() -> None:
    """Prevent direct script-breakout in HTML payload serialization."""
    report = BountyReport(
        root=".",
        profile="bugbounty",
        quick_mode=True,
        generated_at=0.0,
        summary={},
        findings=[{"score": 1, "severity": "low", "impact": "</script><script>alert(1)</script>"}],
        graph={"nodes": [], "edges": []},
    )
    html = report.to_html()
    assert 'id="report-data"' in html
    assert "</script><script>alert(1)</script>" not in html


def test_sarif_output_contains_run() -> None:
    """Render SARIF output for CI integrations."""
    report = BountyReport(
        root=".",
        profile="bugbounty",
        quick_mode=True,
        generated_at=0.0,
        summary={},
        findings=[
            {
                "score": 95.0,
                "severity": "critical",
                "impact": "RCE",
                "source_location": "a.py:1",
                "sink_location": "a.py:2",
                "path_labels": ["request", "eval"],
            }
        ],
        graph={"nodes": [], "edges": []},
    )
    sarif = bounty_report_to_sarif(report)
    assert '"runs"' in sarif
    assert '"ruleId"' in sarif
