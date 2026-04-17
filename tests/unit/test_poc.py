"""PoC generation tests."""

from __future__ import annotations

from rootai_semantic_parser.reports import generate_poc_hints


def test_generate_poc_hints_for_exec_sink() -> None:
    """Generate useful PoC snippets for execution sinks."""
    finding = {"sink_label": "eval", "source_label": "cmd", "impact": "RCE", "path_labels": ["cmd", "eval"]}
    hints = generate_poc_hints(finding, collaborator_base="https://cb.example")
    assert "curl" in hints
    assert "burp_repeater" in hints
    assert "cb.example" in hints["collaborator"]
