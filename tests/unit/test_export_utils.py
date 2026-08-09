from __future__ import annotations

import json

import pytest

import export_utils
from export_utils import (
    EXPORT_KEYS,
    build_bounty_graph,
    build_snapshot_payload,
    compact_bounty_payload,
    render_export,
)


@pytest.fixture
def report_payload():
    return {
        "graph": {
            "nodes": [{"id": "n1", "label": "source", "type": "Variable", "file": "app.py"}],
            "edges": [],
        },
        "taint_paths": [],
        "root": "/workspace",
        "node_count": 1,
        "edge_count": 0,
        "pii_node_count": 0,
        "taint_path_count": 0,
        "severity_summary": {},
        "top_risks": [],
        "unresolved_calls": 0,
        "cache_hits": 0,
        "cache_misses": 0,
    }


@pytest.fixture
def bounty_payload():
    return {
        "root": "/workspace",
        "profile": "human-only",
        "quick_mode": False,
        "generated_at": 1.0,
        "summary": {},
        "findings": [],
        "graph": {"nodes": [{"id": "n1", "label": "source"}], "edges": []},
    }


def test_every_advertised_export_renders_to_text(report_payload, bounty_payload) -> None:
    for export_key in EXPORT_KEYS:
        rendered = render_export(report_payload, bounty_payload, export_key)
        assert isinstance(rendered, str)


def test_duplicate_web_ui_html_is_a_compatibility_alias_not_an_advertised_export(
    report_payload, bounty_payload
) -> None:
    assert "web_ui_html" not in EXPORT_KEYS
    assert render_export(report_payload, bounty_payload, "web_ui_html") == render_export(
        report_payload, bounty_payload, "bounty_html"
    )


def test_compact_bounty_payload_reuses_the_report_graph(report_payload, bounty_payload) -> None:
    bounty_payload["graph"] = build_bounty_graph(report_payload["graph"])
    compact_bounty = compact_bounty_payload(report_payload, bounty_payload)

    rendered = json.loads(render_export(report_payload, compact_bounty, "bounty_json"))

    assert "graph" not in compact_bounty
    assert rendered["graph"] == build_bounty_graph(report_payload["graph"])


def test_compaction_preserves_a_distinct_bounty_graph(report_payload, bounty_payload) -> None:
    bounty_payload["graph"] = {"nodes": [], "edges": []}

    compact_bounty = compact_bounty_payload(report_payload, bounty_payload)

    assert compact_bounty["graph"] == {"nodes": [], "edges": []}


def test_compact_payload_preserves_every_export(report_payload, bounty_payload) -> None:
    bounty_payload["graph"] = build_bounty_graph(report_payload["graph"])
    compact_bounty = compact_bounty_payload(report_payload, bounty_payload)

    for export_key in EXPORT_KEYS:
        assert render_export(report_payload, compact_bounty, export_key) == render_export(
            report_payload, bounty_payload, export_key
        )


def test_only_the_requested_renderer_runs(monkeypatch, report_payload, bounty_payload) -> None:
    calls = []

    def fake_renderer(bounty, format_name):
        calls.append(format_name)
        return format_name

    monkeypatch.setattr(export_utils, "render_bounty_output", fake_renderer)

    assert render_export(report_payload, bounty_payload, "sarif") == "sarif"
    assert calls == ["sarif"]


def test_snapshot_hashes_are_built_on_demand(report_payload) -> None:
    snapshot = build_snapshot_payload(report_payload)

    assert snapshot["graph"] == report_payload["graph"]
    assert set(snapshot["node_hashes"]) == {"n1"}
    assert isinstance(snapshot["fingerprint"], str)
    assert len(snapshot["fingerprint"]) == 64


def test_unknown_export_fails_loudly(report_payload, bounty_payload) -> None:
    with pytest.raises(ValueError, match="unknown export format"):
        render_export(report_payload, bounty_payload, "everything-at-once")
