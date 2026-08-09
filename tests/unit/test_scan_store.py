from __future__ import annotations

import json

import pytest

from scan_store import ScanArtifactStore


def _scan_result(node_count: int = 240) -> dict:
    nodes = [
        {"id": f"n{index}", "label": f"node-{index}", "type": "Variable", "file": "app.py"}
        for index in range(node_count)
    ]
    edges = [
        {"source": f"n{index}", "target": f"n{index + 1}", "relation": "dataflow"}
        for index in range(node_count - 1)
    ]
    return {
        "report": {
            "graph": {"nodes": nodes, "edges": edges},
            "taint_paths": [],
            "root": "/workspace/example",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "pii_node_count": 0,
            "taint_path_count": 0,
            "severity_summary": {},
            "top_risks": [],
            "unresolved_calls": 0,
            "cache_hits": 0,
            "cache_misses": node_count,
        },
        "bounty": {
            "root": "/workspace/example",
            "profile": "human-only",
            "quick_mode": False,
            "generated_at": 1.0,
            "summary": {"taint_path_count": 0},
            "findings": [],
        },
        "meta": {
            "profile": "human-only",
            "trace_summary": {"duration_seconds": 0.5, "stage_count": 4},
        },
        "trace": [],
        "automation": {"cli_transcript": "$ semantic-parser", "cli_preview": "semantic-parser"},
        "visuals": {"taint_flow_cards": [], "graph_focus": {"nodes": [], "edges": []}},
        "export_options": ["scan_json", "sarif"],
    }


def test_scan_is_content_addressed_and_round_trips(tmp_path) -> None:
    store = ScanArtifactStore(tmp_path)
    result = _scan_result()

    first_ref = store.store_scan(result)
    second_ref = store.store_scan(result)

    assert first_ref == second_ref
    assert len(first_ref["scan_id"]) == 64
    assert store.load_scan(first_ref["scan_id"]) == result


def test_reference_is_compact_and_contains_no_graph_or_findings(tmp_path) -> None:
    store = ScanArtifactStore(tmp_path)
    result = _scan_result()

    reference = store.store_scan(result)

    encoded_reference = json.dumps(reference)
    encoded_result = json.dumps(result)
    assert "graph" not in encoded_reference
    assert "findings" not in encoded_reference
    assert len(encoded_reference) < len(encoded_result) / 100
    assert reference["summary"]["node_count"] == 240
    assert reference["summary"]["edge_count"] == 239


def test_export_cache_is_scoped_by_format_and_options(tmp_path) -> None:
    store = ScanArtifactStore(tmp_path)
    scan_id = store.store_scan(_scan_result(2))["scan_id"]
    first_key = store.export_cache_key("sarif", {"collaborator_base": ""})
    second_key = store.export_cache_key("sarif", {"collaborator_base": "https://example.test"})

    store.store_export(scan_id, first_key, "first")
    store.store_export(scan_id, second_key, b"second")

    assert first_key != second_key
    assert store.load_export(scan_id, first_key, text=True) == "first"
    assert store.load_export(scan_id, second_key, text=False) == b"second"


def test_missing_export_returns_none_without_generating_work(tmp_path) -> None:
    store = ScanArtifactStore(tmp_path)
    scan_id = store.store_scan(_scan_result(1))["scan_id"]
    cache_key = store.export_cache_key("security_pdf", {})

    assert store.load_export(scan_id, cache_key, text=False) is None


def test_tampered_scan_artifact_fails_integrity_check_and_can_be_repaired(tmp_path) -> None:
    store = ScanArtifactStore(tmp_path)
    result = _scan_result(2)
    reference = store.store_scan(result)
    artifact = tmp_path / reference["scan_id"] / "scan.json"
    artifact.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="integrity check"):
        store.load_scan(reference["scan_id"])

    store.store_scan(result)
    assert store.load_scan(reference["scan_id"]) == result


@pytest.mark.parametrize("invalid", ["", "../escape", "A" * 64, "0" * 63, "0" * 65])
def test_invalid_artifact_identifiers_are_rejected(tmp_path, invalid) -> None:
    store = ScanArtifactStore(tmp_path)

    with pytest.raises(ValueError, match="artifact identifier"):
        store.load_scan(invalid)
