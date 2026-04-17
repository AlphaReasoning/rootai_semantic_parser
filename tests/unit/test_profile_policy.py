"""Finding-profile policy tests."""

from __future__ import annotations

from rootai_semantic_parser.models import FindingProfile, ScanReport
from rootai_semantic_parser.reports.renderers import build_bounty_report


def test_human_only_profile_filters_disabled_patterns() -> None:
    """Commodity scanner patterns should be removed from the human-only report."""
    report = ScanReport(
        graph={
            "nodes": [
                {"id": "n1", "label": "request", "file": "a.py", "type": "Function"},
                {"id": "n2", "label": "os.system", "file": "a.py", "type": "Function"},
            ],
            "edges": [],
        },
        taint_paths=[
            {
                "path": ["n1", "n2"],
                "sink_label": "os.system",
                "impact": "RCE",
                "score": 75.0,
                "confidence": 0.75,
                "severity": "high",
                "source_location": "a.py:1",
                "sink_location": "a.py:2",
                "payload_hints": [],
            }
        ],
        root=".",
        node_count=2,
        edge_count=0,
        pii_node_count=0,
        taint_path_count=1,
    )
    bounty = build_bounty_report(report, profile="human-only", quick_mode=True)
    assert bounty.findings == []
    assert bounty.summary["taint_path_count"] == 0


def test_human_only_profile_boosts_business_logic_findings() -> None:
    """Business-logic findings should receive the configured score multiplier."""
    report = ScanReport(
        graph={
            "nodes": [
                {"id": "n1", "label": "request", "file": "a.py", "type": "Function"},
                {"id": "n2", "label": "transferFunds", "file": "a.py", "type": "Function"},
            ],
            "edges": [],
        },
        taint_paths=[
            {
                "path": ["n1", "n2"],
                "sink_label": "transferFunds",
                "impact": "Generic taint sink",
                "score": 10.0,
                "confidence": 0.4,
                "severity": "high",
                "source_location": "a.py:1",
                "sink_location": "a.py:2",
                "payload_hints": [],
                "explanation": "request -> transferFunds",
            }
        ],
        root=".",
        node_count=2,
        edge_count=0,
        pii_node_count=0,
        taint_path_count=1,
    )
    bounty = build_bounty_report(report, profile="human-only", quick_mode=True)
    assert len(bounty.findings) == 1
    assert bounty.findings[0]["pattern"] == "business_logic_flaw"
    assert bounty.findings[0]["score"] == 18.0
    assert bounty.summary["profile_min_score"] == 6.5


def test_custom_profile_object_can_drive_report_policy() -> None:
    """A custom profile object should filter and rescore findings."""
    report = ScanReport(
        graph={
            "nodes": [
                {"id": "n1", "label": "request", "file": "a.py", "type": "Function"},
                {"id": "n2", "label": "checkoutOrder", "file": "a.py", "type": "Function"},
                {"id": "n3", "label": "os.system", "file": "a.py", "type": "Function"},
            ],
            "edges": [],
        },
        taint_paths=[
            {
                "path": ["n1", "n2"],
                "sink_label": "checkoutOrder",
                "impact": "Generic taint sink",
                "score": 10.0,
                "confidence": 0.4,
                "severity": "high",
                "source_location": "a.py:1",
                "sink_location": "a.py:2",
                "payload_hints": [],
                "explanation": "request -> checkoutOrder",
            },
            {
                "path": ["n1", "n3"],
                "sink_label": "os.system",
                "impact": "RCE",
                "score": 75.0,
                "confidence": 0.75,
                "severity": "high",
                "source_location": "a.py:1",
                "sink_location": "a.py:3",
                "payload_hints": [],
            },
        ],
        root=".",
        node_count=3,
        edge_count=0,
        pii_node_count=0,
        taint_path_count=2,
    )
    profile = FindingProfile(
        name="custom-human-only",
        description="Custom logic-focused policy",
        min_score=6.5,
        disabled_patterns=frozenset({"command_injection"}),
        boosted_scoring={"business_logic_flaw": 2.0},
    )
    bounty = build_bounty_report(report, profile=profile, quick_mode=True)
    assert bounty.profile == "custom-human-only"
    assert len(bounty.findings) == 1
    assert bounty.findings[0]["pattern"] == "business_logic_flaw"
    assert bounty.findings[0]["score"] == 20.0
    assert bounty.summary["profile_min_score"] == 6.5
