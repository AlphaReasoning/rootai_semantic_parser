"""On-demand report and snapshot export helpers."""

from __future__ import annotations

import json
from typing import Any, Dict

from models import BountyReport, ScanReport
from reports import (
    GraphSnapshot,
    bounty_report_to_submission_markdown,
    export_llm_context,
    generate_poc_hints,
    render_bounty_output,
)

EXPORT_KEYS = (
    "scan_json",
    "scan_text",
    "llm_markdown",
    "bounty_json",
    "bounty_markdown",
    "bounty_html",
    "sarif",
    "github_annotations",
    "gitlab_annotations",
    "bitbucket_annotations",
    "submission_hackerone",
    "submission_bugcrowd",
    "poc_json",
)


def render_export(
    report_payload: Dict[str, Any],
    bounty_payload: Dict[str, Any],
    export_key: str,
    *,
    collaborator_base: str = "",
) -> str:
    """Render exactly one requested export from the stored scan payload."""
    if export_key not in EXPORT_KEYS and export_key != "web_ui_html":
        raise ValueError(f"unknown export format: {export_key}")
    report = ScanReport(**report_payload)
    bounty = BountyReport(**bounty_payload)

    if export_key == "scan_json":
        return report.to_json()
    if export_key == "scan_text":
        return report.to_text()
    if export_key == "llm_markdown":
        return export_llm_context(report.graph, report.taint_paths)
    if export_key == "bounty_json":
        return bounty.to_json()
    if export_key == "bounty_markdown":
        return render_bounty_output(bounty, "bounty-markdown")
    if export_key in ("bounty_html", "web_ui_html"):
        return render_bounty_output(bounty, "bounty-html")
    if export_key == "sarif":
        return render_bounty_output(bounty, "sarif")
    if export_key == "github_annotations":
        return render_bounty_output(bounty, "github-annotations")
    if export_key == "gitlab_annotations":
        return render_bounty_output(bounty, "gitlab-annotations")
    if export_key == "bitbucket_annotations":
        return render_bounty_output(bounty, "bitbucket-annotations")
    if export_key == "submission_hackerone":
        return bounty_report_to_submission_markdown(
            bounty, "HackerOne", collaborator_base=collaborator_base
        )
    if export_key == "submission_bugcrowd":
        return bounty_report_to_submission_markdown(
            bounty, "Bugcrowd", collaborator_base=collaborator_base
        )
    return json.dumps(
        [
            generate_poc_hints(finding, collaborator_base=collaborator_base)
            for finding in bounty.findings[:10]
        ],
        indent=2,
    )


def build_snapshot_payload(report_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build graph hashes only when a snapshot or comparison is requested."""
    snapshot = GraphSnapshot.from_graph(report_payload["graph"])
    return {
        "fingerprint": snapshot.fingerprint,
        "graph": snapshot.full_graph,
        "node_hashes": snapshot._node_hashes,
        "edge_hashes": sorted(snapshot._edge_hashes),
    }
