"""Streamlit-facing scan helpers built on the core CLI/runtime stack."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any, Dict, Iterable, Optional, Sequence, Set

from config import load_finding_profile, load_ruleset
from core.runtime import CVEEnricher, MultiFileParser
from feedback import apply_feedback_scores, load_feedback_db
from models import AnalysisOptions, BountyReport, FindingProfile, SecurityConfig, TaintConfig
from reports import (
    GraphSnapshot,
    apply_baseline_and_suppressions,
    bounty_report_to_submission_markdown,
    build_bounty_report,
    export_llm_context,
    generate_poc_hints,
    render_bounty_output,
)


def _load_suppressions(path: Optional[str]) -> Set[str]:
    if not path:
        return set()
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, list):
        return {str(item) for item in raw}
    return {str(item) for item in raw.get("suppressions", [])}


def _security_config(profile: str, config_path: Optional[str]) -> SecurityConfig:
    if config_path:
        return SecurityConfig.from_file(config_path)
    if profile == "bugbounty":
        return SecurityConfig.default_bugbounty()
    if profile == "human-only":
        return SecurityConfig.default_human_only()
    return SecurityConfig.default_web()


def _finding_profile(profile: str, profile_file: Optional[str]) -> FindingProfile:
    return load_finding_profile(profile_file) if profile_file else FindingProfile.built_in(profile)


def _baseline_report(path: Optional[str]) -> Optional[BountyReport]:
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    return BountyReport(**raw)


def _clean_paths(paths: Optional[Sequence[str]]) -> list[str]:
    return [path for path in (paths or []) if path]


def _label_index(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {node["id"]: node for node in graph.get("nodes", [])}


def _build_taint_flow_cards(report_dict: Dict[str, Any], bounty_dict: Dict[str, Any]) -> list[Dict[str, Any]]:
    node_idx = _label_index(report_dict["graph"])
    cards: list[Dict[str, Any]] = []
    for idx, finding in enumerate(bounty_dict.get("findings", [])[:12], start=1):
        path_ids = finding.get("path", [])
        steps = []
        for position, node_id in enumerate(path_ids, start=1):
            node = node_idx.get(node_id, {})
            steps.append(
                {
                    "order": position,
                    "node_id": node_id,
                    "label": node.get("label", node_id),
                    "type": node.get("type", "Unknown"),
                    "file": node.get("file", ""),
                    "lineno": node.get("lineno"),
                }
            )
        cards.append(
            {
                "id": idx,
                "title": finding.get("potential_impact", finding.get("impact", f"Finding {idx}")),
                "severity": finding.get("severity", "unknown"),
                "score": finding.get("score", 0.0),
                "steps": steps,
                "source": finding.get("source_location", ""),
                "sink": finding.get("sink_location", ""),
                "explanation": finding.get("explanation", ""),
                "reachable": finding.get("reachable", False),
                "sanitization_status": finding.get("sanitization_status", "unknown"),
                "payload_hints": finding.get("payload_hints", []),
            }
        )
    return cards


def _build_graph_focus(report_dict: Dict[str, Any], bounty_dict: Dict[str, Any]) -> Dict[str, Any]:
    graph = report_dict["graph"]
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    highlighted_ids = []
    for finding in bounty_dict.get("findings", [])[:8]:
        highlighted_ids.extend(finding.get("path", []))
    highlight_set = set(highlighted_ids)
    top_nodes = nodes[:120]
    graph_nodes = [
        {
            "id": node["id"],
            "label": node.get("label", node["id"]),
            "type": node.get("type", "Unknown"),
            "file": node.get("file", ""),
            "lineno": node.get("lineno"),
            "highlighted": node["id"] in highlight_set,
        }
        for node in top_nodes
    ]
    allowed = {node["id"] for node in graph_nodes}
    graph_edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "relation": edge.get("relation", ""),
            "fragility_score": edge.get("fragility_score", 0.5),
            "highlighted": edge["source"] in highlight_set and edge["target"] in highlight_set,
        }
        for edge in edges
        if edge["source"] in allowed and edge["target"] in allowed
    ][:220]
    return {"nodes": graph_nodes, "edges": graph_edges}


def _build_cli_preview(
    workspace_path: str,
    profile: str,
    min_score: float,
    quick_mode: bool,
    use_cache: bool,
    enable_reachability: bool,
    enable_auth_checks: bool,
    only_reachable_unsanitized: bool,
) -> str:
    parts = [
        "semantic-parser",
        f"--profile {profile}",
        f"--min-score {min_score:.1f}",
    ]
    if quick_mode:
        parts.append("--quick-mode")
    if not use_cache:
        parts.append("--no-cache")
    if not enable_reachability:
        parts.append("--no-reachability")
    if not enable_auth_checks:
        parts.append("--no-auth-checks")
    if only_reachable_unsanitized:
        parts.append("--only-unsanitized-reachable")
    parts.append(f"{workspace_path} scan --format bounty-json")
    return " ".join(parts)


def _build_trace_summary(trace: list[Dict[str, Any]]) -> Dict[str, Any]:
    if not trace:
        return {"stage_count": 0, "duration_seconds": 0.0}
    return {
        "stage_count": len({event["stage"] for event in trace}),
        "duration_seconds": round(trace[-1]["ts"] - trace[0]["ts"], 2),
    }


def scan_async(
    workspace_path: str,
    profile: str = "human-only",
    min_score: float = 6.5,
    quick_mode: bool = False,
    use_cache: bool = True,
    enable_reachability: bool = True,
    enable_auth_checks: bool = True,
    only_reachable_unsanitized: bool = False,
    exclude_patterns: Optional[Iterable[str]] = None,
    config_path: Optional[str] = None,
    profile_file: Optional[str] = None,
    ruleset_path: Optional[str] = None,
    suppressions_path: Optional[str] = None,
    baseline_path: Optional[str] = None,
    feedback_db_path: Optional[str] = None,
    cve_feed_path: Optional[str] = None,
    dependency_graph_paths: Optional[Sequence[str]] = None,
    collaborator_base: str = "",
) -> Dict[str, Any]:
    """Run a full parser scan and return UI-friendly structured payloads."""
    trace: list[Dict[str, Any]] = []

    def _record(event: Dict[str, Any]) -> None:
        trace.append(event)

    started_at = time.time()
    trace.append({"ts": started_at, "stage": "plan", "message": "Preparing scan profile and parser runtime."})
    finding_profile = _finding_profile(profile, profile_file)
    security_config = _security_config(profile, config_path)
    taint_config = security_config.to_taint_config() if config_path else TaintConfig.profile(profile)
    if ruleset_path:
        taint_config = load_ruleset(ruleset_path, taint_config)
        trace.append({"ts": time.time(), "stage": "plan", "message": "Custom taint ruleset merged into active profile."})

    options = AnalysisOptions(
        quick_mode=quick_mode,
        profile=profile,
        enable_reachability=enable_reachability,
        enable_auth_checks=enable_auth_checks,
        min_score=min_score,
        only_reachable_unsanitized=only_reachable_unsanitized,
    )
    parser = MultiFileParser(
        root=workspace_path,
        security_config=security_config,
        exclude_patterns=list(exclude_patterns or []),
        options=options,
        use_cache=use_cache,
        event_callback=_record,
    )

    cve_enricher = CVEEnricher.from_feed(cve_feed_path) if cve_feed_path else None
    external_graphs = []
    for path in _clean_paths(dependency_graph_paths):
        snapshot = GraphSnapshot.load(path)
        if snapshot.full_graph:
            external_graphs.append(snapshot.full_graph)
    if external_graphs:
        trace.append(
            {
                "ts": time.time(),
                "stage": "plan",
                "message": "External dependency graphs loaded for cross-boundary resolution.",
                "dependency_graph_count": len(external_graphs),
            }
        )

    report = parser.scan(
        taint_config=taint_config,
        cve_enricher=cve_enricher,
        external_graphs=external_graphs or None,
    )
    bounty = build_bounty_report(report, profile=finding_profile, quick_mode=quick_mode)
    bounty = apply_baseline_and_suppressions(
        bounty,
        baseline=_baseline_report(baseline_path),
        suppressions=_load_suppressions(suppressions_path),
    )
    if feedback_db_path:
        bounty = apply_feedback_scores(bounty, load_feedback_db(feedback_db_path))
        trace.append({"ts": time.time(), "stage": "report", "message": "Feedback-adjusted scoring applied."})

    snapshot = GraphSnapshot.from_graph(report.graph)
    report_dict = asdict(report)
    bounty_dict = asdict(bounty)
    trace.append({"ts": time.time(), "stage": "report", "message": "Snapshot and export payloads prepared."})
    exports = {
        "scan_json": report.to_json(),
        "scan_text": report.to_text(),
        "llm_markdown": export_llm_context(report.graph, report.taint_paths),
        "bounty_json": bounty.to_json(),
        "bounty_markdown": render_bounty_output(bounty, "bounty-markdown"),
        "bounty_html": render_bounty_output(bounty, "bounty-html"),
        "web_ui_html": render_bounty_output(bounty, "bounty-html"),
        "sarif": render_bounty_output(bounty, "sarif"),
        "github_annotations": render_bounty_output(bounty, "github-annotations"),
        "gitlab_annotations": render_bounty_output(bounty, "gitlab-annotations"),
        "bitbucket_annotations": render_bounty_output(bounty, "bitbucket-annotations"),
        "submission_hackerone": bounty_report_to_submission_markdown(
            bounty, "HackerOne", collaborator_base=collaborator_base
        ),
        "submission_bugcrowd": bounty_report_to_submission_markdown(
            bounty, "Bugcrowd", collaborator_base=collaborator_base
        ),
        "poc_json": json.dumps(
            [generate_poc_hints(finding, collaborator_base=collaborator_base) for finding in bounty.findings[:10]],
            indent=2,
        ),
    }
    cli_preview = _build_cli_preview(
        workspace_path=workspace_path,
        profile=profile,
        min_score=min_score,
        quick_mode=quick_mode,
        use_cache=use_cache,
        enable_reachability=enable_reachability,
        enable_auth_checks=enable_auth_checks,
        only_reachable_unsanitized=only_reachable_unsanitized,
    )
    cli_transcript_lines = [f"$ {cli_preview}"]
    for event in trace:
        stamp = time.strftime("%H:%M:%S", time.localtime(event["ts"]))
        cli_transcript_lines.append(f"[{stamp}] [{event['stage'].upper()}] {event['message']}")
    cli_transcript = "\n".join(cli_transcript_lines)
    return {
        "report": report_dict,
        "bounty": bounty_dict,
        "exports": exports,
        "snapshot": {
            "fingerprint": snapshot.fingerprint,
            "graph": snapshot.full_graph,
            "node_hashes": snapshot._node_hashes,
            "edge_hashes": sorted(snapshot._edge_hashes),
        },
        "meta": {
            "profile": finding_profile.name,
            "profile_description": finding_profile.description,
            "min_score": min_score,
            "quick_mode": quick_mode,
            "workspace_path": workspace_path,
            "dependency_graph_count": len(external_graphs),
            "trace_summary": _build_trace_summary(trace),
            "cli_preview": cli_preview,
        },
        "trace": trace,
        "automation": {
            "cli_transcript": cli_transcript,
            "cli_preview": cli_preview,
        },
        "visuals": {
            "taint_flow_cards": _build_taint_flow_cards(report_dict, bounty_dict),
            "graph_focus": _build_graph_focus(report_dict, bounty_dict),
        },
    }
