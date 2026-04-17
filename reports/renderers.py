"""Report renderers and CI integration formats."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Set

from models import BountyReport, FindingProfile, GraphDiff, ScanReport
from reports.markdown import bounty_report_to_markdown_table


class GraphSnapshot:
    """Serializable graph snapshot for diffing/baselines."""

    def __init__(self, node_hashes: Dict[str, str], edge_hashes: Set[str], full_graph: Optional[Dict] = None) -> None:
        self._node_hashes = node_hashes
        self._edge_hashes = edge_hashes
        self.full_graph = full_graph or {"nodes": [], "edges": []}

    @classmethod
    def from_graph(cls, graph: Dict) -> "GraphSnapshot":
        import hashlib
        return cls(
            {
                n["id"]: hashlib.sha256(json.dumps(n, sort_keys=True, default=str).encode()).hexdigest()
                for n in graph.get("nodes", [])
            },
            {
                hashlib.sha256(f"{e['source']}::{e['target']}::{e['relation']}".encode()).hexdigest()
                for e in graph.get("edges", [])
            },
            full_graph=graph,
        )

    @property
    def fingerprint(self) -> str:
        """Return a stable snapshot fingerprint."""
        import hashlib
        combined = "".join(sorted(self._node_hashes.values()) + sorted(self._edge_hashes))
        return hashlib.sha256(combined.encode()).hexdigest()

    def save(self, path: str) -> None:
        """Save snapshot to JSON."""
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "fingerprint": self.fingerprint,
                    "node_hashes": self._node_hashes,
                    "edge_hashes": list(self._edge_hashes),
                    "graph": self.full_graph,
                },
                handle,
                indent=2,
            )

    @classmethod
    def load(cls, path: str) -> "GraphSnapshot":
        """Load snapshot from JSON."""
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        return cls(raw["node_hashes"], set(raw["edge_hashes"]), raw.get("graph"))

    def diff(self, other: "GraphSnapshot") -> GraphDiff:
        """Diff two snapshots."""
        added = [nid for nid in other._node_hashes if nid not in self._node_hashes]
        removed = [nid for nid in self._node_hashes if nid not in other._node_hashes]
        changed = [nid for nid, node_hash in other._node_hashes.items() if nid in self._node_hashes and self._node_hashes[nid] != node_hash]
        return GraphDiff(
            added_nodes=added,
            removed_nodes=removed,
            changed_nodes=changed,
            added_edges=list(other._edge_hashes - self._edge_hashes),
            removed_edges=list(self._edge_hashes - other._edge_hashes),
        )


def export_llm_context(graph: Dict, taint_paths: Optional[List[Dict]] = None, token_budget: int = 4000) -> str:
    """Render a compact Markdown context export."""
    char_limit = token_budget * 4
    lines = [f"# Semantic Code Context", f"Nodes: {len(graph['nodes'])}  |  Edges: {len(graph['edges'])}", ""]
    pii = [n for n in graph["nodes"] if n.get("is_pii_sensitive")]
    if pii:
        lines.append(f"## PII-Sensitive Nodes ({len(pii)})")
        for node in pii[:20]:
            lines.append(f"- `{node['label']}` [{node['type']}] @ {node.get('file', '?')}")
        lines.append("")
    unsafe = [n for n in graph["nodes"] if n.get("is_unsafe")]
    if unsafe:
        lines.append(f"## Unsafe / Tainted Nodes ({len(unsafe)})")
        for node in unsafe[:20]:
            lines.append(f"- `{node['label']}` [{node['type']}] @ {node.get('file', '?')}:{node.get('lineno', '?')}")
        lines.append("")
    if taint_paths:
        node_idx = {n["id"]: n for n in graph["nodes"]}
        lines.append(f"## Taint Paths ({len(taint_paths)})")
        for tp_dict in taint_paths[:20]:
            path_labels = [node_idx.get(nid, {}).get("label", nid) for nid in tp_dict.get("path", [])]
            lines.append(f"- [{tp_dict.get('severity', 'high').upper()}] " + " -> ".join(path_labels))
        lines.append("")
    full_text = "\n".join(lines)
    if len(full_text) > char_limit:
        truncated = full_text[:char_limit]
        last_newline = truncated.rfind("\n")
        return truncated[:last_newline] + "\n\n...[Context Truncated due to Token Budget] ..."
    return full_text


def classify_finding_pattern(finding: Dict[str, Any]) -> str:
    """Classify a finding into a normalized pattern key."""
    sink = str(finding.get("sink_label", "")).lower()
    impact = str(finding.get("impact", "")).lower()
    explanation = str(finding.get("explanation", "")).lower()
    path = " ".join(str(item).lower() for item in finding.get("path_labels", []))
    text = " ".join(part for part in (sink, impact, explanation, path) if part)

    if any(token in text for token in ("os.system", "subprocess.run", "processbuilder", "shell_exec", "passthru", "exec.command", " eval", "exec(", " compile")):
        return "command_injection"
    if any(token in text for token in ("sql injection", "cursor.execute", "db.execute", "jdbc", " query ", " sql")):
        return "sql_injection"
    if any(token in text for token in ("innerhtml", "xss", "html injection")):
        return "xss"
    if any(token in text for token in ("redirect", "returnurl", "next=", "callback=")):
        return "open_redirect"
    if any(token in text for token in ("ssrf", "fetch(", "httpclient", "urlopen", "requests.", "axios", "webclient", "curl")):
        return "ssrf"
    if any(token in text for token in ("../", "path traversal", "filepath", "readfile", "writefile", "open(")):
        return "path_traversal"
    if any(token in text for token in ("header", "x-forwarded", "authorization header")):
        return "header_leak"
    if any(token in text for token in ("log", "logger", "audit")) and any(
        token in text for token in ("password", "secret", "token", "credential", "authorization")
    ):
        return "credential_logging"
    if any(token in text for token in ("idor", "direct object reference")):
        return "idor"
    if any(token in text for token in ("grantadmin", "setrole", "assumerole", "privilege", "admin role", "elevation")):
        return "privilege_escalation"
    if any(token in text for token in ("session", "mfa", "otp", "passwordreset", "unlock")):
        return "weak_session_management"
    if any(token in text for token in ("authorize", "authorization", "permission", "access control", "resourceowner", "ownership")):
        return "improper_access_control"
    if any(token in text for token in ("workflow", "approve", "approval", "step", "state transition")):
        return "workflow_bypass"
    if any(token in text for token in ("checkout", "refund", "redeem", "transfer", "withdraw", "override", "featureflag")):
        return "business_logic_flaw"
    if any(token in text for token in ("race", "concurrent", "compareandset")):
        return "race_condition"
    if any(token in text for token in ("multi-step", "multistep", "step 1", "step 2")):
        return "broken_multi_step_flow"
    if any(token in text for token in ("throttle", "rate limit", "quota", "limit")):
        return "missing_rate_limit"
    if any(token in text for token in ("inconsistent auth", "auth mismatch")):
        return "inconsistent_auth"
    if any(token in text for token in ("audit gap", "missing log", "insufficient logging")):
        return "insufficient_logging"
    return "generic"


def apply_finding_profile(findings: List[Dict[str, Any]], profile: FindingProfile) -> List[Dict[str, Any]]:
    """Apply pattern filtering and score boosts for a profile."""
    filtered: List[Dict[str, Any]] = []
    disabled_patterns = profile.effective_disabled_patterns
    for finding in findings:
        enriched = dict(finding)
        pattern = classify_finding_pattern(enriched)
        enriched["pattern"] = pattern
        if pattern in disabled_patterns:
            continue
        multiplier = float(profile.boosted_scoring.get(pattern, 1.0))
        if multiplier != 1.0:
            enriched["score"] = round(float(enriched.get("score", 0.0)) * multiplier, 2)
            if "confidence" in enriched:
                enriched["confidence"] = max(
                    0.0,
                    min(round(float(enriched.get("confidence", 0.0)) * multiplier, 4), 1.0),
                )
        filtered.append(enriched)
    filtered.sort(key=lambda item: float(item.get("score", 0.0)), reverse=True)
    return filtered


def build_bounty_report(
    report: ScanReport, profile: str | FindingProfile, quick_mode: bool
) -> BountyReport:
    """Build a hunter-oriented report from a scan report."""
    node_idx = {node["id"]: node for node in report.graph.get("nodes", [])}
    profile_def = profile if isinstance(profile, FindingProfile) else FindingProfile.built_in(profile)
    findings: List[Dict[str, Any]] = []
    for finding in report.taint_paths:
        enriched = dict(finding)
        enriched["path_labels"] = [node_idx.get(nid, {}).get("label", nid) for nid in finding.get("path", [])]
        findings.append(enriched)
    findings = apply_finding_profile(findings, profile_def)
    filtered_severity_summary: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", ""))
        if severity:
            filtered_severity_summary[severity] = filtered_severity_summary.get(severity, 0) + 1
    if findings:
        filtered_severity_summary["total"] = len(findings)
    summary = {
        "root": report.root,
        "node_count": report.node_count,
        "edge_count": report.edge_count,
        "taint_path_count": len(findings),
        "severity_summary": filtered_severity_summary or report.severity_summary,
        "unresolved_calls": report.unresolved_calls,
        "cache_hits": report.cache_hits,
        "cache_misses": report.cache_misses,
        "profile_description": profile_def.description,
        "profile_min_score": profile_def.min_score,
    }
    slim_graph = {
        "nodes": [{"id": n["id"], "label": n.get("label"), "file": n.get("file"), "lineno": n.get("lineno"), "type": n.get("type")} for n in report.graph.get("nodes", [])],
        "edges": [{"source": e["source"], "target": e["target"], "relation": e["relation"]} for e in report.graph.get("edges", [])],
    }
    return BountyReport(root=report.root, profile=profile_def.name, quick_mode=quick_mode, generated_at=time.time(), summary=summary, findings=findings, graph=slim_graph)


def generate_poc_hints(finding: Dict[str, Any], collaborator_base: str = "") -> Dict[str, Any]:
    """Generate one-click PoC helpers for a finding."""
    sink = str(finding.get("sink_label", "")).lower()
    source = str(finding.get("source_label", "input"))
    collab = collaborator_base.rstrip("/")
    token = finding_fingerprint(finding)[:12]
    callback = f"{collab}/{token}" if collab else f"https://interactsh.invalid/{token}"
    curl = f"curl -i 'https://target.example/path?{source}=id'"
    repeater = f"GET /path?{source}=id HTTP/1.1\\nHost: target.example\\n\\n"
    if "ssrf" in sink or "url" in sink:
        curl = f"curl -i 'https://target.example/path?{source}={callback}'"
        repeater = f"GET /path?{source}={callback} HTTP/1.1\\nHost: target.example\\n\\n"
    if any(token_name in sink for token_name in ("eval", "exec", "subprocess", "system", "processbuilder")):
        curl = f"curl -i 'https://target.example/path?{source}=id'"
        repeater = f"POST /path HTTP/1.1\\nHost: target.example\\nContent-Type: application/json\\n\\n{{\"{source}\":\"id\"}}"
    return {
        "curl": curl,
        "burp_repeater": repeater,
        "collaborator": callback,
    }


def bounty_report_to_submission_markdown(bounty: BountyReport, platform: str, collaborator_base: str = "") -> str:
    """Render a HackerOne/Bugcrowd-ready Markdown report."""
    lines = [f"# {platform} Submission Draft", ""]
    for idx, finding in enumerate(bounty.findings[:10], start=1):
        poc = generate_poc_hints(finding, collaborator_base=collaborator_base)
        lines.extend(
            [
                f"## Finding {idx}: {finding.get('potential_impact', finding.get('impact'))}",
                f"Confidence: {finding.get('confidence', 0):.2f}",
                f"Exploitability: {finding.get('exploitability', 'unconfirmed')}",
                f"Source: {finding.get('source_location', '')}",
                f"Sink: {finding.get('sink_location', '')}",
                f"Flow: {finding.get('explanation', '')}",
                f"Sanitization: {finding.get('sanitization_status', 'unknown')}",
                "",
                "### Reproduction",
                "```bash",
                poc["curl"],
                "```",
                "",
                "### Burp Repeater",
                "```http",
                poc["burp_repeater"],
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def bounty_report_to_web_ui(bounty: BountyReport) -> str:
    """Render a standalone upload/report landing page."""
    report_html = bounty.to_html()
    return report_html.replace("<h1>Bounty Report</h1>", "<h1>RootAI Web UI</h1><p class=\"muted\">Upload repo or GitHub link in hosted mode; this local build renders an interactive report view.</p>")


def finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Generate a stable finding fingerprint."""
    import hashlib
    payload = "|".join(
        [
            str(finding.get("impact", "")),
            str(finding.get("source_location", "")),
            str(finding.get("sink_location", "")),
            "->".join(str(item) for item in finding.get("path_labels", [])),
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def bounty_report_to_sarif(bounty: BountyReport) -> str:
    """Render SARIF output for AppSec tooling."""
    results = []
    for finding in bounty.findings:
        rule_id = finding.get("impact", "generic").replace(" ", "_").lower()
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.get("severity") == "critical" else "warning",
                "message": {"text": f"{finding.get('potential_impact', finding.get('impact', 'Potential issue'))} | exploitability={finding.get('exploitability', 'unconfirmed')} | {finding.get('explanation', ' -> '.join(finding.get('path_labels', [])))}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.get("sink_location", "")).split(":")[0]},
                            "region": {"startLine": int(str(finding.get("sink_location", "0:0")).split(":")[-1] or 1)},
                        }
                    }
                ],
                "fingerprints": {"rootaiFinding": finding_fingerprint(finding)},
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "rootai-semantic-parser", "informationUri": "https://example.invalid"}}, "results": results}],
    }
    return json.dumps(sarif, indent=2)


def bounty_report_to_annotations(bounty: BountyReport, provider: str) -> str:
    """Render simple annotation payloads for CI providers."""
    items = []
    for finding in bounty.findings:
        items.append(
            {
                "provider": provider,
                "fingerprint": finding_fingerprint(finding),
                "severity": finding.get("severity"),
                "message": f"{finding.get('potential_impact', finding.get('impact'))}: {finding.get('explanation', ' -> '.join(finding.get('path_labels', [])))}",
                "path": str(finding.get("sink_location", "")).split(":")[0],
                "location": finding.get("sink_location"),
            }
        )
    return json.dumps(items, indent=2)


def apply_baseline_and_suppressions(
    bounty: BountyReport,
    baseline: Optional[BountyReport] = None,
    suppressions: Optional[Set[str]] = None,
) -> BountyReport:
    """Filter findings already present in a baseline or suppression file."""
    baseline_fingerprints = {finding_fingerprint(item) for item in (baseline.findings if baseline else [])}
    suppression_set = suppressions or set()
    filtered = [
        finding
        for finding in bounty.findings
        if finding_fingerprint(finding) not in baseline_fingerprints
        and finding_fingerprint(finding) not in suppression_set
    ]
    bounty.findings = filtered
    bounty.summary["taint_path_count"] = len(filtered)
    return bounty


def render_bounty_output(bounty: BountyReport, fmt: str) -> str:
    """Render bounty output in a requested format."""
    if fmt == "bounty-html":
        return bounty.to_html()
    if fmt == "bounty-markdown":
        return bounty_report_to_markdown_table(bounty)
    if fmt == "sarif":
        return bounty_report_to_sarif(bounty)
    if fmt == "github-annotations":
        return bounty_report_to_annotations(bounty, "github")
    if fmt == "gitlab-annotations":
        return bounty_report_to_annotations(bounty, "gitlab")
    if fmt == "bitbucket-annotations":
        return bounty_report_to_annotations(bounty, "bitbucket")
    return bounty.to_json()
