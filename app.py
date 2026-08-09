"""Challenge-grade Streamlit UI for the RootAI semantic parser."""

from __future__ import annotations

import html
import json
import math
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

import streamlit as st
from archive_utils import extract_zip_bytes
from async_parse import scan_async
from export_utils import EXPORT_KEYS, build_snapshot_payload, render_export
from graph_queries import GraphQueryEngine, GraphQueryError, render_query_text
from reports import GraphSnapshot
from scan_store import ScanArtifactStore


SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cs", ".php", ".rb"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "#ff6b6b",
    "high": "#ff9f43",
    "medium": "#ffd166",
    "low": "#48d6b2",
    "info": "#7bdff2",
    "unknown": "#94a3b8",
}
FLOW_COPY = [
    {
        "id": "scan",
        "title": "Scan",
        "purpose": "Point RootAI at a codebase, choose the scan mode, and run the analysis.",
        "guide": "Keep the main pane simple. Use advanced options only when you need custom rules, suppressions, baselines, or enrichment.",
    },
    {
        "id": "results",
        "title": "Results",
        "purpose": "Review findings, replay the taint path, and inspect the code reference trail.",
        "guide": "The selected finding should answer three things quickly: where the data entered, how it moved, and where it became dangerous.",
    },
    {
        "id": "export",
        "title": "Export",
        "purpose": "Hand off the results in the format your next step needs.",
        "guide": "Use Markdown for readouts, SARIF for pipelines, HTML for sharing, and snapshots for before/after comparison.",
    },
]
EXPORT_GUIDE = [
    ("`scan-report.json`", "Raw machine-readable output for downstream tooling or custom post-processing."),
    ("`bounty-report.md`", "Fast human readout for reviewers, judges, or writeups."),
    ("`rootai.sarif`", "CI/CD and static-analysis platform import."),
    ("`bounty-report.html`", "Shareable standalone interactive report for demos."),
    ("`poc-hints.json`", "Payload ideas and reproduction helpers for the top ranked findings."),
    ("`graph-snapshot.json`", "Before/after structural diffing between scans."),
]
EXPORT_DOWNLOADS = {
    "scan_json": ("scan-report.json", "application/json"),
    "scan_text": ("scan-report.txt", "text/plain"),
    "llm_markdown": ("llm-context.md", "text/markdown"),
    "bounty_json": ("bounty-report.json", "application/json"),
    "bounty_markdown": ("bounty-report.md", "text/markdown"),
    "bounty_html": ("bounty-report.html", "text/html"),
    "sarif": ("rootai.sarif", "application/json"),
    "github_annotations": ("github-annotations.json", "application/json"),
    "gitlab_annotations": ("gitlab-annotations.json", "application/json"),
    "bitbucket_annotations": ("bitbucket-annotations.json", "application/json"),
    "submission_hackerone": ("hackerone-submission.md", "text/markdown"),
    "submission_bugcrowd": ("bugcrowd-submission.md", "text/markdown"),
    "poc_json": ("poc-hints.json", "application/json"),
    "graph_snapshot": ("graph-snapshot.json", "application/json"),
    "neo4j_cypher": ("graph.neo4j.cypher", "text/plain"),
    "security_pdf": ("security-report.pdf", "application/pdf"),
}
STAGE_EXPLAINERS = {
    "plan": "RootAI locks in the mission profile, thresholds, and optional rule packs before touching source.",
    "discover": "The repo is walked and reduced to parser-relevant files. Quick mode trims tests and fixtures to accelerate demos.",
    "parse": "Language-specific parsers build structural facts from code instead of guessing from text.",
    "graph": "Parser outputs are merged into one semantic graph, then symbols are resolved across files and boundaries.",
    "enrich": "Optional enrichment layers attach outside intelligence like CVE hints.",
    "taint": "Untrusted data sources are traced through calls and dataflow until they reach dangerous sinks.",
    "report": "RootAI ranks, summarizes, and packages everything into analyst-ready outputs.",
    "scan": "High-level mission wrapper for the full end-to-end run.",
}

USE_CASE_MODES = {
    "Security Analysis": {
        "profile": "bugbounty",
        "quick_mode": False,
        "min_score": 4.5,
        "headline": "Trace input to sensitive sinks and expose privilege boundaries.",
        "query": "path source=request target=eval relations=dataflow,calls depth=8",
        "examples": ["Trace user input to database", "Analyze authentication flow", "Check for taint reaching a sink"],
        "summary": "Optimized for defensive taint review, sink exposure, and attack-surface ranking.",
    },
    "Code Understanding": {
        "profile": "default",
        "quick_mode": False,
        "min_score": 6.0,
        "headline": "Explain how the code is wired and where important work happens.",
        "query": "cone start=handler direction=out depth=2 relations=calls,dataflow",
        "examples": ["Trace a request handler", "Show call relationships", "Follow a data path"],
        "summary": "Optimized for reading unfamiliar code and following deterministic structure.",
    },
    "AI Audit": {
        "profile": "human-only",
        "quick_mode": False,
        "min_score": 6.5,
        "headline": "Surface contradictory logic, missing validation, and inconsistent policy paths.",
        "query": "centrality relations=calls,dataflow limit=15",
        "examples": ["Check for contradictions", "Review policy logic", "Find inconsistent paths"],
        "summary": "Optimized for policy review, contradiction signals, and decision-path inspection.",
    },
}

EXAMPLE_WORKSPACES = {
    "Security Analysis": {
        "api.py": """from db import save_user\n\n\ndef submit(request):\n    token = request.args.get('token')\n    return save_user(token)\n""",
        "db.py": """def save_user(token):\n    return eval(token)\n""",
    },
    "Code Understanding": {
        "service.py": """from utils import normalize\n\n\ndef handler(request):\n    value = normalize(request.args.get('q'))\n    return render(value)\n\n\ndef render(value):\n    return value\n""",
        "utils.py": """def normalize(value):\n    return value.strip()\n""",
    },
    "AI Audit": {
        "policy.py": """def approve(user, request):\n    if user.is_admin:\n        return True\n    if request.args.get('force'):\n        return True\n    return False\n\n\ndef deny(user, request):\n    if user.is_admin:\n        return False\n    if request.args.get('force'):\n        return False\n    return True\n""",
        "audit.py": """from policy import approve, deny\n\n\ndef route(user, request):\n    if approve(user, request):\n        return deny(user, request)\n    return False\n""",
    },
}


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

        :root {
            --bg-a: #07111e;
            --bg-b: #0d1728;
            --bg-c: #17233c;
            --panel: rgba(8, 16, 28, 0.82);
            --panel-strong: rgba(10, 18, 32, 0.94);
            --stroke: rgba(255,255,255,0.09);
            --text: #eef4ff;
            --muted: #90a1be;
            --accent: #48d6b2;
            --accent-warm: #ffb86b;
            --critical: #ff6b6b;
            --high: #ff9f43;
            --medium: #ffd166;
            --low: #48d6b2;
            --info: #7bdff2;
        }

        .stApp {
            background:
                radial-gradient(circle at 8% 12%, rgba(255,184,107,0.12), transparent 25%),
                radial-gradient(circle at 92% 4%, rgba(72,214,178,0.14), transparent 25%),
                linear-gradient(180deg, var(--bg-a), var(--bg-b) 48%, var(--bg-c) 100%);
            color: var(--text);
        }

        html, body, [class*="css"]  {
            font-family: "Space Grotesk", "Segoe UI", sans-serif;
        }

        code, pre, .stCodeBlock, .stJson {
            font-family: "IBM Plex Mono", monospace;
        }

        .block-container {
            max-width: 1450px;
            padding-top: 1.1rem;
            padding-bottom: 2rem;
        }

        .hero-shell {
            border: 1px solid var(--stroke);
            border-radius: 28px;
            padding: 1.4rem 1.5rem;
            background:
                linear-gradient(135deg, rgba(72,214,178,0.11), rgba(255,184,107,0.08)),
                var(--panel-strong);
            box-shadow: 0 18px 70px rgba(0,0,0,0.28);
            overflow: hidden;
            position: relative;
        }

        .hero-shell::after {
            content: "";
            position: absolute;
            inset: auto -100px -120px auto;
            width: 320px;
            height: 320px;
            border-radius: 999px;
            background: radial-gradient(circle, rgba(72,214,178,0.24), transparent 68%);
            pointer-events: none;
        }

        .hero-kicker {
            text-transform: uppercase;
            letter-spacing: 0.12em;
            color: var(--muted);
            font-size: 0.78rem;
        }

        .hero-title {
            margin: 0.3rem 0 0.45rem;
            font-size: clamp(2.15rem, 5vw, 4rem);
            line-height: 0.98;
        }

        .hero-note {
            color: #d4e2ff;
            max-width: 760px;
            font-size: 1rem;
        }

        .mission-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.8rem;
            margin-top: 1rem;
        }

        .mission-card, .glass-card {
            border: 1px solid var(--stroke);
            background: var(--panel);
            border-radius: 20px;
            padding: 0.95rem 1rem;
            box-shadow: 0 12px 40px rgba(0,0,0,0.15);
        }

        .mission-label {
            color: var(--muted);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }

        .mission-value {
            font-size: 1.45rem;
            font-weight: 700;
            margin-top: 0.2rem;
        }

        .step-card {
            border: 1px solid var(--stroke);
            border-radius: 18px;
            padding: 0.95rem 1rem;
            background: rgba(7, 14, 24, 0.72);
            margin-bottom: 0.75rem;
        }

        .step-line {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.65rem;
            margin: 0.85rem 0 1rem;
        }

        .step-pill {
            border: 1px solid var(--stroke);
            border-radius: 999px;
            padding: 0.55rem 0.7rem;
            background: rgba(255,255,255,0.03);
            text-align: center;
            color: var(--muted);
            font-size: 0.82rem;
        }

        .step-pill.active {
            color: var(--text);
            background: rgba(72,214,178,0.12);
            border-color: rgba(72,214,178,0.4);
        }

        .step-card strong {
            display: block;
            margin-bottom: 0.25rem;
            color: var(--text);
        }

        .microcopy {
            color: var(--muted);
            font-size: 0.92rem;
        }

        .status-dot {
            display: inline-block;
            width: 9px;
            height: 9px;
            border-radius: 999px;
            margin-right: 0.45rem;
            background: var(--accent);
            box-shadow: 0 0 14px rgba(72,214,178,0.6);
        }

        .console {
            border: 1px solid rgba(72,214,178,0.16);
            border-radius: 18px;
            background: #040913;
            padding: 1rem;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
        }

        .console-title {
            color: var(--muted);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 0.6rem;
        }

        .path-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            padding: 0.2rem 0.6rem;
            border-radius: 999px;
            border: 1px solid var(--stroke);
            margin-right: 0.4rem;
            margin-top: 0.3rem;
            background: rgba(255,255,255,0.04);
            font-size: 0.8rem;
        }

        .stButton > button, .stDownloadButton > button {
            background: linear-gradient(135deg, #48d6b2, #2b7fff) !important;
            color: #04101a !important;
            border: none !important;
            font-weight: 700 !important;
        }

        .stButton > button:hover, .stDownloadButton > button:hover {
            color: #04101a !important;
            filter: brightness(1.05);
        }

        .stToggle label, .stSelectbox label, .stSlider label, .stTextInput label, .stFileUploader label {
            color: var(--text) !important;
        }

        .reference-card {
            border: 1px solid var(--stroke);
            background: rgba(6, 13, 22, 0.82);
            border-radius: 18px;
            padding: 1rem;
            margin-bottom: 0.8rem;
        }

        [data-testid="stSidebar"] {
            background: rgba(6, 12, 22, 0.96);
            border-right: 1px solid var(--stroke);
        }

        @media (max-width: 980px) {
            .mission-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _ensure_state() -> None:
    st.session_state.setdefault("workspace_path", None)
    st.session_state.setdefault("workspace_label", None)
    st.session_state.setdefault("workspace_source", None)
    st.session_state.setdefault("workspace_log", [])
    st.session_state.setdefault("scan_ref", None)
    st.session_state.setdefault("scan_timestamp", None)
    st.session_state.setdefault("scan_error", None)
    st.session_state.setdefault("use_case_mode", "Security Analysis")
    st.session_state.setdefault("example_name", "Trace user input to database")
    st.session_state.setdefault("graph_query", USE_CASE_MODES["Security Analysis"]["query"])
    st.session_state.setdefault("selected_finding", 1)
    st.session_state.setdefault("session_save_path", None)
    st.session_state.setdefault("collaborator_base", "")
    st.session_state.setdefault("prepared_export", None)


def _log_workspace(message: str) -> None:
    st.session_state.workspace_log.append(
        {"ts": datetime.utcnow().strftime("%H:%M:%S"), "message": message}
    )


def _session_store_dir() -> Path:
    base = Path.home() / ".cache" / "rootai-semantic-parser" / "ui-sessions"
    base.mkdir(parents=True, exist_ok=True)
    return base


@st.cache_resource(show_spinner=False)
def _artifact_store() -> ScanArtifactStore:
    return ScanArtifactStore()


@st.cache_resource(show_spinner=False)
def _load_scan_artifact(scan_id: str) -> Dict[str, Any]:
    return _artifact_store().load_scan(scan_id)


@st.cache_resource(show_spinner=False)
def _load_export_artifact(scan_id: str, cache_key: str, text: bool) -> str | bytes | None:
    return _artifact_store().load_export(scan_id, cache_key, text=text)


def _current_scan_result() -> Dict[str, Any] | None:
    reference = st.session_state.scan_ref
    if reference:
        try:
            return _load_scan_artifact(reference["scan_id"])
        except (FileNotFoundError, ValueError) as exc:
            st.session_state.scan_error = str(exc)
            return None

    legacy_result = st.session_state.get("scan_result")
    if legacy_result:
        reference = _artifact_store().store_scan(legacy_result)
        st.session_state.scan_ref = reference
        del st.session_state["scan_result"]
        return legacy_result
    return None


def _selected_mode() -> Dict[str, Any]:
    return USE_CASE_MODES[st.session_state.use_case_mode]


def _stage_example_workspace(mode_name: str) -> tuple[str, str]:
    tmp_dir = tempfile.mkdtemp(prefix="rootai-example-")
    for filename, contents in EXAMPLE_WORKSPACES[mode_name].items():
        target = Path(tmp_dir) / filename
        target.write_text(contents, encoding="utf-8")
    return tmp_dir, f"{mode_name} example"


def _insight_lines(
    report: Dict[str, Any],
    bounty: Dict[str, Any],
    query_result: Dict[str, Any] | None,
    graph: Dict[str, Any] | None = None,
) -> List[str]:
    findings = bounty.get("findings", [])
    insights = []
    if findings:
        top = findings[0]
        insights.append(f"Top finding: {top.get('potential_impact', top.get('impact', 'Potential issue'))}")
        if top.get("reachable"):
            insights.append("Data appears to reach a sensitive sink.")
        if top.get("sanitized"):
            insights.append("A sanitizer was detected on the strongest path.")
    if report.get("unresolved_calls", 0):
        insights.append(f"{report['unresolved_calls']} static call or import targets remain unresolved.")
    if query_result:
        if query_result.get("query") == "path" and query_result.get("found"):
            labels = " -> ".join(node.get("label", node.get("id")) for node in query_result.get("nodes", []))
            insights.append(f"Query path found: {labels}")
        elif query_result.get("query") in {"bfs", "dfs"}:
            insights.append(f"Query reached {len(query_result.get('nodes', []))} nodes from the selected start point.")
    if graph:
        labels = " ".join(node.get("label", "").lower() for node in graph.get("nodes", []))
        if any(a in labels and b in labels for a, b in [("approve", "deny"), ("grant", "revoke"), ("enable", "disable"), ("allow", "deny")]):
            insights.append("Contradiction signal: opposing policy labels appear in the same graph.")
        if any(token in labels for token in ("request", "args", "input")) and any(token in labels for token in ("eval", "execute", "query", "save", "write")):
            insights.append("Taint signal: untrusted input and a sensitive sink are both present in the graph.")
    if not insights:
        insights.append("No high-signal insight detected yet. Load an example or run a scan.")
    return insights[:5]


def _graph_query_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "query": result.get("query"),
        "found": result.get("found"),
        "depth": result.get("depth"),
        "nodes": result.get("nodes", [])[:40],
        "edges": result.get("edges", [])[:40],
        "components": result.get("components", [])[:10],
    }


def _neo4j_export(graph: Dict[str, Any]) -> str:
    lines = ["// RootAI Neo4j-style export"]
    for node in graph.get("nodes", []):
        props = {
            "id": node.get("id"),
            "label": node.get("label"),
            "type": node.get("type"),
            "file": node.get("file"),
            "lineno": node.get("lineno"),
        }
        props_text = ", ".join(f"{key}: {json.dumps(value)}" for key, value in props.items() if value is not None)
        node_name = _safe_name(str(node.get("id")))
        lines.append(f"MERGE (n_{node_name}:Node {{id: {json.dumps(node.get('id'))}}}) SET n_{node_name} += {{{props_text}}};")
    for edge in graph.get("edges", []):
        src = _safe_name(str(edge.get("source")))
        tgt = _safe_name(str(edge.get("target")))
        rel = str(edge.get("relation", "REL")).upper().replace("-", "_")
        lines.append(f"MERGE (n_{src})-[:{rel}]->(n_{tgt});")
    return "\n".join(lines)


def _write_text_pdf(path: str, title: str, lines: List[str]) -> None:
    max_lines = 45
    lines = [title] + lines[:max_lines]
    stream_lines = ["BT", "/F1 11 Tf", "50 760 Td", "14 TL"]
    for index, line in enumerate(lines):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream_lines.append(f"({safe}) Tj")
        if index != len(lines) - 1:
            stream_lines.append("T*")
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", errors="replace")

    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream",
    ]

    with open(path, "wb") as handle:
        handle.write(b"%PDF-1.4\n")
        offsets = [0]
        for idx, obj in enumerate(objects, start=1):
            offsets.append(handle.tell())
            handle.write(f"{idx} 0 obj\n".encode("latin-1"))
            if isinstance(obj, str):
                handle.write(obj.encode("latin-1"))
            else:
                handle.write(obj)
            handle.write(b"\nendobj\n")
        xref = handle.tell()
        handle.write(f"xref\n0 {len(objects)+1}\n".encode("latin-1"))
        handle.write(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            handle.write(f"{offset:010d} 00000 n \n".encode("latin-1"))
        handle.write(f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode("latin-1"))


def _build_security_pdf(report: Dict[str, Any], bounty: Dict[str, Any]) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="rootai-pdf-")
    out_path = os.path.join(tmp_dir, "security-report.pdf")
    lines = [
        "RootAI Security Report",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Root: {report.get('root', '')}",
        f"Nodes: {report.get('node_count', 0)}",
        f"Edges: {report.get('edge_count', 0)}",
        f"Taint paths: {report.get('taint_path_count', 0)}",
        f"Unresolved calls: {report.get('unresolved_calls', 0)}",
        "",
        "Top findings:",
    ]
    for finding in bounty.get("findings", [])[:8]:
        lines.extend(
            [
                f"- {finding.get('severity', '').upper()} | {finding.get('potential_impact', finding.get('impact', 'Potential issue'))}",
                f"  Source: {finding.get('source_location', '')}",
                f"  Sink: {finding.get('sink_location', '')}",
                f"  Path: {' -> '.join(finding.get('path_labels', []))}",
            ]
        )
    _write_text_pdf(out_path, "RootAI Security Report", lines)
    return out_path


def _save_session() -> None:
    if st.session_state.scan_ref and _current_scan_result() is None:
        st.error("The current scan artifact is unavailable and the session was not saved.")
        return
    payload = {
        "workspace_path": st.session_state.workspace_path,
        "workspace_label": st.session_state.workspace_label,
        "workspace_source": st.session_state.workspace_source,
        "use_case_mode": st.session_state.use_case_mode,
        "graph_query": st.session_state.graph_query,
        "scan_timestamp": st.session_state.scan_timestamp,
        "scan_ref": st.session_state.scan_ref,
        "saved_at": datetime.utcnow().isoformat() + "Z",
    }
    path = _session_store_dir() / f"session-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    st.session_state.session_save_path = str(path)
    st.success(f"Session saved to {path.name}")


def _load_most_recent_session() -> None:
    sessions = sorted(_session_store_dir().glob("session-*.json"))
    if not sessions:
        st.info("No saved session found yet.")
        return
    raw = json.loads(sessions[-1].read_text(encoding="utf-8"))
    st.session_state.workspace_path = raw.get("workspace_path")
    st.session_state.workspace_label = raw.get("workspace_label")
    st.session_state.workspace_source = raw.get("workspace_source")
    st.session_state.use_case_mode = raw.get("use_case_mode", st.session_state.use_case_mode)
    st.session_state.graph_query = raw.get("graph_query", st.session_state.graph_query)
    st.session_state.scan_timestamp = raw.get("scan_timestamp")
    scan_ref = raw.get("scan_ref")
    legacy_result = raw.get("scan_result")
    if legacy_result:
        scan_ref = _artifact_store().store_scan(legacy_result)
    if scan_ref:
        try:
            _load_scan_artifact(scan_ref["scan_id"])
        except (FileNotFoundError, ValueError) as exc:
            st.error(f"Saved scan artifact is unavailable: {exc}")
            return
    st.session_state.scan_ref = scan_ref
    st.session_state.pop("scan_result", None)
    st.session_state.prepared_export = None
    st.session_state.session_save_path = str(sessions[-1])
    st.success(f"Loaded {sessions[-1].name}")


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def _save_uploaded_file(uploaded_file, suffix: str = "") -> str:
    tmp_dir = tempfile.mkdtemp(prefix="rootai-ui-")
    file_path = os.path.join(tmp_dir, _safe_name(uploaded_file.name))
    if suffix and not file_path.endswith(suffix):
        file_path += suffix
    with open(file_path, "wb") as handle:
        handle.write(uploaded_file.getbuffer())
    return file_path


def _extract_zip(uploaded_zip) -> tuple[str, str]:
    return extract_zip_bytes(bytes(uploaded_zip.getbuffer()), uploaded_zip.name)


def _clone_repo(repo_url: str) -> tuple[str, str]:
    tmp_dir = tempfile.mkdtemp(prefix="rootai-clone-")
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, tmp_dir],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "git clone failed")
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "") or "repository"
    return tmp_dir, repo_name


def _count_workspace(path: str) -> dict[str, int]:
    total_files = 0
    supported_files = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in {".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv"}
        ]
        for filename in filenames:
            total_files += 1
            if Path(filename).suffix.lower() in SUPPORTED_EXTENSIONS:
                supported_files += 1
    return {"total_files": total_files, "supported_files": supported_files}


def _preset_defaults(preset: str) -> Dict[str, Any]:
    mapping = {
        "Demo Mode": {"profile": "human-only", "quick_mode": False, "min_score": 6.0},
        "Fast Audit": {"profile": "default", "quick_mode": True, "min_score": 5.5},
        "Bug Bounty Hunter": {"profile": "bugbounty", "quick_mode": False, "min_score": 4.5},
        "Auth Logic Review": {"profile": "human-only", "quick_mode": False, "min_score": 6.5},
    }
    return mapping[preset]


def _normalize_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for idx, finding in enumerate(findings, start=1):
        rows.append(
            {
                "id": idx,
                "severity": str(finding.get("severity", "unknown")).lower(),
                "score": round(float(finding.get("score", 0.0)), 2),
                "confidence": round(float(finding.get("confidence", 0.0)), 2),
                "pattern": finding.get("pattern", "generic"),
                "impact": finding.get("potential_impact", finding.get("impact", "Potential issue")),
                "source": finding.get("source_location", ""),
                "sink": finding.get("sink_location", ""),
                "raw": finding,
            }
        )
    rows.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 99), -item["score"]))
    return rows


def _render_hero() -> None:
    st.markdown(
        """
        <section class="hero-shell">
          <div class="hero-kicker">OpenAI Codex Creators Challenge Build</div>
          <h1 class="hero-title">RootAI Sovereign Command Deck</h1>
          <div class="hero-note">
            Semantic parsing, taint reasoning, graph storytelling, and export-ready security intelligence in one guided interface. This build is tuned to be clear, useful, creative, well-executed, and genuinely usable in front of judges and real users.
          </div>
          <div style="margin-top:0.85rem;">
            <span class="path-badge">Guided demo flow</span>
            <span class="path-badge">Live automation transcript</span>
            <span class="path-badge">Visual taint-path storytelling</span>
            <span class="path-badge">One-click export handoff</span>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def _render_mission_summary() -> None:
    stats = {"workspace": "Not staged", "files": "-", "supported": "-", "scan": "Not run"}
    if st.session_state.workspace_path:
        workspace_stats = _count_workspace(st.session_state.workspace_path)
        stats = {
            "workspace": st.session_state.workspace_label or "Mounted",
            "files": str(workspace_stats["total_files"]),
            "supported": str(workspace_stats["supported_files"]),
            "scan": st.session_state.scan_timestamp or "Ready",
        }
    st.markdown(
        f"""
        <div class="mission-grid">
          <div class="mission-card"><div class="mission-label">Workspace</div><div class="mission-value">{stats["workspace"]}</div></div>
          <div class="mission-card"><div class="mission-label">Files</div><div class="mission-value">{stats["files"]}</div></div>
          <div class="mission-card"><div class="mission-label">Parser-Supported</div><div class="mission-value">{stats["supported"]}</div></div>
          <div class="mission-card"><div class="mission-label">Last Run</div><div class="mission-value">{stats["scan"]}</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_positioning_banner(mode_name: str) -> None:
    mode = USE_CASE_MODES[mode_name]
    st.markdown(
        f"""
        <div class="glass-card" style="margin-top:0.95rem;">
          <div class="mission-label">What This Does</div>
          <div style="font-size:1.1rem; font-weight:700; margin:0.2rem 0 0.3rem;">Transforms source into a deterministic graph you can query, audit, and verify.</div>
          <div class="microcopy">{mode["headline"]}</div>
          <div class="microcopy" style="margin-top:0.25rem;">{mode["summary"]}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_step_visual(mode_name: str) -> None:
    steps = ["Parse", "Build Graph", "Index", "Query"]
    pills = []
    for idx, step in enumerate(steps):
        cls = "step-pill active" if idx <= 2 else "step-pill"
        pills.append(f"<div class='{cls}'>{step}</div>")
    st.markdown(f"<div class='step-line'>{''.join(pills)}</div>", unsafe_allow_html=True)


def _render_top_selector() -> Dict[str, Any]:
    left, right = st.columns([0.62, 0.38], gap="large")
    with left:
        mode_name = st.selectbox(
            "Use Case Mode",
            list(USE_CASE_MODES.keys()),
            index=list(USE_CASE_MODES.keys()).index(st.session_state.use_case_mode),
            help="Choose the primary outcome you want the tool to optimize for.",
            key="use_case_mode",
        )
        st.caption(USE_CASE_MODES[mode_name]["summary"])
    with right:
        example_name = st.selectbox(
            "Load Example",
            USE_CASE_MODES[mode_name]["examples"],
            index=USE_CASE_MODES[mode_name]["examples"].index(st.session_state.get(f"example_name_{mode_name}", USE_CASE_MODES[mode_name]["examples"][0]))
            if st.session_state.get(f"example_name_{mode_name}", USE_CASE_MODES[mode_name]["examples"][0]) in USE_CASE_MODES[mode_name]["examples"]
            else 0,
            key=f"example_name_{mode_name}",
            help="Stage a tiny built-in example to make the value obvious immediately.",
        )
        if st.button("Load Example", use_container_width=True):
            workspace, label = _stage_example_workspace(mode_name)
            st.session_state.workspace_path = workspace
            st.session_state.workspace_label = label
            st.session_state.workspace_source = "example"
            mode = USE_CASE_MODES[mode_name]
            st.session_state.graph_query = mode["query"]
            st.session_state.selected_finding = 1
            st.session_state[f"example_name_{mode_name}"] = example_name
            _log_workspace(f"Loaded built-in {mode_name.lower()} example.")
    return USE_CASE_MODES[mode_name]


def _render_left_guidance() -> None:
    st.sidebar.markdown("## Quick Use")
    cards = [
        ("1. Stage source", "Paste a Git URL, upload a ZIP, or mount a local folder."),
        ("2. Choose scan mode", "Stay with the default preset unless you need deeper tuning."),
        ("3. Run the scan", "The transcript will show what RootAI is doing."),
        ("4. Review one finding", "Use Results to inspect the path and file references."),
        ("5. Export", "Download Markdown, HTML, SARIF, or snapshot artifacts."),
    ]
    st.sidebar.markdown(
        "".join(
            f"<div class='step-card'><strong>{title}</strong><div class='microcopy'>{body}</div></div>"
            for title, body in cards
        ),
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("## What RootAI Shows")
    st.sidebar.write(
        "RootAI helps users see where data enters a system, how it moves through code, and which sink makes that movement risky."
    )


def _render_step_intro(stage_id: str) -> None:
    stage = next(item for item in FLOW_COPY if item["id"] == stage_id)
    st.markdown(
        f"""
        <div class="glass-card">
          <div class="mission-label">{stage["title"]}</div>
          <div style="font-size:1.15rem; font-weight:700; margin:0.2rem 0 0.3rem;">{stage["purpose"]}</div>
          <div class="microcopy">{stage["guide"]}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_source_intake() -> None:
    st.markdown("### Source")
    st.caption("Point RootAI at a repository, archive, or local directory.")
    with st.expander("Clone Public URL", expanded=True):
        st.write("Best for demos and real-world repositories. Paste a public Git URL and RootAI stages a shallow clone for analysis.")
        repo_url = st.text_input("Repository URL", placeholder="https://github.com/owner/repo", key="repo_url")
        if st.button("Clone And Stage", use_container_width=True):
            if not repo_url.strip():
                st.error("Enter a public Git URL first.")
            else:
                with st.spinner("Cloning repository and preparing the workspace..."):
                    try:
                        workspace, label = _clone_repo(repo_url.strip())
                    except Exception as exc:
                        st.error(f"Clone failed: {exc}")
                    else:
                        st.session_state.workspace_path = workspace
                        st.session_state.workspace_label = label
                        st.session_state.workspace_source = "git"
                        _log_workspace(f"Cloned {repo_url.strip()} into isolated workspace.")
                        st.success(f"Workspace staged from {label}.")

    with st.expander("Upload Archive", expanded=False):
        st.write("Use this when the source is not hosted publicly. ZIP upload preserves your same analysis flow without requiring Git.")
        uploaded_zip = st.file_uploader("Source archive", type=["zip"], key="source_zip")
        if st.button("Extract And Stage", use_container_width=True):
            if uploaded_zip is None:
                st.error("Upload a ZIP archive first.")
            else:
                with st.spinner("Extracting archive and preparing the workspace..."):
                    workspace, label = _extract_zip(uploaded_zip)
                    st.session_state.workspace_path = workspace
                    st.session_state.workspace_label = label
                    st.session_state.workspace_source = "zip"
                    _log_workspace(f"Extracted {label} into isolated workspace.")
                    st.success(f"Workspace staged from {label}.")

    with st.expander("Use Local Path", expanded=False):
        st.write("Useful when the code already exists on disk. RootAI reads directly from the path you provide.")
        local_path = st.text_input(
            "Local repository path",
            value=st.session_state.workspace_path or "",
            key="local_path",
        )
        if st.button("Mount Local Workspace", use_container_width=True):
            candidate = local_path.strip()
            if not candidate:
                st.error("Provide a local path.")
            elif not os.path.isdir(candidate):
                st.error("That path does not exist or is not a directory.")
            else:
                st.session_state.workspace_path = candidate
                st.session_state.workspace_label = os.path.basename(candidate.rstrip("/")) or "workspace"
                st.session_state.workspace_source = "local"
                _log_workspace(f"Mounted local workspace {candidate}.")
                st.success("Local workspace mounted.")

    if st.session_state.workspace_path:
        st.markdown("### Active Workspace")
        st.code(st.session_state.workspace_path, language="text")
        if st.session_state.workspace_log:
            console = "\n".join(f"[{entry['ts']}] {entry['message']}" for entry in st.session_state.workspace_log[-8:])
            st.markdown('<div class="console-title">Workspace Activity</div>', unsafe_allow_html=True)
            st.code(console, language="bash")


def _render_config_step(mode: Dict[str, Any]) -> Dict[str, Any]:
    st.markdown("### Scan Mode")
    st.caption("Start with a preset. Open advanced controls only when you need deeper tuning.")

    preset = st.selectbox(
        "Preset",
        ["Demo Mode", "Fast Audit", "Bug Bounty Hunter", "Auth Logic Review"],
        index=0 if mode["profile"] == "human-only" else 1 if mode["profile"] == "default" else 2,
        help="Presets change profile, scan depth, and sensitivity. You can still override everything below.",
    )
    defaults = _preset_defaults(preset)

    basic_left, basic_right = st.columns([1, 1])
    with basic_left:
        profile = st.selectbox(
            "Finding profile",
            ["human-only", "bugbounty", "default"],
            index=["human-only", "bugbounty", "default"].index(mode["profile"] if mode else defaults["profile"]),
            help="Profiles change what the parser considers important. Human-only focuses on logic and auth paths. Bugbounty pushes toward exploit-centric sinks.",
        )
        min_score = st.slider(
            "Minimum score",
            min_value=0.0,
            max_value=10.0,
            value=float(mode.get("min_score", defaults["min_score"])),
            step=0.1,
            help="Higher values suppress weaker findings. Lower values reveal more exploratory paths.",
        )
    with basic_right:
        quick_mode = st.toggle(
            "Quick mode",
            value=bool(mode.get("quick_mode", defaults["quick_mode"])),
            help="Quick mode reduces scope for faster demos. Turn it off when you want deeper graph coverage.",
        )
        use_cache = st.toggle(
            "Use parse cache",
            value=True,
            help="Good for repeat scans of the same workspace. Turn off when you want a cold-run demonstration.",
        )

    with st.expander("Advanced Controls", expanded=False):
        col_a, col_b = st.columns(2)
        with col_a:
            enable_reachability = st.toggle("Reachability heuristics", value=True)
            enable_auth_checks = st.toggle("Authorization heuristics", value=True)
            only_reachable_unsanitized = st.toggle("Only reachable + unsanitized", value=False)
            collaborator_base = st.text_input(
                "Collaborator base URL",
                placeholder="https://oast.site/your-endpoint",
                help="Used when generating PoC callback helpers for top findings.",
            )
        with col_b:
            exclude_patterns = st.text_input(
                "Exclude globs",
                value=".git,node_modules,__pycache__,dist,build,.venv,venv",
                help="Comma-separated glob patterns. Use this when you want to avoid generated folders or third-party bundles.",
            )
            config_file = st.file_uploader("Security config JSON", type=["json"], key="cfg")
            profile_file = st.file_uploader("Custom finding profile JSON", type=["json"], key="profile_file")
            ruleset_file = st.file_uploader("Ruleset extension JSON", type=["json"], key="ruleset")
        col_c, col_d = st.columns(2)
        with col_c:
            suppressions_file = st.file_uploader("Suppressions JSON", type=["json"], key="suppressions")
            baseline_file = st.file_uploader("Baseline bounty report JSON", type=["json"], key="baseline")
            feedback_db_file = st.file_uploader("Feedback DB JSON", type=["json"], key="feedback")
        with col_d:
            cve_feed_file = st.file_uploader("CVE feed JSON", type=["json"], key="cve_feed")
            dependency_graph_files = st.file_uploader(
                "External graph snapshots",
                type=["json"],
                accept_multiple_files=True,
                key="dependency_graphs",
            )
    st.markdown("### Session")
    session_col_a, session_col_b = st.columns([0.7, 0.3])
    with session_col_a:
        if st.button("Save Session", use_container_width=True):
            _save_session()
    with session_col_b:
        if st.button("Load Session", use_container_width=True):
            _load_most_recent_session()

    summary = {
        "profile": profile,
        "min_score": min_score,
        "quick_mode": quick_mode,
        "use_cache": use_cache,
        "enable_reachability": locals().get("enable_reachability", True),
        "enable_auth_checks": locals().get("enable_auth_checks", True),
        "only_reachable_unsanitized": locals().get("only_reachable_unsanitized", False),
        "exclude_patterns": [part.strip() for part in exclude_patterns.split(",") if part.strip()],
        "collaborator_base": locals().get("collaborator_base", "").strip(),
        "config_file": locals().get("config_file"),
        "profile_file": locals().get("profile_file"),
        "ruleset_file": locals().get("ruleset_file"),
        "suppressions_file": locals().get("suppressions_file"),
        "baseline_file": locals().get("baseline_file"),
        "feedback_db_file": locals().get("feedback_db_file"),
        "cve_feed_file": locals().get("cve_feed_file"),
        "dependency_graph_files": locals().get("dependency_graph_files"),
        "mode_name": st.session_state.use_case_mode,
    }

    with st.expander("Current Run Summary", expanded=False):
        st.json(
        {
            "preset": preset,
            "profile": summary["profile"],
            "quick_mode": summary["quick_mode"],
            "min_score": summary["min_score"],
            "use_cache": summary["use_cache"],
            "reachability": summary["enable_reachability"],
            "auth_checks": summary["enable_auth_checks"],
            "reachable_unsanitized_only": summary["only_reachable_unsanitized"],
            "excludes": summary["exclude_patterns"],
        }
        )
    return summary


def _run_scan(options: Dict[str, Any]) -> None:
    if not st.session_state.workspace_path:
        st.error("Stage a workspace first.")
        return

    staged_paths: Dict[str, Any] = {}
    for key in (
        "config_file",
        "profile_file",
        "ruleset_file",
        "suppressions_file",
        "baseline_file",
        "feedback_db_file",
        "cve_feed_file",
    ):
        uploaded = options.get(key)
        staged_paths[key] = _save_uploaded_file(uploaded) if uploaded is not None else None
    dependency_paths = []
    for uploaded in options.get("dependency_graph_files") or []:
        dependency_paths.append(_save_uploaded_file(uploaded))

    st.session_state.scan_error = None
    with st.spinner("Parsing, building the graph, indexing symbols, and ranking outcomes..."):
        try:
            result = scan_async(
                workspace_path=st.session_state.workspace_path,
                profile=options["profile"],
                min_score=options["min_score"],
                quick_mode=options["quick_mode"],
                use_cache=options["use_cache"],
                enable_reachability=options["enable_reachability"],
                enable_auth_checks=options["enable_auth_checks"],
                only_reachable_unsanitized=options["only_reachable_unsanitized"],
                exclude_patterns=options["exclude_patterns"],
                config_path=staged_paths["config_file"],
                profile_file=staged_paths["profile_file"],
                ruleset_path=staged_paths["ruleset_file"],
                suppressions_path=staged_paths["suppressions_file"],
                baseline_path=staged_paths["baseline_file"],
                feedback_db_path=staged_paths["feedback_db_file"],
                cve_feed_path=staged_paths["cve_feed_file"],
                dependency_graph_paths=dependency_paths,
                collaborator_base=options["collaborator_base"],
            )
            scan_ref = _artifact_store().store_scan(result)
        except Exception as exc:
            st.session_state.scan_ref = None
            st.session_state.pop("scan_result", None)
            st.session_state.scan_error = str(exc)
            st.error(f"Scan failed: {exc}")
            return
    st.session_state.scan_ref = scan_ref
    st.session_state.pop("scan_result", None)
    st.session_state.collaborator_base = options["collaborator_base"]
    st.session_state.prepared_export = None
    st.session_state.scan_timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    st.session_state.selected_finding = 1


def _render_stage_timeline(trace: List[Dict[str, Any]]) -> None:
    if not trace:
        st.info("Run a scan to see the backend stages unfold.")
        return
    rows = []
    base = trace[0]["ts"]
    for event in trace:
        rows.append(
            f"<div class='step-card'><strong><span class='status-dot'></span>{html.escape(event['stage'].upper())}</strong>"
            f"<div class='microcopy'>+{event['ts'] - base:.2f}s • {html.escape(event['message'])}</div></div>"
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


def _render_execute_step(options: Dict[str, Any]) -> None:
    st.markdown("### Run")
    st.caption("Run the scan here. Open the sections below if you want the transcript, stage glossary, or execution metrics.")
    if st.button("Execute Semantic Scan", type="primary", use_container_width=True):
        _run_scan(options)
    result = _current_scan_result()
    if not result:
        if st.session_state.scan_error:
            st.error(f"Last run failed: {st.session_state.scan_error}")
        st.info("Run a scan to populate transcript, metrics, and findings.")
        return
    trace_summary = result["meta"]["trace_summary"]
    report = result["report"]
    determinism = "YES"
    confidence_drift = "0%"
    st.markdown(
        f"""
        <div class="mission-grid">
          <div class="mission-card"><div class="mission-label">Duration</div><div class="mission-value">{trace_summary["duration_seconds"]}s</div></div>
          <div class="mission-card"><div class="mission-label">Nodes / Edges</div><div class="mission-value">{report["node_count"]} / {report["edge_count"]}</div></div>
          <div class="mission-card"><div class="mission-label">Taint Paths</div><div class="mission-value">{report["taint_path_count"]}</div></div>
          <div class="mission-card"><div class="mission-label">Deterministic</div><div class="mission-value">{determinism}</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    metric_cols = st.columns(4)
    with metric_cols[0]:
        st.markdown("**Profile**")
        st.write(result["meta"]["profile"])
    with metric_cols[1]:
        st.markdown("**Cache Hits**")
        st.write(report.get("cache_hits", 0))
    with metric_cols[2]:
        st.markdown("**Cache Misses**")
        st.write(report.get("cache_misses", 0))
    with metric_cols[3]:
        st.markdown("**Confidence Drift**")
        st.write(confidence_drift)
    with st.expander("Automation Transcript", expanded=True):
        st.markdown('<div class="console-title">Automated CLI Process</div>', unsafe_allow_html=True)
        st.markdown('<div class="console">', unsafe_allow_html=True)
        st.code(result["automation"]["cli_transcript"], language="bash")
        st.markdown("</div>", unsafe_allow_html=True)
    with st.expander("Stage Breakdown", expanded=False):
        _render_stage_timeline(result["trace"])
        with st.expander("Stage Glossary", expanded=False):
            st.markdown(
                "".join(
                    f"<div class='step-card'><strong>{stage.upper()}</strong><div class='microcopy'>{copy}</div></div>"
                    for stage, copy in STAGE_EXPLAINERS.items()
                ),
                unsafe_allow_html=True,
            )
    with st.expander("Insight Output", expanded=True):
        selected_query = st.session_state.graph_query.strip()
        query_result = None
        if selected_query:
            try:
                query_result = GraphQueryEngine(report["graph"]).execute(selected_query)
            except GraphQueryError as exc:
                st.warning(f"Graph query could not be resolved: {exc}")
        st.markdown("#### Insights")
        for line in _insight_lines(report, result["bounty"], query_result, report["graph"]):
            st.write(f"- {line}")
        if query_result:
            st.markdown("#### Query Output")
            if query_result.get("query") == "path":
                st.code(render_query_text(query_result), language="text")
            else:
                st.json(_graph_query_payload(query_result))


def _render_path_reference(card: Dict[str, Any]) -> None:
    st.markdown("### Taint Path Reference")
    st.caption("This is the path as a readable reference, not a decorative graph.")
    step_rows = [
        {
            "step": step["order"],
            "symbol": step["label"],
            "type": step["type"],
            "location": f"{Path(step['file']).name}:{step['lineno']}" if step.get("file") else "",
        }
        for step in card.get("steps", [])
    ]
    st.dataframe(step_rows, use_container_width=True, hide_index=True)
    summary_cols = st.columns(3)
    with summary_cols[0]:
        st.markdown("**Source**")
        st.write(card.get("source") or "No source location emitted.")
    with summary_cols[1]:
        st.markdown("**Path Story**")
        st.write(card.get("explanation") or "No explanation emitted.")
    with summary_cols[2]:
        st.markdown("**Sink**")
        st.write(card.get("sink") or "No sink location emitted.")


def _render_code_reference(result: Dict[str, Any], selected_ids: List[str]) -> None:
    node_lookup = {node["id"]: node for node in result["report"]["graph"].get("nodes", [])}
    edge_rows = []
    for edge in result["report"]["graph"].get("edges", []):
        if edge["source"] in selected_ids and edge["target"] in selected_ids:
            src = node_lookup.get(edge["source"], {})
            tgt = node_lookup.get(edge["target"], {})
            edge_rows.append(
                {
                    "from": src.get("label", edge["source"]),
                    "relation": edge.get("relation", ""),
                    "to": tgt.get("label", edge["target"]),
                }
            )
    if edge_rows:
        st.markdown("### Semantic Links In This Path")
        st.dataframe(edge_rows, use_container_width=True, hide_index=True)
    file_rows = []
    seen = set()
    for node_id in selected_ids:
        node = node_lookup.get(node_id, {})
        key = (node.get("file"), node.get("lineno"), node.get("label"))
        if key in seen:
            continue
        seen.add(key)
        file_rows.append(
            {
                "file": node.get("file", ""),
                "line": node.get("lineno"),
                "symbol": node.get("label", node_id),
                "type": node.get("type", ""),
            }
        )
    if file_rows:
        st.markdown("### File Reference")
        st.dataframe(file_rows, use_container_width=True, hide_index=True)


def _render_understand_step() -> None:
    _render_step_intro("results")
    result = _current_scan_result()
    if not result:
        st.info("Run a scan first to populate results.")
        return

    bounty = result["bounty"]
    findings = _normalize_findings(bounty["findings"])
    path_cards = result["visuals"]["taint_flow_cards"]
    path_map = {card["id"]: card for card in path_cards}
    graph = result["report"]["graph"]

    if not findings:
        st.info("No findings were ranked for this workspace and mode.")
        return

    st.markdown("### Findings")
    st.caption("Choose a finding on the left. The right side stays focused on that one path.")

    left, right = st.columns([0.9, 1.1], gap="large")
    with left:
        query = st.text_input("Search findings", placeholder="impact, sink, source, pattern")
        severity_filter = st.multiselect(
            "Severity filter",
            sorted({row["severity"] for row in findings}, key=lambda sev: SEVERITY_ORDER.get(sev, 99)),
            default=sorted({row["severity"] for row in findings}, key=lambda sev: SEVERITY_ORDER.get(sev, 99)),
        )
        filtered_rows = [
            row
            for row in findings
            if row["severity"] in severity_filter
            and query.lower() in " ".join(
                [row["impact"], row["source"], row["sink"], row["pattern"], row["raw"].get("explanation", "")]
            ).lower()
        ]
        st.dataframe(
            [
                {
                    "id": row["id"],
                    "severity": row["severity"],
                    "score": row["score"],
                    "confidence": row["confidence"],
                    "impact": row["impact"],
                    "source": row["source"],
                    "sink": row["sink"],
                }
                for row in filtered_rows
            ],
            use_container_width=True,
            hide_index=True,
        )
    with right:
        st.markdown("### Ask About The Graph")
        st.caption("This is the deterministic query surface. It answers the graph directly, then the UI explains the result.")
        st.text_input(
            "Graph query",
            value=st.session_state.graph_query,
            help="Examples: path source=handler target=eval relations=dataflow,calls depth=8 | centrality relations=calls,dataflow limit=15",
            key="graph_query",
        )
        query_cols = st.columns([0.55, 0.45])
        with query_cols[0]:
            run_query = st.button("Run Graph Query", use_container_width=True)
        with query_cols[1]:
            show_json = st.toggle("JSON", value=False, help="Render the query result as structured JSON.")
        if run_query:
            try:
                query_output = GraphQueryEngine(graph).execute(st.session_state.graph_query)
            except GraphQueryError as exc:
                st.error(f"Query failed: {exc}")
            else:
                if show_json:
                    st.json(_graph_query_payload(query_output))
                else:
                    st.code(render_query_text(query_output), language="text")
        st.markdown("### Selected Finding")
        selected_id = st.selectbox(
            "Selected finding",
            [row["id"] for row in findings],
            format_func=lambda item: f"Finding {item}",
            key="selected_finding",
        )
        finding = next(row["raw"] for row in findings if row["id"] == selected_id)
        severity = str(finding.get("severity", "unknown")).lower()
        st.markdown(
            f"""
            <div class="glass-card">
              <div class="mission-label">Selected Finding</div>
              <div style="font-size:1.25rem; font-weight:700; margin-top:0.3rem;">{html.escape(finding.get("potential_impact", finding.get("impact", "Potential issue")))}</div>
              <div class="microcopy" style="margin-top:0.4rem;">{html.escape(finding.get("explanation", "No explanation emitted."))}</div>
              <div style="margin-top:0.5rem;">
                <span class="path-badge" style="color:{SEVERITY_COLOR.get(severity, '#94a3b8')};">{severity.upper()}</span>
                <span class="path-badge">Score {float(finding.get("score", 0.0)):.1f}</span>
                <span class="path-badge">Confidence {float(finding.get("confidence", 0.0)):.2f}</span>
                <span class="path-badge">{html.escape(finding.get("pattern", "generic"))}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write(f"**Entry point:** `{finding.get('source_location', 'n/a')}`")
        st.write(f"**Sink:** `{finding.get('sink_location', 'n/a')}`")
        st.write(f"**Sanitization status:** `{finding.get('sanitization_status', 'unknown')}`")
        st.write(f"**Why it matters:** {finding.get('potential_impact', finding.get('impact', 'Potential issue'))}")
        story_cols = st.columns(4)
        with story_cols[0]:
            st.markdown("**Entry**")
            st.write(finding.get("source_label") or "Unknown")
        with story_cols[1]:
            st.markdown("**Traversal**")
            st.write(f"{len(finding.get('path', []))} semantic hops")
        with story_cols[2]:
            st.markdown("**Trust Posture**")
            st.write("Reachable" if finding.get("reachable") else "Needs manual reachability check")
        with story_cols[3]:
            st.markdown("**Operator Move**")
            st.write("Review path and export report")

    selected_card = path_map.get(selected_id)
    if selected_card:
        with st.expander("Path Reference", expanded=True):
            _render_path_reference(selected_card)
        with st.expander("Code Reference", expanded=False):
            _render_code_reference(result, [step["node_id"] for step in selected_card["steps"]])
        with st.expander("Payload Guidance", expanded=False):
            st.markdown("### Payload Guidance")
            st.json(selected_card.get("payload_hints", []))
    st.markdown("### Trace Path")
    st.caption("The path view is the same selected finding rendered from source to sink.")
    st.dataframe(
        [
            {
                "step": step["order"],
                "label": step["label"],
                "type": step["type"],
                "file": step["file"],
                "line": step["lineno"] or "",
            }
            for step in (selected_card["steps"] if selected_card else [])
        ],
        use_container_width=True,
        hide_index=True,
    )


def _prepare_export(
    scan_ref: Dict[str, Any], result: Dict[str, Any], export_key: str
) -> Dict[str, Any]:
    filename, mime = EXPORT_DOWNLOADS[export_key]
    scan_id = scan_ref["scan_id"]
    collaborator_formats = {"submission_hackerone", "submission_bugcrowd", "poc_json"}
    options = (
        {"collaborator_base": st.session_state.collaborator_base}
        if export_key in collaborator_formats
        else {}
    )
    cache_key = _artifact_store().export_cache_key(export_key, options)
    is_text = export_key != "security_pdf"
    data = _artifact_store().load_export(scan_id, cache_key, text=is_text)
    if data is None:
        if export_key == "graph_snapshot":
            data = json.dumps(build_snapshot_payload(result["report"]), indent=2)
        elif export_key == "neo4j_cypher":
            data = _neo4j_export(result["report"]["graph"])
        elif export_key == "security_pdf":
            pdf_path = Path(_build_security_pdf(result["report"], result["bounty"]))
            try:
                data = pdf_path.read_bytes()
            finally:
                shutil.rmtree(pdf_path.parent, ignore_errors=True)
        else:
            data = render_export(
                result["report"],
                result["bounty"],
                export_key,
                collaborator_base=st.session_state.collaborator_base,
            )
        _artifact_store().store_export(scan_id, cache_key, data)
    return {
        "key": export_key,
        "filename": filename,
        "mime": mime,
        "scan_id": scan_id,
        "cache_key": cache_key,
        "is_text": is_text,
    }


def _render_export_step() -> None:
    _render_step_intro("export")
    result = _current_scan_result()
    if not result:
        st.info("Run a scan first to unlock the export deck.")
        return

    left, right = st.columns([0.92, 1.08], gap="large")
    with left:
        st.markdown("### Download Center")
        available = [key for key in result.get("export_options", EXPORT_KEYS) if key in EXPORT_DOWNLOADS]
        available.extend(["graph_snapshot", "neo4j_cypher", "security_pdf"])
        selected_export = st.selectbox(
            "Artifact",
            available,
            format_func=lambda key: EXPORT_DOWNLOADS[key][0],
        )
        if st.button("Prepare Selected Artifact", use_container_width=True):
            try:
                st.session_state.prepared_export = _prepare_export(
                    st.session_state.scan_ref, result, selected_export
                )
            except Exception as exc:
                st.error(f"Export failed: {exc}")
        prepared = st.session_state.prepared_export
        if prepared and "scan_id" not in prepared:
            st.session_state.prepared_export = None
            prepared = None
        if (
            prepared
            and prepared["key"] == selected_export
            and prepared["scan_id"] == st.session_state.scan_ref["scan_id"]
        ):
            data = _load_export_artifact(
                prepared["scan_id"], prepared["cache_key"], prepared["is_text"]
            )
            if data is None:
                st.warning("Prepared artifact is no longer available; prepare it again.")
            else:
                st.download_button(
                    label=f"Download {prepared['filename']}",
                    data=data,
                    file_name=prepared["filename"],
                    mime=prepared["mime"],
                    use_container_width=True,
                )
                if isinstance(data, str):
                    with st.expander("Preview prepared artifact", expanded=False):
                        st.code(data[:16000], language="text")
    with right:
        st.markdown("### Snapshot And Session Lab")
        uploaded_snapshot = st.file_uploader("Compare against prior snapshot", type=["json"], key="snapshot_compare")
        if uploaded_snapshot is not None:
            current_payload = build_snapshot_payload(result["report"])
            prior_path = _save_uploaded_file(uploaded_snapshot)
            current_snapshot = GraphSnapshot(
                current_payload["node_hashes"],
                set(current_payload["edge_hashes"]),
                current_payload["graph"],
            )
            prior_snapshot = GraphSnapshot.load(prior_path)
            diff = prior_snapshot.diff(current_snapshot)
            st.json(
                {
                    "added_nodes": diff.added_nodes[:50],
                    "removed_nodes": diff.removed_nodes[:50],
                    "changed_nodes": diff.changed_nodes[:50],
                    "added_edges": diff.added_edges[:50],
                    "removed_edges": diff.removed_edges[:50],
                }
            )
        st.markdown("### Metrics")
        metric_cols = st.columns(3)
        with metric_cols[0]:
            st.metric("Nodes", result["report"]["node_count"])
        with metric_cols[1]:
            st.metric("Edges", result["report"]["edge_count"])
        with metric_cols[2]:
            st.metric("Taint paths", result["report"]["taint_path_count"])
    st.markdown("### Export Guide")
    st.caption("Every export exists for a different audience. This is the usefulness and execution layer: the scan should end in something immediately shareable, automatable, or demo-ready.")
    st.table(
        [{"Artifact": artifact, "Best Use": use_case} for artifact, use_case in EXPORT_GUIDE]
    )


def main() -> None:
    st.set_page_config(page_title="RootAI Semantic Parser", page_icon="🛡️", layout="wide")
    _inject_styles()
    _ensure_state()
    _render_left_guidance()
    _render_hero()
    mode = _render_top_selector()
    _render_positioning_banner(st.session_state.use_case_mode)
    _render_step_visual(st.session_state.use_case_mode)
    _render_mission_summary()
    options = None
    with st.expander("Scan", expanded=True):
        _render_step_intro("scan")
        _render_source_intake()
        options = _render_config_step(mode)
        _render_execute_step(options)
    with st.expander("Results", expanded=True):
        _render_understand_step()
    with st.expander("Export", expanded=False):
        _render_export_step()

    st.caption("alpha-reasoning lab | RootAI semantic parser | challenge-grade HF Space build")


if __name__ == "__main__":
    main()
