"""Stable data models and report types."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple


class NodeType(str, Enum):
    """Supported graph node types."""

    MODULE = "Module"
    CLASS = "Class"
    STRUCT = "Struct"
    FUNCTION = "Function"
    VARIABLE = "Variable"
    UNSAFE = "Unsafe"
    INTERFACE = "Interface"
    CONTROL = "ControlNode"
    DATA = "DataNode"
    MODULE_ND = "ModuleNode"

    @classmethod
    def plumbing(cls) -> FrozenSet["NodeType"]:
        """Return synthetic plumbing node types."""
        return frozenset({cls.CONTROL, cls.DATA, cls.MODULE_ND})


class EdgeRelation(str, Enum):
    """Supported graph edge relations."""

    CALLS = "calls"
    DATAFLOW = "dataflow"
    IMPORTS = "imports"
    IMPLEMENTS = "implements"
    UNSAFE_ACCESS = "unsafe_access"
    INHERITS = "inherits"


class LogicClass(str, Enum):
    """Security logic classification for a node."""

    NEUTRAL = "neutral"
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"

    @property
    def rank(self) -> int:
        """Return the severity rank used for merges."""
        return _LOGIC_RANK[self.value]

    @classmethod
    def merge(cls, a: "LogicClass", b: "LogicClass") -> "LogicClass":
        """Merge logic classes by rank."""
        return a if a.rank >= b.rank else b


_LOGIC_RANK: Dict[str, int] = {
    "neutral": 0,
    "read": 1,
    "write": 2,
    "destructive": 3,
}
VALID_NODE_TYPES: FrozenSet[str] = frozenset(t.value for t in NodeType)
VALID_EDGE_RELATIONS: FrozenSet[str] = frozenset(r.value for r in EdgeRelation)


@dataclass
class TaintConfig:
    """Taint source, sink, and sanitizer definitions."""

    sources: Set[str] = field(
        default_factory=lambda: {
            "request.form",
            "request.args",
            "request.json",
            "request.data",
            "r.URL",
            "r.Body",
            "os.Args",
            "env::var",
            "stdin",
            "params",
            "os.environ",
            "sys.argv",
            "input",
            "request",
            "req",
            "r.form",
            "r.args",
        }
    )
    sinks: Set[str] = field(
        default_factory=lambda: {
            "os.system",
            "exec.Command",
            "eval",
            "db.execute",
            "unsafe",
            "innerHTML",
            "subprocess.run",
            "cursor.execute",
            "exec",
            "compile",
            "pickle.loads",
            "yaml.load",
        }
    )
    sanitizers: Set[str] = field(
        default_factory=lambda: {
            "int",
            "float",
            "html.escape",
            "strconv.Atoi",
            "sanitize",
            "escape",
            "validate",
            "bleach.clean",
            "re.escape",
            "shlex.quote",
        }
    )
    critical_sinks: Set[str] = field(
        default_factory=lambda: {
            "eval",
            "os.system",
            "exec",
            "compile",
            "cursor.execute",
            "subprocess.run",
            "pickle.loads",
        }
    )

    @classmethod
    def profile(cls, name: str = "default") -> "TaintConfig":
        """Load a built-in taint profile."""
        normalized = (name or "default").strip().lower()
        base = cls()
        if normalized in {"default", "web", "generic"}:
            return base
        if normalized == "human-only":
            return cls(
                sources=base.sources
                | {
                    "request.headers.authorization",
                    "cookie",
                    "session",
                    "session.user",
                    "currentuser",
                    "principal",
                    "claims",
                    "jwt",
                    "token",
                    "graphqlcontext",
                    "resolver",
                    "ctx.args",
                    "args.input",
                    "message.value",
                },
                sinks={
                    "grantadmin",
                    "setrole",
                    "assumerole",
                    "permission",
                    "authorize",
                    "authorization",
                    "workflow",
                    "approve",
                    "checkout",
                    "refund",
                    "redeem",
                    "transfer",
                    "withdraw",
                    "limit",
                    "quota",
                    "override",
                    "featureflag",
                    "session",
                    "mfa",
                    "otp",
                    "passwordreset",
                    "unlock",
                },
                sanitizers=base.sanitizers
                | {
                    "authorize",
                    "isauthorized",
                    "haspermission",
                    "require_role",
                    "requirepermission",
                    "ownershipcheck",
                    "resourceowner",
                    "workflow.validate",
                    "stateguard",
                    "compareandset",
                    "transaction",
                },
                critical_sinks={
                    "grantadmin",
                    "setrole",
                    "assumerole",
                    "permission",
                    "authorize",
                    "authorization",
                    "refund",
                    "redeem",
                    "transfer",
                    "withdraw",
                    "passwordreset",
                    "mfa",
                    "otp",
                    "override",
                },
            )
        if normalized != "bugbounty":
            raise ValueError(f"Unsupported taint profile '{name}'")

        return cls(
            sources=base.sources
            | {
                "graphql.resolveinfo",
                "graphqlcontext",
                "resolver",
                "ctx.args",
                "args.input",
                "grpc.serverstream",
                "grpc.unaryrequest",
                "kafkaconsumer",
                "consumerrecord",
                "message.value",
                "redis.get",
                "redis.hget",
                "jwt.decode",
                "jwt.verify",
                "jsonwebtoken.verify",
                "aws event",
                "s3event",
                "snsrecord",
                "sqsrecord",
                "apigatewayproxyevent",
                "request.headers.authorization",
                "cookie",
            },
            sinks=base.sinks
            | {
                "runtime.getruntime().exec",
                "processbuilder",
                "system(",
                "shell_exec",
                "passthru",
                "proc_open",
                "unserialize",
                "marshal.load",
                "jsonpickle.decode",
                "objectinputstream",
                "execjs.eval",
                "graphql.mutation",
                "resolver.mutation",
                "redis.set",
                "redis.eval",
                "kafka.produce",
                "sns.publish",
                "sqs.send_message",
                "lambda.invoke",
                "sts.assumerole",
                "iam.put",
                "admin",
                "setrole",
                "grantadmin",
                "writefile",
                "open(",
            },
            sanitizers=base.sanitizers
            | {
                "jwt.decode_complete",
                "verify_signature",
                "parameterized",
                "preparedstatement",
                "allowlist",
                "schema.validate",
            },
            critical_sinks=base.critical_sinks
            | {
                "runtime.getruntime().exec",
                "processbuilder",
                "shell_exec",
                "passthru",
                "proc_open",
                "unserialize",
                "marshal.load",
                "jsonpickle.decode",
                "sts.assumerole",
                "iam.put",
                "grantadmin",
            },
        )


@dataclass(frozen=True)
class FindingProfile:
    """Finding filtering and scoring policy for a named profile."""

    name: str
    description: str
    min_score: float = 0.0
    disabled_patterns: FrozenSet[str] = frozenset()
    boosted_scoring: Mapping[str, float] = field(default_factory=dict)

    @property
    def effective_disabled_patterns(self) -> FrozenSet[str]:
        """Return disabled patterns after resolving boost/disable conflicts."""
        focus_patterns = (
            {
                "workflow_bypass",
                "inconsistent_auth",
                "privilege_escalation",
                "business_logic_flaw",
                "race_condition",
                "broken_multi_step_flow",
                "improper_access_control",
                "weak_session_management",
            }
            if self.name == "human-only"
            else set()
        )
        return frozenset(
            pattern
            for pattern in self.disabled_patterns
            if pattern not in self.boosted_scoring and pattern not in focus_patterns
        )

    @classmethod
    def built_in(cls, name: str = "default") -> "FindingProfile":
        """Return a built-in finding profile."""
        normalized = (name or "default").strip().lower()
        if normalized in {"default", "web", "generic"}:
            return cls(
                name="default",
                description="Generic semantic taint profile with no pattern filtering.",
            )
        if normalized == "bugbounty":
            return cls(
                name="bugbounty",
                description="Bug-bounty focused profile tuned for exploit-centric paths.",
            )
        if normalized == "human-only":
            return cls(
                name="human-only",
                description="Focus on logic, business, and auth flaws that scanners usually miss.",
                min_score=6.5,
                disabled_patterns=frozenset(
                    {
                        "ssrf",
                        "header_leak",
                        "credential_logging",
                        "idor",
                        "path_traversal",
                        "command_injection",
                        "sql_injection",
                        "xss",
                        "open_redirect",
                        "missing_rate_limit",
                        "workflow_bypass",
                        "inconsistent_auth",
                        "privilege_escalation",
                        "business_logic_flaw",
                        "race_condition",
                        "broken_multi_step_flow",
                        "improper_access_control",
                        "weak_session_management",
                        "insufficient_logging",
                    }
                ),
                boosted_scoring={
                    "business_logic_flaw": 1.8,
                    "workflow_bypass": 1.6,
                    "race_condition": 1.5,
                },
            )
        raise ValueError(f"Unsupported finding profile '{name}'")

    @classmethod
    def supported_names(cls) -> Tuple[str, ...]:
        """Return supported built-in profile names."""
        return ("default", "bugbounty", "human-only")


@dataclass
class SecurityConfig:
    """Security classification and taint defaults."""

    pii_functions: Set[str] = field(default_factory=set)
    destructive_functions: Set[str] = field(default_factory=set)
    write_functions: Set[str] = field(default_factory=set)
    read_only_functions: Set[str] = field(default_factory=set)
    pii_variable_patterns: Set[str] = field(default_factory=set)
    taint_sources: Set[str] = field(default_factory=set)
    taint_sinks: Set[str] = field(default_factory=set)
    taint_sanitizers: Set[str] = field(default_factory=set)
    taint_critical_sinks: Set[str] = field(default_factory=set)
    stack: str = "generic"

    def classify_node(
        self, label: str, node_type: Optional[str] = None
    ) -> Tuple[bool, LogicClass]:
        """Classify node sensitivity and logic behavior."""
        if node_type and node_type in {t.value for t in NodeType.plumbing()}:
            return False, LogicClass.NEUTRAL
        name = label.lower()
        is_pii = any(p in name for p in self.pii_functions) or any(
            p in name for p in self.pii_variable_patterns
        )
        logic = LogicClass.NEUTRAL
        if any(d in name for d in self.destructive_functions):
            logic = LogicClass.DESTRUCTIVE
        elif any(w in name for w in self.write_functions):
            logic = LogicClass.WRITE
        elif any(r in name for r in self.read_only_functions):
            logic = LogicClass.READ
        return is_pii, logic

    def to_taint_config(self) -> TaintConfig:
        """Convert security config into a taint config."""
        base = TaintConfig()
        return TaintConfig(
            sources=self.taint_sources or base.sources,
            sinks=self.taint_sinks or base.sinks,
            sanitizers=self.taint_sanitizers or base.sanitizers,
            critical_sinks=self.taint_critical_sinks or base.critical_sinks,
        )

    @classmethod
    def default_web(cls) -> "SecurityConfig":
        """Return default web security semantics."""
        return cls(
            stack="web",
            pii_functions={
                "email",
                "password",
                "ssn",
                "credit_card",
                "token",
                "secret",
                "api_key",
                "auth",
            },
            destructive_functions={"delete", "drop", "truncate", "remove", "destroy"},
            write_functions={"post", "put", "patch", "insert", "update", "write", "save"},
            read_only_functions={"get", "fetch", "read", "select", "query", "list"},
            pii_variable_patterns={"_pii", "_secret", "_key", "_pass", "_token"},
        )

    @classmethod
    def default_go(cls) -> "SecurityConfig":
        """Return default Go security semantics."""
        return cls(
            stack="go",
            pii_functions={"email", "password", "token", "secret"},
            destructive_functions={"delete", "drop", "remove"},
            write_functions={"write", "insert", "update", "put", "post"},
            read_only_functions={"get", "read", "fetch", "query", "list"},
            pii_variable_patterns={"PII", "Secret", "Token", "Pass"},
        )

    @classmethod
    def default_bugbounty(cls) -> "SecurityConfig":
        """Return the bug-bounty tuned security profile."""
        taint = TaintConfig.profile("bugbounty")
        return cls(
            stack="bugbounty",
            pii_functions={
                "email",
                "password",
                "token",
                "secret",
                "api_key",
                "jwt",
                "session",
                "customer",
                "profile",
                "ssn",
            },
            destructive_functions={
                "delete",
                "drop",
                "destroy",
                "remove",
                "truncate",
                "exec",
                "eval",
                "deserialize",
            },
            write_functions={
                "create",
                "insert",
                "update",
                "patch",
                "write",
                "save",
                "publish",
                "set",
                "grant",
                "assume_role",
            },
            read_only_functions={"get", "list", "fetch", "read", "query", "resolve"},
            pii_variable_patterns={"_secret", "_token", "_jwt", "_session", "_password", "_key"},
            taint_sources=set(taint.sources),
            taint_sinks=set(taint.sinks),
            taint_sanitizers=set(taint.sanitizers),
            taint_critical_sinks=set(taint.critical_sinks),
        )

    @classmethod
    def default_human_only(cls) -> "SecurityConfig":
        """Return a business-logic and auth-focused security profile."""
        taint = TaintConfig.profile("human-only")
        return cls(
            stack="human-only",
            pii_functions={
                "account",
                "customer",
                "identity",
                "profile",
                "session",
                "token",
                "wallet",
                "balance",
                "cart",
                "checkout",
            },
            destructive_functions={
                "grant",
                "assume",
                "override",
                "approve",
                "refund",
                "redeem",
                "transfer",
                "withdraw",
                "reset",
                "unlock",
                "disable_mfa",
            },
            write_functions={
                "approve",
                "checkout",
                "complete",
                "refund",
                "redeem",
                "transfer",
                "withdraw",
                "grant",
                "assign",
                "reset",
                "unlock",
                "override",
            },
            read_only_functions={"get", "list", "fetch", "read", "status", "preview"},
            pii_variable_patterns={
                "_session",
                "_token",
                "_role",
                "_balance",
                "_wallet",
                "_limit",
                "_quota",
            },
            taint_sources=set(taint.sources),
            taint_sinks=set(taint.sinks),
            taint_sanitizers=set(taint.sanitizers),
            taint_critical_sinks=set(taint.critical_sinks),
        )

    @classmethod
    def from_file(cls, path: str) -> "SecurityConfig":
        """Load config from JSON."""
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        return cls(
            stack=raw.get("stack", "generic"),
            pii_functions=set(raw.get("pii_functions", [])),
            destructive_functions=set(raw.get("destructive_functions", [])),
            write_functions=set(raw.get("write_functions", [])),
            read_only_functions=set(raw.get("read_only_functions", [])),
            pii_variable_patterns=set(raw.get("pii_variable_patterns", [])),
            taint_sources=set(raw.get("taint_sources", [])),
            taint_sinks=set(raw.get("taint_sinks", [])),
            taint_sanitizers=set(raw.get("taint_sanitizers", [])),
            taint_critical_sinks=set(raw.get("taint_critical_sinks", [])),
        )

    def to_file(self, path: str) -> None:
        """Write config to JSON."""
        data = {
            "stack": self.stack,
            "pii_functions": sorted(self.pii_functions),
            "destructive_functions": sorted(self.destructive_functions),
            "write_functions": sorted(self.write_functions),
            "read_only_functions": sorted(self.read_only_functions),
            "pii_variable_patterns": sorted(self.pii_variable_patterns),
            "taint_sources": sorted(self.taint_sources),
            "taint_sinks": sorted(self.taint_sinks),
            "taint_sanitizers": sorted(self.taint_sanitizers),
            "taint_critical_sinks": sorted(self.taint_critical_sinks),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)


@dataclass(frozen=True)
class AnalysisOptions:
    """Analysis execution options."""

    quick_mode: bool = False
    profile: str = "default"
    enable_reachability: bool = True
    enable_auth_checks: bool = True
    min_score: float = 0.0
    only_reachable_unsanitized: bool = False
    suppress_test_files: bool = True
    suppress_dead_code: bool = True
    suppress_library_code: bool = False


@dataclass
class Node:
    """Graph node."""

    id: str
    type: str
    label: str
    file: str
    lineno: Optional[int] = None
    qualified_name: Optional[str] = None
    language: str = "python"
    is_pii_sensitive: bool = False
    logic_class: str = LogicClass.NEUTRAL.value
    is_unsafe: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate node values after creation."""
        if self.type not in VALID_NODE_TYPES:
            raise ValueError(f"Invalid NodeType '{self.type}'. Valid: {sorted(VALID_NODE_TYPES)}")
        if isinstance(self.logic_class, LogicClass):
            self.logic_class = self.logic_class.value
        self.metadata.setdefault("symbol", self.label)
        self.metadata.setdefault("file_scope", self.file)


@dataclass
class Edge:
    """Graph edge."""

    source: str
    target: str
    relation: str
    fragility_score: float = 0.5
    is_logic_mismatch: bool = False
    cve_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate edge values after creation."""
        if self.relation not in VALID_EDGE_RELATIONS:
            raise ValueError(f"Invalid EdgeRelation '{self.relation}'.")
        if isinstance(self.relation, EdgeRelation):
            self.relation = self.relation.value


@dataclass
class TaintPath:
    """Ranked taint path result."""

    source_id: str
    sink_id: str
    path: List[str]
    sanitized: bool = False
    sanitization_status: str = "unknown"
    severity: str = "high"
    reachable: bool = True
    auth_guarded: bool = False
    impact: str = "generic"
    potential_impact: str = "Potential generic sink"
    payload_hints: List[str] = field(default_factory=list)
    source_location: str = ""
    sink_location: str = ""
    entrypoints: List[str] = field(default_factory=list)
    score: float = 0.0
    confidence: float = 0.0
    exploitability: str = "unconfirmed"
    source_label: str = ""
    sink_label: str = ""
    explanation: str = ""

    def summary(self, node_idx: Dict[str, Dict[str, Any]]) -> str:
        """Render a short path summary."""
        labels = [node_idx.get(nid, {}).get("label", nid) for nid in self.path]
        return f"[{self.severity.upper()}] " + " -> ".join(labels)


@dataclass
class ScanReport:
    """Scan output report."""

    graph: Dict[str, Any]
    taint_paths: List[Dict[str, Any]]
    root: str
    node_count: int
    edge_count: int
    pii_node_count: int
    taint_path_count: int
    severity_summary: Dict[str, int] = field(default_factory=dict)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    unresolved_calls: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON."""
        return json.dumps(asdict(self), indent=indent, default=str)

    def to_text(self) -> str:
        """Serialize report to human-readable text."""
        lines = [
            f"=== Scan Report: {self.root} ===",
            f"  Nodes           : {self.node_count}",
            f"  Edges           : {self.edge_count}",
            f"  PII nodes       : {self.pii_node_count}",
            f"  Taint paths     : {self.taint_path_count}",
            f"  Unresolved calls: {self.unresolved_calls}",
        ]
        if self.severity_summary:
            lines.append("\n  Severities:")
            for sev, count in sorted(self.severity_summary.items()):
                lines.append(f"    {sev:14s} : {count}")
        if self.top_risks:
            lines.append("\n  Top Risks:")
            for risk in self.top_risks[:5]:
                lines.append(
                    f"    fragility={risk.get('fragility_score', 0.0):.2f}  "
                    f"{risk.get('source', '')} -> {risk.get('target', '')}"
                )
        return "\n".join(lines)


@dataclass
class BountyReport:
    """Hunter-focused report output."""

    root: str
    profile: str
    quick_mode: bool
    generated_at: float
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    graph: Dict[str, Any]

    def to_json(self, indent: int = 2) -> str:
        """Serialize bounty report to JSON."""
        return json.dumps(asdict(self), indent=indent, default=str)

    def to_html(self) -> str:
        """Render a standalone interactive HTML report."""
        payload = json.dumps(asdict(self), default=str)
        payload_script = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bounty Report</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #101a2f;
      --panel-alt: #15223d;
      --text: #e8eefc;
      --muted: #94a3b8;
      --accent: #f59e0b;
      --good: #22c55e;
      --warn: #f97316;
      --bad: #ef4444;
      --border: rgba(148,163,184,0.18);
    }}
    body {{
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: radial-gradient(circle at top, #13203a, var(--bg) 58%);
      color: var(--text);
    }}
    header, main {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    .grid {{ display: grid; grid-template-columns: 360px 1fr; gap: 16px; }}
    .card {{
      background: linear-gradient(180deg, var(--panel), var(--panel-alt));
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.28);
    }}
    .finding {{ border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-bottom: 10px; cursor: pointer; }}
    .finding.active {{ border-color: var(--accent); }}
    .sev-critical {{ color: var(--bad); }}
    .sev-high {{ color: var(--warn); }}
    .sev-medium {{ color: var(--accent); }}
    .muted {{ color: var(--muted); }}
    pre {{
      background: rgba(2,6,23,0.65);
      padding: 12px;
      border-radius: 10px;
      overflow: auto;
    }}
    svg {{ width: 100%; height: 520px; border: 1px solid var(--border); border-radius: 12px; background: rgba(2,6,23,0.35); }}
    .pill {{ display: inline-block; margin-right: 8px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Bounty Report</h1>
    <p class="muted">Profile: <span id="profile"></span> | Quick mode: <span id="quick"></span> | Findings: <span id="finding-count"></span></p>
  </header>
  <main class="grid">
    <section class="card">
      <h2>Findings</h2>
      <div id="findings"></div>
    </section>
    <section class="card">
      <h2 id="detail-title">Graph View</h2>
      <div class="muted" id="detail-meta"></div>
      <div style="margin:12px 0" id="detail-pills"></div>
      <svg id="graph" viewBox="0 0 900 520"></svg>
      <h3>Suggested Payloads</h3>
      <pre id="payloads"></pre>
      <h3>Path</h3>
      <pre id="path"></pre>
    </section>
  </main>
  <script id="report-data" type="application/json">{payload_script}</script>
  <script>
    const report = JSON.parse(document.getElementById('report-data').textContent);
    const findingsEl = document.getElementById('findings');
    const profileEl = document.getElementById('profile');
    const quickEl = document.getElementById('quick');
    const countEl = document.getElementById('finding-count');
    const titleEl = document.getElementById('detail-title');
    const metaEl = document.getElementById('detail-meta');
    const pillsEl = document.getElementById('detail-pills');
    const payloadsEl = document.getElementById('payloads');
    const pathEl = document.getElementById('path');
    const svg = document.getElementById('graph');
    const nodeIndex = Object.fromEntries((report.graph.nodes || []).map(n => [n.id, n]));

    function renderGraph(pathIds) {{
      svg.innerHTML = '';
      const labels = pathIds.map(id => (nodeIndex[id] || {{ label: id }}).label);
      const spacing = 820 / Math.max(labels.length - 1, 1);
      const y = 260;
      pathIds.forEach((id, i) => {{
        const x = 40 + i * spacing;
        if (i < pathIds.length - 1) {{
          const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line.setAttribute('x1', x);
          line.setAttribute('y1', y);
          line.setAttribute('x2', 40 + (i + 1) * spacing);
          line.setAttribute('y2', y);
          line.setAttribute('stroke', '#f59e0b');
          line.setAttribute('stroke-width', '2');
          svg.appendChild(line);
        }}
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', x);
        circle.setAttribute('cy', y);
        circle.setAttribute('r', '18');
        circle.setAttribute('fill', i === 0 ? '#22c55e' : i === pathIds.length - 1 ? '#ef4444' : '#38bdf8');
        svg.appendChild(circle);

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', x);
        text.setAttribute('y', y + 42);
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#e8eefc');
        text.setAttribute('font-size', '11');
        text.textContent = labels[i];
        svg.appendChild(text);
      }});
    }}

    function selectFinding(index) {{
      document.querySelectorAll('.finding').forEach((el, i) => el.classList.toggle('active', i === index));
      const finding = report.findings[index];
      titleEl.textContent = `${{finding.potential_impact || finding.impact}} | ${{finding.severity.toUpperCase()}}`;
      metaEl.textContent = `${{finding.source_location}} -> ${{finding.sink_location}}`;
      pillsEl.innerHTML = '';
      [
        `score=${{finding.score.toFixed(2)}}`,
        `confidence=${{(finding.confidence || 0).toFixed(2)}}`,
        finding.exploitability || 'unconfirmed',
        finding.reachable ? 'reachable' : 'non-reachable',
        finding.auth_guarded ? 'auth-guarded' : 'unguarded',
        finding.sanitization_status || (finding.sanitized ? 'sanitized' : 'unsanitized')
      ].forEach(text => {{
        const span = document.createElement('span');
        span.className = 'pill';
        span.textContent = text;
        pillsEl.appendChild(span);
      }});
      payloadsEl.textContent = (finding.payload_hints || []).join('\\n');
      pathEl.textContent = (finding.path_labels || []).join(' -> ');
      renderGraph(finding.path || []);
    }}

    profileEl.textContent = report.profile;
    quickEl.textContent = report.quick_mode ? 'yes' : 'no';
    countEl.textContent = String(report.findings.length);
    (report.findings || []).forEach((finding, index) => {{
      const div = document.createElement('div');
      div.className = `finding`;
      div.innerHTML = `<div><strong>${{finding.potential_impact || finding.impact}}</strong></div>
        <div class="sev-${{finding.severity}}">${{finding.severity.toUpperCase()}}</div>
        <div class="muted">${{(finding.path_labels || []).join(' -> ')}}</div>`;
      div.addEventListener('click', () => selectFinding(index));
      findingsEl.appendChild(div);
    }});
    if (report.findings.length) selectFinding(0);
  </script>
</body>
</html>"""


@dataclass
class GraphDiff:
    """Snapshot diff output."""

    added_nodes: List[str]
    removed_nodes: List[str]
    changed_nodes: List[str]
    added_edges: List[str]
    removed_edges: List[str]

    @property
    def is_clean(self) -> bool:
        """Return whether the diff has no changes."""
        return not any(
            [
                self.added_nodes,
                self.removed_nodes,
                self.changed_nodes,
                self.added_edges,
                self.removed_edges,
            ]
        )

    def summary(self) -> str:
        """Render a short diff summary."""
        if self.is_clean:
            return "Graphs are identical."
        return (
            f"Added nodes  : {len(self.added_nodes)}\n"
            f"Removed nodes: {len(self.removed_nodes)}\n"
            f"Changed nodes: {len(self.changed_nodes)}\n"
            f"Added edges  : {len(self.added_edges)}\n"
            f"Removed edges: {len(self.removed_edges)}"
        )


__all__ = [
    "AnalysisOptions",
    "BountyReport",
    "Edge",
    "EdgeRelation",
    "GraphDiff",
    "LogicClass",
    "Node",
    "NodeType",
    "ScanReport",
    "SecurityConfig",
    "TaintConfig",
    "TaintPath",
]
