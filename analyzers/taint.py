"""Taint analysis and risk scoring."""

from __future__ import annotations

import functools
import heapq
import re
from collections import defaultdict
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from models import (
    LANGUAGE_SCOPED_SINKS,
    LANGUAGE_SCOPED_SOURCES,
    AnalysisOptions,
    EdgeRelation,
    TaintConfig,
    TaintPath,
)

#: Fallback language identification for nodes whose parser recorded none.
_EXTENSION_LANGUAGES: Dict[str, str] = {
    "py": "python", "js": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "typescript", "tsx": "typescript", "jsx": "javascript",
    "go": "go", "java": "java", "cs": "csharp", "php": "php", "rb": "ruby",
    "rs": "rust", "c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp",
    "hpp": "cpp", "hh": "cpp", "m": "objc", "mm": "objc", "kt": "kotlin",
    "kts": "kotlin", "swift": "swift", "scala": "scala", "lua": "lua",
    "r": "r", "sh": "bash", "bash": "bash",
}

#: Segment-keyed views of the language-scope maps, memoised per map object.
_SCOPE_BY_SEGMENTS: Dict[int, Dict[Tuple[str, ...], FrozenSet[str]]] = {}


def language_scope(scope: Dict[str, FrozenSet[str]]) -> Dict[Tuple[str, ...], FrozenSet[str]]:
    """Re-key a language-scope map by segments instead of literal spelling.

    Profiles spell the same sink more than one way -- the base config has
    ``system`` and the bugbounty profile adds ``system(`` -- and a scope rule
    written against one spelling silently failed to cover the other. Both
    tokenise to ``('system',)``, which is the identity that matters.
    """
    key = id(scope)
    cached = _SCOPE_BY_SEGMENTS.get(key)
    if cached is None:
        cached = {TaintAnalyzer._segments(pattern): languages for pattern, languages in scope.items()}
        _SCOPE_BY_SEGMENTS[key] = cached
    return cached

#: Anything that is not part of an identifier separates one name from the next,
#: so ``os.system(cmd)``, ``ctx->recv_buf`` and ``Command::new(&x)`` all reduce to
#: their component names.
_SEGMENT_SPLIT = re.compile(r"[^0-9A-Za-z_]+")

#: Dataflow edges that record a declaration rather than a value transfer.
_DECLARATION_FLOW_KINDS = frozenset(
    {"binding", "local_decl", "let_binding", "assignment"}
)

#: SSA versioning suffix appended by the parsers (``user_input_v2``).
_SSA_SUFFIX = re.compile(r"_v\d+$")


class TaintAnalyzer:
    """Inter-procedural taint analysis with path ranking."""

    _SCORE_EPSILON = 1e-9
    _REACHABILITY_LABEL_HINTS = frozenset(
        {
            "request",
            "resolver",
            "handler",
            "consumer",
            "query",
            "mutation",
            "fastapi",
            "apirouter",
            "router.",
            "route",
            "endpoint",
            "controller",
            "restcontroller",
            "requestmapping",
            "getmapping",
            "postmapping",
            "putmapping",
            "deletemapping",
            "patchmapping",
            "gin.context",
            "echo.context",
            "fiber.ctx",
        }
    )

    def __init__(self, graph: Dict, config: TaintConfig, options: Optional[AnalysisOptions] = None) -> None:
        self.graph = graph
        self.config = config
        self.options = options or AnalysisOptions()
        self.tainted_nodes: Set[str] = set()
        self.taint_paths: List[TaintPath] = []
        self._node_idx: Dict[str, Dict] = {n["id"]: n for n in graph.get("nodes", [])}
        self._segment_cache: Dict[Any, Tuple[str, ...]] = {}
        # value node -> the function that declares it. Declaration edges are not
        # value flow, but they do record ownership, which is how a finding is
        # attributed to the route its enclosing handler serves.
        self._enclosing_function: Dict[str, str] = {}
        for edge in graph.get("edges", []):
            metadata = edge.get("metadata") or {}
            if edge.get("relation") == EdgeRelation.DATAFLOW.value and metadata.get(
                "flow_kind"
            ) in _DECLARATION_FLOW_KINDS | {"parameter"}:
                self._enclosing_function.setdefault(edge["target"], edge["source"])
            elif edge.get("relation") == EdgeRelation.CONTAINS.value:
                self._enclosing_function.setdefault(edge["target"], edge["source"])

        # Positional fallback. Some values have no declaration edge at all --
        # Flask's `request` is a module-level proxy, not a parameter -- so they
        # would be attributed to no function and inherit no route. The nearest
        # function declared above them in the same file is the right owner.
        self._functions_by_file: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        for node in graph.get("nodes", []):
            if node.get("type") == "Function" and not (node.get("metadata") or {}).get("synthetic"):
                self._functions_by_file[str(node.get("file", ""))].append(
                    (int(node.get("lineno") or 0), node["id"])
                )
        for entries in self._functions_by_file.values():
            entries.sort()
        self._adj: Dict[str, List[Tuple[str, str, float]]] = defaultdict(list)
        for edge in graph.get("edges", []):
            for source, target, relation, weight in self._propagations(edge):
                self._adj[source].append((target, relation, weight))
        self._parent: Dict[Tuple[str, FrozenSet[str]], Tuple[str, FrozenSet[str]]] = {}
        self._best_score: Dict[Tuple[str, FrozenSet[str]], float] = {}
        self._hop_count: Dict[Tuple[str, FrozenSet[str]], int] = {}
        self._fragility_sum: Dict[Tuple[str, FrozenSet[str]], float] = {}

    @staticmethod
    def _propagations(edge: Dict) -> List[Tuple[str, str, str, float]]:
        """Return the taint propagations implied by one graph edge.

        Yields ``(source, target, relation, weight)``. An edge can imply flow in
        the reverse direction, or none at all; only relations that actually carry
        a *value* belong here. ``contains``/``imports``/``inherits`` are structural,
        ``drops``/``lifetime_bounds`` describe object lifetime rather than data,
        and ``moves`` as emitted links a function to the local it declares (a
        binding record, not a value transfer), so all of them are excluded.
        """
        relation = edge.get("relation")
        src, tgt = edge["source"], edge["target"]
        weight = float(edge.get("fragility_score", 0.5))
        metadata = edge.get("metadata") or {}

        if relation == EdgeRelation.CALLS.value:
            # Control flow, not data flow. A callee receives data through its
            # arguments and returns it through its return value, both modelled
            # as DATAFLOW. Propagating along the call edge itself combined with
            # the reverse-parameter rule to make any tainted parameter implicate
            # every function reachable from its body.
            return []

        if relation == EdgeRelation.DATAFLOW.value:
            # A parameter edge runs function -> parameter, which is a binding
            # record. The value flows the other way: a tainted argument makes the
            # receiving function operate on tainted data, and the function's own
            # call-argument edges carry that onward to its callees.
            flow_kind = metadata.get("flow_kind")
            if flow_kind == "parameter":
                # Declaration record, like the binding kinds below. A tainted
                # argument reaches this parameter through argument_binding.
                return []
            if flow_kind == "call_argument_resolved":
                # The callee's body is in the graph, so the value reaches it
                # through argument_binding and comes back only if the body
                # returns it. Keeping this edge as well would let taint enter
                # the call stub and leave again as the result, bypassing
                # whatever the function does to the value.
                return []
            if flow_kind in _DECLARATION_FLOW_KINDS:
                # function -> variable records *that* a local is declared here,
                # not that the function's data flows into it. Treating it as
                # value flow let a tainted parameter contaminate every local in
                # the same function, and from there every call those locals fed.
                # The value itself arrives via assignment_rhs or call_return.
                return []
            return [(src, tgt, relation, weight)]

        if relation == EdgeRelation.FIELD_ACCESS.value:
            # Aggregate -> field. Taint flows both ways: a tainted struct yields
            # tainted members, and a tainted member makes the aggregate carry
            # tainted data. Down-weighted because it is field-insensitive.
            return [
                (src, tgt, relation, weight * 0.5),
                (tgt, src, relation, weight * 0.5),
            ]

        if relation in (
            EdgeRelation.UNSAFE_DEREFERENCE.value,
            EdgeRelation.POINTER_ARITH.value,
            EdgeRelation.BORROWS.value,
            EdgeRelation.MACRO_EXPANDS_TO.value,
        ):
            # Reading through a pointer, deriving a pointer, lending a reference
            # and expanding a macro all carry the underlying value forward.
            return [(src, tgt, relation, weight)]

        return []

    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def _segments(text: str) -> Tuple[str, ...]:
        """Split an expression into the identifier names it is built from.

        Cached: the configured patterns are re-tokenised on every comparison,
        which dominated parsing -- 1.4 million calls for sixty Java files.

        ``os.system(cmd)`` becomes ``('os', 'system', 'cmd')`` and
        ``ctx->recv_buf`` becomes ``('ctx', 'recv_buf')``. SSA suffixes are
        removed so a pattern written for ``user_input`` still matches the
        parser's ``user_input_v2``.
        """
        segments: List[str] = []
        for raw in _SEGMENT_SPLIT.split(text.lower()):
            if not raw:
                continue
            segments.append(_SSA_SUFFIX.sub("", raw) or raw)
        return tuple(segments)

    def _node_segments(self, node: Dict) -> Tuple[str, ...]:
        node_id = node.get("id")
        cached = self._segment_cache.get(node_id)
        if cached is None:
            cached = self._segments(node.get("label", ""))
            self._segment_cache[node_id] = cached
        return cached

    @classmethod
    def _pattern_matches(cls, label_segments: Tuple[str, ...], pattern: str) -> bool:
        """Match a configured pattern against an expression's identifier names.

        Matching is segment-aligned rather than a raw substring test. Plain
        containment made ``exec`` match ``execute``, ``eval`` match
        ``EvaluationCase`` and ``read`` match any function whose name merely
        contained those letters, which was the dominant source of false
        positives. A single-name pattern must equal a whole segment; a dotted or
        scoped pattern must appear as a consecutive run of segments, so
        ``os.system`` matches ``os.system(cmd)`` but not an unrelated ``system``
        attribute of another object.
        """
        pattern_segments = cls._segments(pattern)
        if not pattern_segments:
            return False
        if len(pattern_segments) == 1:
            return pattern_segments[0] in label_segments
        span = len(pattern_segments)
        return any(
            label_segments[index : index + span] == pattern_segments
            for index in range(len(label_segments) - span + 1)
        )

    def _enclosing_by_position(self, node: Dict) -> Optional[Dict]:
        """Return the nearest function declared above ``node`` in the same file."""
        lineno = node.get("lineno")
        if not lineno:
            return None
        best: Optional[str] = None
        for declared_line, fn_id in self._functions_by_file.get(str(node.get("file", "")), []):
            if declared_line <= lineno:
                best = fn_id
            else:
                break
        return self._node_idx.get(best) if best else None

    def _matches(
        self,
        node: Dict,
        keyword_set: Set[str],
        scope: Optional[Dict[str, FrozenSet[str]]] = None,
    ) -> bool:
        """Return whether any pattern in ``keyword_set`` describes ``node``.

        ``scope`` restricts individual patterns to the languages they are
        meaningful in. Without it, PHP's ``include`` sink fires on Java's
        ``RequestDispatcher.include`` and the C ``system`` sink fires on
        ``System.out.println``, both of which are boilerplate rather than risk.
        """
        label_segments = self._node_segments(node)
        if not label_segments:
            return False
        language = self._language(node) if scope else None
        for keyword in keyword_set:
            if not self._pattern_matches(label_segments, keyword):
                continue
            if scope is not None:
                allowed = language_scope(scope).get(self._segments(keyword))
                # An unknown language is not evidence the pattern is wrong, so
                # scoping only rejects a match it can positively contradict.
                if allowed is not None and language is not None and language not in allowed:
                    continue
            return True
        return False

    def _language(self, node: Dict) -> Optional[str]:
        """The language a node was parsed from, by metadata then by extension."""
        metadata = node.get("metadata") or {}
        language = metadata.get("language")
        if language:
            return str(language).lower()
        suffix = str(node.get("file", "")).rsplit(".", 1)
        return _EXTENSION_LANGUAGES.get(suffix[-1].lower()) if len(suffix) == 2 else None

    def _is_taint_source(self, node: Dict) -> bool:
        """Return whether a node introduces externally controlled data.

        ``is_unsafe`` deliberately does not qualify. The parsers set it for
        memory-unsafe *constructs* -- every pointer parameter, every dangerous
        sink -- which is a severity signal, not a statement about attacker
        control. Seeding from it made every pointer-taking C function a taint
        source and made each sink its own source, producing ``system -> system``
        style self-loops.
        """
        if self._matches(node, self.config.sources, LANGUAGE_SCOPED_SOURCES):
            return True
        metadata = node.get("metadata") or {}
        return bool(metadata.get("is_taint_source") or metadata.get("tainted_by"))

    def _is_sanitizer(self, node: Dict) -> bool:
        """Return whether passing through this node defends the value.

        Label matching alone is not enough: a parser can establish that a value
        was validated by a guard (`if (!ALLOWED.includes(c)) return;`) which no
        keyword in the node's own name would reveal. Gating on the label meant
        that metadata was recorded and never read.
        """
        if self._matches(node, self.config.sanitizers):
            return True
        metadata = node.get("metadata") or {}
        return bool(metadata.get("sanitizer_for") or metadata.get("sanitizer_categories"))

    def _is_taint_sink(self, node: Dict) -> bool:
        """Return whether a node is a dangerous operation.

        Label matching alone is not enough. A parser may know a call is a sink
        through information the label does not carry -- Rust resolves
        ``Command::new`` to ``std::process::Command`` via its ``use`` statements,
        but the node's label remains the source text. Where a parser has already
        made that determination, honour it.
        """
        if self._matches(node, self.config.sinks, LANGUAGE_SCOPED_SINKS):
            return True
        metadata = node.get("metadata") or {}
        return bool(metadata.get("is_taint_sink"))

    @staticmethod
    def _sink_categories(label: str) -> Set[str]:
        value = label.lower()
        categories: Set[str] = set()
        if any(token in value for token in {
            "os.system", "subprocess.run", "exec.command", "shell", "processbuilder",
            "system", "popen", "execve", "execl", "execv", "shell_exec", "proc_open",
            "invoke-expression", "os.execute", "process.start", "runtime.exec",
            # Node's child_process family: named "exec*" but they spawn a shell
            # command, not evaluate code, so a shell escaper is the right defence.
            "execsync", "spawnsync", "child_process", "exec.commandcontext",
        }):
            categories.add("command")
        if "command" not in categories and any(
            token in value for token in {"eval", "exec", "compile"}
        ):
            categories.add("code")
        if any(token in value for token in {"cursor.execute", "db.execute", "query", "sql", "jdbc"}):
            categories.add("sql")
        if any(token in value for token in {"innerhtml", "html"}):
            categories.add("html")
        if any(token in value for token in {"pickle.loads", "yaml.load", "deserialize", "unserialize", "objectinputstream"}):
            categories.add("deserialize")
        # Memory-safety sinks. Without this the entire C/C++/Rust sink vocabulary
        # fell through to "generic", so buffer overflows were reported with no
        # impact class and an understated severity.
        if any(token in value for token in {
            "strcpy", "strcat", "sprintf", "gets", "memcpy", "memmove", "alloca",
            "stpcpy", "std::ptr::write", "std::ptr::read", "transmute",
        }):
            categories.add("memory")
        if any(token in value for token in {
            "needle.get", "axios", "http.get", "https.get", "requests.get",
            "urlopen", "resttemplate", "urlconnection", "httpclient",
        }):
            categories.add("ssrf")
        if any(token in value for token in {
            "collection.find", "collection.update", "db.collection", "rawquery", "knex.raw",
        }):
            categories.add("nosql")
        if any(token in value for token in {
            "res.write", "res.send", "innerhtml", "outerhtml", "insertadjacenthtml",
            "dangerouslysetinnerhtml", "document.write",
        }):
            categories.add("xss")
        if any(token in value for token in {
            "fs.readfile", "createreadstream", "sendfile", "fileinputstream",
            "readalltext",
        }):
            categories.add("path")
        return categories or {"generic"}

    #: Sanitizers that change a value's *type* rather than escaping its content.
    #: The result cannot carry an injection payload for any sink, so these
    #: neutralise every category rather than one.
    _UNIVERSAL_SANITIZERS = frozenset(
        {
            "int", "float", "long", "bool",
            "parseint", "parsefloat", "number", "tonumber",
            "atoi", "atof", "strconv.atoi", "strconv.parseint",
            "integer.parseint", "double.parsedouble", "uuid", "int32.parse",
        }
    )

    @classmethod
    def _sanitizer_categories(cls, node: Dict) -> Set[str]:
        metadata = node.get("metadata", {})
        explicit = metadata.get("sanitizer_for") or metadata.get("sanitizer_categories") or []
        explicit_categories = {str(item).strip().lower() for item in explicit if str(item).strip()}
        if explicit_categories:
            return explicit_categories
        label = node.get("label", "").lower()
        segments = cls._segments(label)
        if any(name in cls._UNIVERSAL_SANITIZERS for name in segments):
            # A value parsed into a number is safe everywhere, not merely against
            # the categories a string escaper would cover.
            return {"*"}
        categories: Set[str] = set()
        if any(token in label for token in {
            "shlex.quote", "shellescape", "escape_shell", "quote",
            "escapeshellarg", "escapeshellcmd",
        }):
            categories.add("command")
        if any(token in label for token in {"int", "float", "validate_number", "numeric", "integer.parseint"}):
            categories.update({"code", "sql"})
        if any(token in label for token in {
            "html.escape", "bleach.clean", "escape_html", "escapehtml",
            "htmlspecialchars", "sanitize_html", "dompurify", "encode_text",
        }):
            # Named for the sink class it defends, so it lines up with the
            # category _sink_categories assigns to an XSS sink.
            categories.update({"html", "xss"})
        if any(token in label for token in {
            "sql_escape", "param", "parameterize", "preparedstatement",
            "preparestatement", "real_escape_string", "quote_ident",
        }):
            categories.update({"sql", "nosql"})
        if any(token in label for token in {"safe_load", "deserialize_safe"}):
            categories.add("deserialize")
        if any(token in label for token in {"sanitize", "validate", "validator"}):
            categories.add("generic")
        framework = metadata.get("framework", "")
        if framework in {"fastapi", "spring", "gin"} and any(token in label for token in {"path", "query", "bind", "validated"}):
            categories.add("generic")
        return categories

    def _effective_sanitized(self, sanitizers: FrozenSet[str], sink_label: str) -> bool:
        if not sanitizers:
            return False
        if "*" in sanitizers:
            return True
        sink_categories = self._sink_categories(sink_label)
        return bool(sanitizers & sink_categories) or ("generic" in sanitizers and sink_categories == {"generic"})

    @staticmethod
    def _location(node: Dict) -> str:
        file_value = str(node.get("file", "?"))
        line = node.get("lineno")
        return f"{file_value}:{line}" if line else file_value

    def _path_metadata(self, path: List[str], sink_node: Dict, sanitized: bool, severity: str) -> Dict[str, Any]:
        nodes = [self._node_idx.get(nid, {}) for nid in path]
        labels = [node.get("label", "?") for node in nodes]
        # A declared route is direct evidence of external reachability, and it
        # carries the URL an operator needs in order to test the finding.
        # Walk out to each node's declaring function: the route is recorded on
        # the handler, and with declaration edges no longer carrying taint the
        # handler itself is not on the data path.
        context: List[Dict] = list(nodes)
        for node in nodes:
            current = node.get("id")
            if current not in self._enclosing_function:
                owner = self._enclosing_by_position(node)
                if owner:
                    context.append(owner)
            for _ in range(4):
                current = self._enclosing_function.get(current)
                if not current:
                    break
                owner = self._node_idx.get(current)
                if owner:
                    context.append(owner)

        routes = sorted(
            {
                str(item.get("metadata", {}).get("route"))
                for item in context
                if item.get("metadata", {}).get("route")
            }
        )
        entrypoints = sorted(
            {
                f"{item['metadata']['route']} ({self._location(item)})"
                if item.get("metadata", {}).get("route")
                else self._location(item)
                for item in context
                if item.get("metadata", {}).get("entrypoint")
            }
        )
        file_paths = [str(node.get("file", "")) for node in nodes]
        reachable = True
        if self.options.enable_reachability:
            # Prefer the declared route. The label heuristic below is a fallback
            # for code whose framework is not modelled; on its own it inverted
            # the ranking, marking an unrouted helper reachable because a label
            # contained "query" while a real routed endpoint scored lower.
            reachable = bool(entrypoints) or any(
                any(token in node.get("label", "").lower() for token in self._REACHABILITY_LABEL_HINTS)
                for node in nodes
            )
        auth_guarded = self.options.enable_auth_checks and any(node.get("metadata", {}).get("auth_guard") for node in nodes)
        validation_guards = [
            str(node.get("metadata", {}).get("guard_test"))
            for node in nodes
            if node.get("metadata", {}).get("guarded")
        ]
        impact = self._impact_for_sink(sink_node.get("label", ""))
        potential_impact = f"Potential {impact}" if not impact.lower().startswith("potential") else impact
        payload_hints = self._payload_hints(sink_node.get("label", ""))
        score = {"critical": 95.0, "high": 75.0, "medium": 50.0, "low": 20.0}.get(severity, 40.0)
        is_test_path = any(any(token in item.lower() for token in ("/test", "/tests", "_test.", ".spec.", ".test.")) for item in file_paths)
        is_library_path = any(any(token in item.lower() for token in ("/site-packages/", "/vendor/", "/dist/")) for item in file_paths)
        dead_code = not reachable and not entrypoints
        if routes:
            # Confirmed externally reachable, which is what separates an
            # exploitable finding from an internal helper.
            score += 10.0
        if not reachable:
            score -= 30.0
        if auth_guarded:
            score -= 15.0
        if sanitized:
            score -= 20.0
        if self.options.suppress_test_files and is_test_path:
            score -= 60.0
        if self.options.suppress_library_code and is_library_path:
            score -= 40.0
        if self.options.suppress_dead_code and dead_code:
            score -= 25.0
        confidence = score / 100.0
        sanitization_status = "none_detected" if not sanitized else "sanitized_detected"
        source_label = labels[0] if labels else ""
        sink_label = sink_node.get("label", "")
        explanation = f"{source_label} -> {' -> '.join(labels[1:-1]) + ' -> ' if len(labels) > 2 else ''}{sink_label}"
        return {
            "reachable": reachable,
            "auth_guarded": auth_guarded,
            "impact": impact,
            "potential_impact": potential_impact,
            "payload_hints": payload_hints,
            "source_location": self._location(nodes[0]) if nodes else "",
            "sink_location": self._location(sink_node),
            "entrypoints": entrypoints,
            "score": max(score, 0.0),
            "confidence": max(min(confidence, 1.0), 0.0),
            "exploitability": "unconfirmed",
            "sanitization_status": sanitization_status,
            "source_label": source_label,
            "sink_label": sink_label,
            "explanation": explanation,
            "routes": routes,
            "validation_guards": validation_guards,
            "test_only": is_test_path,
            "dead_code": dead_code,
            "library_code": is_library_path,
            "path_labels": labels,
        }

    @staticmethod
    def _impact_for_sink(label: str) -> str:
        categories = TaintAnalyzer._sink_categories(label)
        if "command" in categories or "code" in categories:
            return "RCE"
        if "deserialize" in categories:
            return "Deserialization"
        if "sql" in categories:
            return "SQL injection"
        if "memory" in categories:
            return "Memory corruption"
        if "nosql" in categories:
            return "NoSQL injection"
        if "ssrf" in categories:
            return "SSRF"
        if "xss" in categories:
            return "Cross-site scripting"
        if "path" in categories:
            return "Path traversal / file disclosure"
        value = label.lower()
        if any(token in value for token in {"admin", "grant", "assumerole", "iam.put", "setrole"}):
            return "Auth bypass / privilege escalation"
        if any(token in value for token in {"s3", "sns", "sqs", "redis.set", "kafka.produce"}):
            return "Sensitive write / message forgery"
        if any(token in value for token in {"jwt", "token", "session", "profile", "customer"}):
            return "PII leak / token abuse"
        return "Generic taint sink"

    @staticmethod
    def _payload_hints(label: str) -> List[str]:
        value = label.lower()
        if any(token in value for token in {"os.system", "subprocess.run", "processbuilder", "shell_exec", "passthru"}):
            return ["id", "sleep 5", "curl http://collaborator"]
        if any(token in value for token in {"eval", "exec", "compile"}):
            return ["1+1", "__import__('os').system('id')", "require('child_process').execSync('id')"]
        if any(token in value for token in {"cursor.execute", "db.execute", "query", "sql"}):
            return ["' OR '1'='1", "'; SELECT pg_sleep(5)--", "' UNION SELECT NULL--"]
        if any(token in value for token in {"pickle.loads", "yaml.load", "unserialize", "marshal.load"}):
            return ["serialized gadget chain", "crafted YAML object", "polyglot deserialization blob"]
        if any(token in value for token in {"admin", "grant", "assumerole", "iam.put"}):
            return ["role=admin", "{\"isAdmin\":true}", "targetRole=arn:aws:iam::123456789012:role/Admin"]
        return ["probe with app-specific tainted input", "verify source reaches sink without sanitizer"]

    def run(self) -> List[TaintPath]:
        """Compute ranked taint paths."""
        # Queue entries carry the sanitizer set as a *sorted tuple*. heapq falls
        # through to comparing later tuple elements when the score and hop count
        # tie, and ``<`` on frozensets is subset containment rather than a total
        # order, which left equally scored paths ordered arbitrarily.
        queue: List[Tuple[float, int, str, Tuple[str, ...]]] = []
        for nid in sorted(self._node_idx):
            node = self._node_idx[nid]
            if self._is_taint_source(node):
                self.tainted_nodes.add(nid)
                # A guard can validate the very value that seeds the path
                # (`c = req.query.c; if (!ALLOWED.includes(c)) return;`). Sanitizer
                # state is otherwise only collected on arrival at a node, so a
                # guarded source would carry none.
                initial = (
                    frozenset(self._sanitizer_categories(node))
                    if self._is_sanitizer(node)
                    else frozenset()
                )
                state = (nid, initial)
                self._parent[state] = state
                self._best_score[state] = 0.0
                self._hop_count[state] = 0
                self._fragility_sum[state] = 0.0
                heapq.heappush(queue, (-0.0, 0, nid, tuple(sorted(state[1]))))

        while queue:
            neg_score, hops, current, sanitizer_key = heapq.heappop(queue)
            sanitizer_categories = frozenset(sanitizer_key)
            current_score = -neg_score
            state = (current, sanitizer_categories)
            if current_score < self._best_score.get(state, float("-inf")) or hops > self._hop_count.get(state, hops):
                continue
            current_fragility = self._fragility_sum.get(state, 0.0)
            for neighbor, _, edge_fragility in self._adj.get(current, []):
                nb_node = self._node_idx.get(neighbor)
                if not nb_node:
                    continue
                next_categories = sanitizer_categories
                if self._is_sanitizer(nb_node):
                    next_categories = frozenset(set(next_categories) | self._sanitizer_categories(nb_node))
                next_state = (neighbor, next_categories)
                next_hops = hops + 1
                next_fragility = current_fragility + edge_fragility
                next_score = next_fragility / next_hops
                best_known = self._best_score.get(next_state, float("-inf"))
                best_hops = self._hop_count.get(next_state, next_hops)
                if next_score < best_known - self._SCORE_EPSILON:
                    continue
                if abs(next_score - best_known) <= self._SCORE_EPSILON and next_hops >= best_hops:
                    continue
                self.tainted_nodes.add(neighbor)
                self._parent[next_state] = state
                self._best_score[next_state] = next_score
                self._hop_count[next_state] = next_hops
                self._fragility_sum[next_state] = next_fragility
                heapq.heappush(
                    queue,
                    (-next_score, next_hops, neighbor, tuple(sorted(next_categories))),
                )

        # Sorted so that findings do not depend on set iteration order, which
        # varies between processes under randomized string hashing.
        for nid in sorted(self.tainted_nodes):
            node = self._node_idx.get(nid)
            if node and self._is_taint_sink(node):
                sink_states = [(state, score) for state, score in self._best_score.items() if state[0] == nid]
                if not sink_states:
                    continue
                # Ties broken on the sanitizer set so one route is chosen
                # reproducibly when several score identically.
                best_state, _ = max(
                    sink_states,
                    key=lambda item: (
                        item[1],
                        -self._hop_count.get(item[0], 0),
                        tuple(sorted(item[0][1])),
                    ),
                )
                sanitizer_categories = best_state[1]
                sanitized = self._effective_sanitized(sanitizer_categories, node.get("label", ""))
                path = self._reconstruct(best_state)
                if len(path) < 2 or path[0] == path[-1]:
                    # A node that matches both a source and a sink pattern is not
                    # evidence of a flow; it is one label satisfying two keyword
                    # sets. Reporting it produced findings like "system -> system".
                    continue
                severity = "critical" if self._matches(node, self.config.critical_sinks) else "high"
                if sanitized:
                    # Previously a critical sink stayed critical even with an
                    # effective sanitizer on the path, which is the opposite of
                    # what the evidence says.
                    severity = "medium" if severity == "critical" else "low"
                metadata = self._path_metadata(path, node, sanitized, severity)
                self.taint_paths.append(
                    TaintPath(
                        source_id=path[0],
                        sink_id=nid,
                        path=path,
                        sanitized=sanitized,
                        severity=severity,
                        reachable=metadata["reachable"],
                        auth_guarded=metadata["auth_guarded"],
                        impact=metadata["impact"],
                        potential_impact=metadata["potential_impact"],
                        payload_hints=metadata["payload_hints"],
                        validation_guards=metadata["validation_guards"],
                        routes=metadata["routes"],
                        source_location=metadata["source_location"],
                        sink_location=metadata["sink_location"],
                        entrypoints=metadata["entrypoints"],
                        score=metadata["score"],
                        confidence=metadata["confidence"],
                        exploitability=metadata["exploitability"],
                        sanitization_status=metadata["sanitization_status"],
                        source_label=metadata["source_label"],
                        sink_label=metadata["sink_label"],
                        explanation=metadata["explanation"],
                    )
                )

        self.taint_paths = self._collapse_nested_sinks(self.taint_paths)
        self.taint_paths = [
            item for item in self.taint_paths
            if item.score >= self.options.min_score
            and (not self.options.only_reachable_unsanitized or (item.reachable and not item.sanitized))
        ]
        self.taint_paths.sort(key=lambda item: item.score, reverse=True)
        return self.taint_paths

    @staticmethod
    def _collapse_nested_sinks(paths: List[TaintPath]) -> List[TaintPath]:
        """Report one finding per source reaching one place in the code.

        ``eval(compile(f.read(), ...))`` nests two sinks on a single line, and
        reporting both makes one issue look like two. The highest-scoring path
        wins; ties break on the sink label so the choice is reproducible.
        """
        best: Dict[Tuple[str, str], TaintPath] = {}
        for path in paths:
            key = (path.source_label, path.sink_location)
            current = best.get(key)
            if (
                current is None
                or path.score > current.score
                or (path.score == current.score and path.sink_label < current.sink_label)
            ):
                best[key] = path
        return list(best.values())

    def _reconstruct(self, sink_state: Tuple[str, FrozenSet[str]]) -> List[str]:
        path: List[str] = []
        cur = sink_state
        seen = set()
        while cur not in seen:
            path.append(cur[0])
            seen.add(cur)
            parent = self._parent.get(cur)
            if parent is None or parent == cur:
                break
            cur = parent
        return list(reversed(path))
