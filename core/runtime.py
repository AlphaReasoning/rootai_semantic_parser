"""Core runtime orchestration."""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, fields
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from analyzers.symbols import SymbolResolver
from analyzers.taint import TaintAnalyzer
from models import AnalysisOptions, Edge, LogicClass, Node, ScanReport, SecurityConfig, TaintConfig
from parsers.registry import iter_parser_classes
from version import __version__

log = logging.getLogger(__name__)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


class GraphMerger:
    """Merge parser outputs into one graph."""

    @staticmethod
    def seed_origins(d: Dict, file: str) -> Dict:
        origins = d.setdefault("metadata", {}).setdefault("origins", [])
        if file not in origins:
            origins.append(file)
        return d

    @staticmethod
    def first_node(node_obj: Node) -> Dict:
        d = asdict(node_obj)
        return GraphMerger.seed_origins(d, node_obj.file)

    @staticmethod
    def resolve_node_conflict(existing: Dict, incoming: Node) -> Dict:
        existing_logic = LogicClass(existing.get("logic_class", "neutral"))
        incoming_logic = LogicClass(incoming.logic_class)
        existing["logic_class"] = LogicClass.merge(existing_logic, incoming_logic).value
        if incoming.is_pii_sensitive:
            existing["is_pii_sensitive"] = True
        if incoming.is_unsafe:
            existing["is_unsafe"] = True
        GraphMerger.seed_origins(existing, incoming.file)
        return existing

    @staticmethod
    def resolve_edge_conflict(existing: Dict, incoming: Edge) -> Dict:
        existing["fragility_score"] = max(existing.get("fragility_score", 0.5), incoming.fragility_score)
        if incoming.cve_id and not existing.get("cve_id"):
            existing["cve_id"] = incoming.cve_id
        if incoming.is_logic_mismatch:
            existing["is_logic_mismatch"] = True
        return existing


class CVEEnricher:
    """Simple CVE enricher with keyword matching."""

    def __init__(self, entries: List[Dict[str, Any]]) -> None:
        self._index: Dict[str, str] = {}
        self._entries = entries
        for entry in entries:
            cve_id = entry.get("id", "")
            for kw in entry.get("keywords", []):
                self._index[kw.lower()] = cve_id

    @classmethod
    def from_feed(cls, path: str) -> "CVEEnricher":
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    @functools.lru_cache(maxsize=512)
    def lookup(self, label: str, language: str = "") -> Optional[str]:
        del language
        label_lower = label.lower()
        for kw, cve_id in self._index.items():
            if kw in label_lower:
                return cve_id
        return None

    def enrich_graph(self, graph: Dict) -> int:
        """Attach CVE ids to graph edges."""
        node_idx = {n["id"]: n for n in graph.get("nodes", [])}
        enriched = 0
        for edge in graph.get("edges", []):
            src = node_idx.get(edge["source"], {})
            cve = self.lookup(src.get("label", ""), src.get("language", ""))
            if cve and not edge.get("cve_id"):
                edge["cve_id"] = cve
                enriched += 1
        return enriched


class GlobalDependencyResolver:
    """Merge external graphs and resolve cross-boundary calls."""

    def __init__(self, base_graph: Dict) -> None:
        self.graph = {"nodes": list(base_graph.get("nodes", [])), "edges": list(base_graph.get("edges", []))}
        self.node_ids = {n["id"] for n in self.graph["nodes"]}
        self.edge_keys = {(e["source"], e["target"], e["relation"]) for e in self.graph["edges"]}

    def ingest(self, external_graph: Dict, prefix: str = "") -> None:
        ext_node_ids = {n["id"] for n in external_graph.get("nodes", [])}
        for node in external_graph.get("nodes", []):
            nid = prefix + node["id"] if prefix else node["id"]
            if nid not in self.node_ids:
                new_node = dict(node)
                new_node["id"] = nid
                self.graph["nodes"].append(new_node)
                self.node_ids.add(nid)
        for edge in external_graph.get("edges", []):
            src = prefix + edge["source"] if prefix and edge["source"] in ext_node_ids else edge["source"]
            tgt = prefix + edge["target"] if prefix and edge["target"] in ext_node_ids else edge["target"]
            ekey = (src, tgt, edge["relation"])
            if ekey not in self.edge_keys:
                new_edge = dict(edge)
                new_edge["source"] = src
                new_edge["target"] = tgt
                self.graph["edges"].append(new_edge)
                self.edge_keys.add(ekey)

    def resolve(self) -> Dict:
        """Resolve merged graph symbols."""
        return SymbolResolver(self.graph).run()


# Modules whose code shapes a cached parse result but which own no parser class:
# the node/edge schema, and the node-id / SSA helpers every parser builds on.
_CACHE_RELEVANT_MODULES = ("models", "analyzers.symbols")


def engine_fingerprint() -> str:
    """Digest of the source files that determine what a parse produces.

    ``ParseCache`` keys on this so that changing an engine invalidates graphs
    cached by an earlier build. Without it a scan silently replays stale results:
    the scanned files' mtimes are unchanged, so every entry still reports a hit
    even though the code that produced it no longer exists.

    File *contents* are hashed rather than mtimes, because a fresh checkout
    rewrites mtimes without changing code, and a patch can change code while
    preserving them. Registered parser classes are consulted through the registry
    so that plugin parsers added via ``register_parser`` are covered too.
    """
    paths: Set[str] = set()
    for parser_cls in iter_parser_classes():
        module = sys.modules.get(getattr(parser_cls, "__module__", ""))
        source = getattr(module, "__file__", None)
        if source:
            paths.add(source)
    for module_name in _CACHE_RELEVANT_MODULES:
        module = sys.modules.get(module_name)
        source = getattr(module, "__file__", None)
        if source:
            paths.add(source)

    digest = hashlib.sha256()
    for source in sorted(paths):
        digest.update(source.encode("utf-8"))
        try:
            with open(source, "rb") as handle:
                digest.update(hashlib.sha256(handle.read()).digest())
        except OSError:
            # An unreadable source must not collapse the fingerprint onto the
            # value it would have had if the file simply did not exist.
            digest.update(b"\x00unreadable")
    return digest.hexdigest()[:16]


def _config_cache_key(config: SecurityConfig) -> Dict[str, Any]:
    """Serialize every SecurityConfig field deterministically.

    All of them reach a cached parse: the taint sets drive call-argument dataflow
    edges, and the pii/logic sets drive ``Node.is_pii_sensitive`` and
    ``Node.logic_class`` via ``classify_node``. Keying on the whole dataclass
    avoids re-introducing the drift a hand-picked subset already suffered.
    """
    key: Dict[str, Any] = {}
    for field_def in fields(config):
        value = getattr(config, field_def.name)
        key[field_def.name] = sorted(value) if isinstance(value, (set, frozenset)) else value
    return key


class ParseCache:
    """On-disk parse cache."""

    def __init__(self, version: str, options: AnalysisOptions, config: SecurityConfig) -> None:
        cache_root = os.path.join(os.path.expanduser("~"), ".cache", "rootai-semantic-parser")
        os.makedirs(cache_root, exist_ok=True)
        self.cache_root = cache_root
        self.namespace = hashlib.sha256(
            json.dumps(
                {
                    "version": version,
                    # Invalidate when the parsing code itself changes.
                    "engine": engine_fingerprint(),
                    # Only the options that change what a parse *emits*. Scoring
                    # flags (min_score, reachability, auth checks, suppressions)
                    # are applied after the cache, so keying on them would blow
                    # the whole cache away every time a threshold is tuned.
                    "quick_mode": options.quick_mode,
                    "profile": options.profile,
                    "config": _config_cache_key(config),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()[:16]
        self.hits = 0
        self.misses = 0

    def _fingerprint(self, path: str) -> str:
        stat = os.stat(path)
        payload = f"{path}|{stat.st_mtime_ns}|{stat.st_size}|{self.namespace}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def _cache_path(self, path: str) -> str:
        return os.path.join(self.cache_root, f"{self._fingerprint(path)}.json")

    def load(self, path: str):
        """Load a cached parser result."""
        cache_path = self._cache_path(path)
        if not os.path.exists(cache_path):
            self.misses += 1
            return None
        try:
            with open(cache_path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError):
            self.misses += 1
            return None
        parser_name = raw.get("parser")
        for parser_cls in iter_parser_classes():
            if parser_cls.__name__ == parser_name:
                config = (
                    SecurityConfig.from_file(raw["config_path"])
                    if raw.get("config_path")
                    else SecurityConfig.default_bugbounty()
                    if raw.get("stack") == "bugbounty"
                    else SecurityConfig.default_human_only()
                    if raw.get("stack") == "human-only"
                    else SecurityConfig.default_web()
                )
                parser = parser_cls(config, options=AnalysisOptions(quick_mode=raw.get("quick_mode", False), profile=raw.get("profile", "default")))
                try:
                    parser.nodes = {item["id"]: Node(**item) for item in raw.get("nodes", [])}
                    parser.edges = [Edge(**item) for item in raw.get("edges", [])]
                except (TypeError, KeyError):
                    # Truncated or hand-edited entry: treat as a miss rather than
                    # letting a poisoned cache file abort the whole scan.
                    self.misses += 1
                    return None
                self.hits += 1
                return parser
        self.misses += 1
        return None

    def save(self, path: str, parser) -> None:
        """Save a parser result to cache."""
        cache_path = self._cache_path(path)
        raw = {
            "parser": parser.__class__.__name__,
            "stack": parser.config.stack,
            "quick_mode": parser.options.quick_mode,
            "profile": parser.options.profile,
            "nodes": [asdict(node) for node in parser.nodes.values()],
            "edges": [asdict(edge) for edge in parser.edges],
        }
        try:
            with open(cache_path, "w", encoding="utf-8") as handle:
                json.dump(raw, handle)
        except OSError:
            pass


_DEFAULT_EXCLUDES = frozenset({"node_modules", ".git", "__pycache__", "vendor", "dist", "build", ".venv", "venv", "target"})


class MultiFileParser:
    """Repository parser orchestration."""

    def __init__(
        self,
        root: str,
        security_config: Optional[SecurityConfig] = None,
        exclude_patterns: Optional[List[str]] = None,
        options: Optional[AnalysisOptions] = None,
        use_cache: bool = True,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.root = root
        self.config = security_config or SecurityConfig.default_web()
        self.options = options or AnalysisOptions(profile=self.config.stack or "default")
        self._excludes: FrozenSet[str] = frozenset(exclude_patterns) if exclude_patterns else _DEFAULT_EXCLUDES
        self._parser_classes: List[type] = list(iter_parser_classes())
        self._parsers: List[Any] = []
        self._parsed = False
        self._cache = ParseCache(__version__, self.options, self.config) if use_cache else None
        self._event_callback = event_callback

    def _emit(self, stage: str, message: str, **payload: Any) -> None:
        if not self._event_callback:
            return
        event = {"ts": time.time(), "stage": stage, "message": message}
        event.update(payload)
        self._event_callback(event)

    def _is_excluded(self, path: str) -> bool:
        parts = path.replace("\\", "/").split("/")
        return any(fnmatch.fnmatch(part, pat) for part in parts for pat in self._excludes)

    def parse_all(self) -> None:
        """Parse all supported files under root."""
        if self._parsed:
            return
        self._parsed = True
        files_to_parse: List[str] = []
        self._emit("discover", "Walking repository and selecting candidate files.", root=self.root)
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, pat) for pat in self._excludes)]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                if not self._is_excluded(fpath):
                    files_to_parse.append(fpath)
        self._emit("discover", "Repository walk complete.", file_count=len(files_to_parse))
        if self.options.quick_mode:
            files_to_parse = [
                path for path in files_to_parse
                if not any(token in path.lower() for token in ("/test", "/tests", "_test.", ".spec.", ".test.", "/fixtures/", "/examples/"))
            ]
            self._emit("discover", "Quick mode filtered test and fixture files.", filtered_file_count=len(files_to_parse))

        def _parse_file(fpath: str):
            if self._cache:
                cached = self._cache.load(fpath)
                if cached is not None:
                    return cached
            for cls in self._parser_classes:
                if cls.supports(fpath):
                    parser = cls(self.config, options=self.options)
                    parser.parse(fpath)
                    if self._cache:
                        self._cache.save(fpath, parser)
                    return parser
            return None

        max_workers = min(32, (os.cpu_count() or 1) + 4)
        parsed_count = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            iterator = as_completed({executor.submit(_parse_file, path): path for path in files_to_parse})
            if tqdm is not None:
                iterator = tqdm(iterator, total=len(files_to_parse), desc="parse", unit="file")
            for future in iterator:
                parser = future.result()
                parsed_count += 1
                if parser:
                    self._parsers.append(parser)
                if parsed_count == 1 or parsed_count == len(files_to_parse) or parsed_count % 25 == 0:
                    self._emit(
                        "parse",
                        "Parser workers are processing source files.",
                        parsed_count=parsed_count,
                        candidate_file_count=len(files_to_parse),
                        parser_count=len(self._parsers),
                    )
        self._emit("parse", "Parsing complete.", parsed_count=parsed_count, parser_count=len(self._parsers))

    def parse_changed_files(self, changed_files: List[str]) -> None:
        """Parse only a provided list of changed files."""
        if self._parsed:
            return
        self._parsed = True
        selected = [path for path in changed_files if os.path.isfile(path) and not self._is_excluded(path)]
        self._emit("discover", "Scanning only changed files.", file_count=len(selected))

        def _parse_file(fpath: str):
            if self._cache:
                cached = self._cache.load(fpath)
                if cached is not None:
                    return cached
            for cls in self._parser_classes:
                if cls.supports(fpath):
                    parser = cls(self.config, options=self.options)
                    parser.parse(fpath)
                    if self._cache:
                        self._cache.save(fpath, parser)
                    return parser
            return None

        max_workers = min(32, (os.cpu_count() or 1) + 4)
        parsed_count = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            iterator = as_completed({executor.submit(_parse_file, path): path for path in selected})
            if tqdm is not None:
                iterator = tqdm(iterator, total=len(selected), desc="parse-changed", unit="file")
            for future in iterator:
                parser = future.result()
                parsed_count += 1
                if parser:
                    self._parsers.append(parser)
        self._emit("parse", "Changed-file parsing complete.", parsed_count=parsed_count, parser_count=len(self._parsers))

    def get_graph(self) -> Dict:
        """Merge parsed files into a graph."""
        self._emit("graph", "Merging parser outputs into a semantic graph.", parser_count=len(self._parsers))
        merged_nodes: Dict[str, Dict] = {}
        merged_edges: Dict[Tuple[str, str, str], Dict] = {}
        for parser in self._parsers:
            for nid, node_obj in parser.nodes.items():
                if nid in merged_nodes:
                    merged_nodes[nid] = GraphMerger.resolve_node_conflict(merged_nodes[nid], node_obj)
                else:
                    merged_nodes[nid] = GraphMerger.first_node(node_obj)
            for edge in parser.edges:
                key = (edge.source, edge.target, edge.relation)
                if key in merged_edges:
                    merged_edges[key] = GraphMerger.resolve_edge_conflict(merged_edges[key], edge)
                else:
                    merged_edges[key] = asdict(edge)
        graph = {"nodes": list(merged_nodes.values()), "edges": list(merged_edges.values())}
        resolved = SymbolResolver(graph).run()
        self._emit(
            "graph",
            "Graph merge and symbol resolution complete.",
            node_count=len(resolved.get("nodes", [])),
            edge_count=len(resolved.get("edges", [])),
            unresolved=resolved.get("_resolution_stats", {}).get("unresolved", 0),
        )
        return resolved

    def scan(
        self,
        taint_config: Optional[TaintConfig] = None,
        cve_enricher: Optional[CVEEnricher] = None,
        external_graphs: Optional[List[Dict]] = None,
    ) -> ScanReport:
        """Parse and analyze a repository."""
        self._emit("scan", "Semantic scan starting.", root=self.root, profile=self.options.profile)
        self.parse_all()
        graph = self.get_graph()
        if external_graphs:
            gdr = GlobalDependencyResolver(graph)
            for i, ext_graph in enumerate(external_graphs):
                gdr.ingest(ext_graph, prefix=f"ext_{i}_")
            graph = gdr.resolve()
            self._emit("graph", "External dependency graphs merged.", dependency_graphs=len(external_graphs))
        if cve_enricher:
            enriched_count = cve_enricher.enrich_graph(graph)
            self._emit("enrich", "CVE enrichment applied.", enriched_edges=enriched_count)
        self._emit("taint", "Running taint analysis and path ranking.")
        analyzer = TaintAnalyzer(graph, taint_config or TaintConfig(), options=self.options)
        paths = analyzer.run()
        severity_summary: Dict[str, int] = {}
        for tp in paths:
            severity_summary[tp.severity] = severity_summary.get(tp.severity, 0) + 1
        severity_summary["total"] = len(paths)
        self._emit("taint", "Taint analysis complete.", taint_path_count=len(paths), severity_summary=severity_summary)
        pii_ids = {n["id"] for n in graph["nodes"] if n.get("is_pii_sensitive")}
        top_risks = sorted(
            [e for e in graph["edges"] if e.get("source") in pii_ids or e.get("target") in pii_ids],
            key=lambda e: e.get("fragility_score", 0),
            reverse=True,
        )[:10]
        self._emit(
            "report",
            "Scan report assembled.",
            node_count=len(graph["nodes"]),
            edge_count=len(graph["edges"]),
            pii_node_count=len(pii_ids),
            top_risk_count=len(top_risks),
        )
        return ScanReport(
            graph=graph,
            taint_paths=[asdict(tp) for tp in paths],
            root=self.root,
            node_count=len(graph["nodes"]),
            edge_count=len(graph["edges"]),
            pii_node_count=len(pii_ids),
            taint_path_count=len(paths),
            severity_summary=severity_summary,
            top_risks=top_risks,
            unresolved_calls=graph.get("_resolution_stats", {}).get("unresolved", 0),
            cache_hits=self._cache.hits if self._cache else 0,
            cache_misses=self._cache.misses if self._cache else 0,
        )


def changed_files_between_commits(root: str, commit_a: str, commit_b: str) -> List[str]:
    """Return changed files between two git commits."""
    proc = subprocess.run(
        ["git", "-C", root, "diff", "--name-only", commit_a, commit_b],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    return [os.path.join(root, line.strip()) for line in proc.stdout.splitlines() if line.strip()]
