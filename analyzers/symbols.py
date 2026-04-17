"""Symbol resolution and SSA helpers."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from models import EdgeRelation


class SSAVersionTracker:
    """Track per-variable SSA versions."""

    def __init__(self) -> None:
        self.counters: Dict[str, int] = {}
        self.current_map: Dict[str, str] = {}

    def get_versioned_id(self, original_id: str) -> str:
        """Return the next SSA label for a variable."""
        version = self.counters.get(original_id, 0) + 1
        self.counters[original_id] = version
        ssa_id = f"{original_id}_v{version}"
        self.current_map[original_id] = ssa_id
        return ssa_id

    def get_current_id(self, original_id: str) -> Optional[str]:
        """Return the latest SSA label for a variable."""
        return self.current_map.get(original_id)


class GlobalSymbolTable:
    """Global graph symbol index used for call resolution."""

    def __init__(self) -> None:
        self.index: Dict[str, List[str]] = defaultdict(list)
        self.qualified_index: Dict[str, List[str]] = defaultdict(list)
        self.file_scoped_index: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self.origin_scoped_index: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    def build(self, graph: Dict) -> None:
        """Build indexes from a graph."""
        self.index.clear()
        self.qualified_index.clear()
        self.file_scoped_index.clear()
        self.origin_scoped_index.clear()
        for node in graph.get("nodes", []):
            name = node.get("label")
            if not name:
                continue
            nid = node["id"]
            if nid not in self.index[name]:
                self.index[name].append(nid)
            qualified_name = node.get("qualified_name")
            if qualified_name:
                qualified_key = self._qualified_key(node, qualified_name)
                if nid not in self.qualified_index[qualified_key]:
                    self.qualified_index[qualified_key].append(nid)
            file_scope = node.get("file")
            if file_scope:
                scoped_key = (self._origin_key(node, fallback=file_scope), name)
                if nid not in self.file_scoped_index[scoped_key]:
                    self.file_scoped_index[scoped_key].append(nid)
            origin_key = self._origin_key(node)
            if origin_key and nid not in self.origin_scoped_index[(origin_key, name)]:
                self.origin_scoped_index[(origin_key, name)].append(nid)

    @staticmethod
    def _origin_key(node: Dict, fallback: str = "") -> str:
        metadata = node.get("metadata", {})
        origins = metadata.get("origins", [])
        if origins:
            return "|".join(sorted(str(origin) for origin in origins))
        return str(node.get("file") or fallback or "")

    @staticmethod
    def _has_stable_origin(node: Dict, fallback: str = "") -> bool:
        metadata = node.get("metadata", {})
        origins = metadata.get("origins", [])
        if origins:
            return True
        file_value = str(node.get("file") or fallback or "")
        return file_value.startswith("/")

    def _qualified_key(self, node: Dict, qualified_name: str) -> str:
        origin_key = self._origin_key(node)
        return f"{origin_key}::{qualified_name}" if origin_key else qualified_name

    def resolve(
        self,
        name: str,
        file_scope: Optional[str] = None,
        source_node: Optional[Dict] = None,
    ) -> Optional[str]:
        """Resolve a symbol name to a concrete node id."""
        source_node = source_node or {}
        source_origin = self._origin_key(source_node, fallback=file_scope or "")
        has_stable_origin = self._has_stable_origin(source_node, fallback=file_scope or "")
        if "::" in name and not has_stable_origin:
            return None
        if not has_stable_origin:
            source_origin = ""
        qualified_key = f"{source_origin}::{name}" if source_origin else name
        qualified_matches = self.qualified_index.get(qualified_key, [])
        if len(qualified_matches) == 1:
            return qualified_matches[0]
        if source_origin:
            scoped_matches = self.file_scoped_index.get((source_origin, name), [])
            if len(scoped_matches) == 1:
                return scoped_matches[0]
        origin_matches = self.origin_scoped_index.get((source_origin, name), [])
        if len(origin_matches) == 1:
            return origin_matches[0]
        matches = self.index.get(name, [])
        if len(matches) == 1:
            return matches[0]
        return None


class SymbolResolver:
    """Resolve synthetic call targets to known symbols."""

    def __init__(self, graph: Dict) -> None:
        self.graph = graph
        self.symbols = GlobalSymbolTable()
        self.node_index = {n["id"]: n for n in graph.get("nodes", [])}

    def run(self) -> Dict:
        """Resolve call edges in-place and return the graph."""
        self.symbols.build(self.graph)
        resolved_count = 0
        unresolved_count = 0
        resolved_edges: List[Dict] = []

        for edge in self.graph.get("edges", []):
            if edge["relation"] != EdgeRelation.CALLS.value:
                resolved_edges.append(edge)
                continue
            target_id = edge["target"]
            if target_id in self.node_index:
                resolved_edges.append(edge)
                continue

            source_node = self.node_index.get(edge["source"], {})
            source_scope = source_node.get("file")
            resolved_id = self.symbols.resolve(
                target_id,
                file_scope=source_scope,
                source_node=source_node,
            )
            edge = dict(edge)
            if resolved_id:
                edge["target"] = resolved_id
                edge.setdefault("metadata", {})["resolved"] = True
                resolved_count += 1
            else:
                edge.setdefault("metadata", {})["unresolved"] = True
                unresolved_count += 1
            resolved_edges.append(edge)

        self.graph["edges"] = resolved_edges
        self.graph["_resolution_stats"] = {
            "resolved": resolved_count,
            "unresolved": unresolved_count,
        }
        return self.graph


def make_node_id(file_path: str, name: str) -> str:
    """Make a stable graph node id."""
    return hashlib.sha256(f"{file_path}::{name}".encode()).hexdigest()[:16]
