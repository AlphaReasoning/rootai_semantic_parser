"""Symbol resolution and SSA helpers."""

from __future__ import annotations

import hashlib
from collections import defaultdict
import os
from typing import Dict, List, Optional, Tuple

from models import EdgeRelation, NodeType


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
        self.import_aliases: Dict[Tuple[str, str], Dict] = {}

    def build(self, graph: Dict) -> None:
        """Build indexes from a graph.

        Fix 2 additions
        ---------------
        * Indexes each non-synthetic FUNCTION node under its short name
          (``label.split('::')[-1]``) in a new ``short_name_index`` so that
          stub call-target nodes with qualified labels like ``"Command::new"``
          can be resolved to the real function whose label is ``"new"``.
        * Also reads ``metadata.call_name_short`` on synthetic stubs to
          perform the same lookup during resolution.
        """
        self.index.clear()
        self.qualified_index.clear()
        self.file_scoped_index.clear()
        self.origin_scoped_index.clear()
        self.import_aliases.clear()
        self.short_name_index: Dict[str, List[str]] = defaultdict(list)  # Fix 2
        for node in graph.get("nodes", []):
            name = node.get("label")
            if not name:
                continue
            nid = node["id"]
            if node.get("type") == NodeType.IMPORT.value:
                origin_key = self._origin_key(node)
                if origin_key:
                    self.import_aliases[(origin_key, name)] = node.get("metadata", {})
            if nid not in self.index[name]:
                self.index[name].append(nid)
            # Fix 2: short-name index (only for non-synthetic nodes).
            metadata = node.get("metadata", {})
            is_synthetic = metadata.get("synthetic") not in (None, False)
            if not is_synthetic and "::" in name:
                short = name.split("::")[-1]
                if nid not in self.short_name_index[short]:
                    self.short_name_index[short].append(nid)
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
        """Resolve a symbol name to a concrete node id.

        Fix 2: after the existing lookup chain fails, try the short-name
        index using ``name.split('::')[-1]``.
        """
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
        # Fix 2: short-name fallback for qualified callee labels.
        short = name.split("::")[-1] if "::" in name else name
        if short != name:
            short_matches = getattr(self, "short_name_index", {}).get(short, [])
            if len(short_matches) == 1:
                return short_matches[0]
        return None

    def resolve_imported(
        self,
        name: str,
        file_scope: Optional[str] = None,
        source_node: Optional[Dict] = None,
    ) -> Optional[str]:
        """Resolve a symbol through static import aliases from the source scope."""
        source_node = source_node or {}
        source_origin = self._origin_key(source_node, fallback=file_scope or "")
        if not self._has_stable_origin(source_node, fallback=file_scope or ""):
            return None
        parts = [part for part in name.split(".") if part]
        if not parts:
            return None
        alias = parts[0]
        import_meta = self.import_aliases.get((source_origin, alias))
        if not import_meta:
            return None
        module_hint = str(import_meta.get("import_module") or "")
        imported_name = import_meta.get("import_name")
        if imported_name:
            target_name = ".".join([str(imported_name)] + parts[1:])
        elif len(parts) > 1:
            target_name = parts[-1]
        else:
            target_name = os.path.basename(module_hint.rstrip(".")).split(".")[0]
        return self.resolve_in_module(target_name, module_hint)

    def resolve_in_module(self, name: str, module_hint: str) -> Optional[str]:
        """Resolve a symbol by label and imported module/file hint."""
        simple_name = name.rsplit(".", 1)[-1]
        candidates = self.index.get(simple_name, [])
        if not candidates:
            return None
        module_matches = [nid for nid in candidates if self._module_matches(self._node_file(nid), module_hint)]
        if len(module_matches) == 1:
            return module_matches[0]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def _node_file(self, node_id: str) -> str:
        for key, ids in self.file_scoped_index.items():
            if node_id in ids:
                return key[0]
        for key, ids in self.origin_scoped_index.items():
            if node_id in ids:
                return key[0]
        return ""

    @staticmethod
    def _module_matches(file_path: str, module_hint: str) -> bool:
        if not file_path or not module_hint:
            return False
        module_parts = [part for part in module_hint.lstrip(".").split(".") if part]
        if not module_parts:
            return False
        normalized = file_path.replace("\\", "/")
        stem = os.path.splitext(os.path.basename(normalized))[0]
        if stem == module_parts[-1]:
            return True
        suffix = "/".join(module_parts)
        return normalized.endswith(f"/{suffix}.py") or normalized.endswith(f"/{suffix}/__init__.py")


class SymbolResolver:
    """Resolve synthetic call targets to known symbols."""

    def __init__(self, graph: Dict) -> None:
        self.graph = graph
        self.symbols = GlobalSymbolTable()
        self.node_index = {n["id"]: n for n in graph.get("nodes", [])}

    def run(self) -> Dict:
        """Resolve static symbol endpoints in-place and return the graph."""
        self.symbols.build(self.graph)
        resolved_count = 0
        unresolved_count = 0
        resolved_edges: List[Dict] = []

        for edge in self.graph.get("edges", []):
            if edge["relation"] not in {
                EdgeRelation.CALLS.value,
                EdgeRelation.DATAFLOW.value,
                EdgeRelation.RETURNS.value,
                EdgeRelation.INHERITS.value,
            }:
                resolved_edges.append(edge)
                continue

            source_node = self.node_index.get(edge["source"], {})
            source_scope = source_node.get("file")
            edge = dict(edge)
            endpoint_resolved = False

            resolved_source = self._resolve_endpoint(edge["source"], source_node, source_scope)
            if resolved_source and resolved_source != edge["source"]:
                edge["source"] = resolved_source
                edge.setdefault("metadata", {})["resolved_source"] = True
                endpoint_resolved = True

            source_node = self.node_index.get(edge["source"], source_node)
            source_scope = source_node.get("file") or source_scope
            resolved_target = self._resolve_endpoint(edge["target"], source_node, source_scope)
            if resolved_target and resolved_target != edge["target"]:
                edge["target"] = resolved_target
                edge.setdefault("metadata", {})["resolved_target"] = True
                endpoint_resolved = True

            if endpoint_resolved:
                edge.setdefault("metadata", {})["resolved"] = True
                resolved_count += 1
            elif self._should_count_unresolved(edge["target"]):
                edge.setdefault("metadata", {})["unresolved"] = True
                unresolved_count += 1
            else:
                target_id = edge["target"]
                if target_id not in self.node_index:
                    resolved_id = self.symbols.resolve(
                        target_id,
                        file_scope=source_scope,
                        source_node=source_node,
                    )
                    if resolved_id:
                        edge["target"] = resolved_id
                        edge.setdefault("metadata", {})["resolved"] = True
                        resolved_count += 1
            resolved_edges.append(edge)

        self.graph["edges"] = resolved_edges
        self.graph["_resolution_stats"] = {
            "resolved": resolved_count,
            "unresolved": unresolved_count,
        }
        return self.graph

    def _resolve_endpoint(self, endpoint_id: str, source_node: Dict, source_scope: Optional[str]) -> Optional[str]:
        endpoint_node = self.node_index.get(endpoint_id)
        if endpoint_node:
            metadata = endpoint_node.get("metadata", {})
            if endpoint_node.get("type") == NodeType.IMPORT.value:
                symbol = str(metadata.get("import_alias") or endpoint_node.get("label") or "")
                return self.symbols.resolve_imported(symbol, file_scope=source_scope, source_node=endpoint_node)
            # Fix 2: match string synthetic tag (was bool True in old code).
            if metadata.get("synthetic") == "call_target":
                # Try call_name_short first (the bare leaf after '::').
                short_name = str(metadata.get("call_name_short") or "")
                symbol = str(metadata.get("call_name") or endpoint_node.get("label") or "")
                resolved = None
                if short_name and short_name != symbol:
                    resolved = (
                        self.symbols.resolve_imported(short_name, file_scope=source_scope, source_node=source_node)
                        or self.symbols.resolve(short_name, file_scope=source_scope, source_node=source_node)
                    )
                if not resolved:
                    resolved = (
                        self.symbols.resolve_imported(symbol, file_scope=source_scope, source_node=source_node)
                        or self.symbols.resolve(symbol, file_scope=source_scope, source_node=source_node)
                    )
                return resolved
            return None
        return self.symbols.resolve_imported(endpoint_id, file_scope=source_scope, source_node=source_node) or self.symbols.resolve(
            endpoint_id,
            file_scope=source_scope,
            source_node=source_node,
        )

    def _should_count_unresolved(self, endpoint_id: str) -> bool:
        endpoint_node = self.node_index.get(endpoint_id)
        if not endpoint_node:
            return True
        metadata = endpoint_node.get("metadata", {})
        # Fix 2: synthetic is now a string, not a bool.
        return endpoint_node.get("type") == NodeType.IMPORT.value or metadata.get("synthetic") == "call_target"


def make_node_id(file_path: str, name: str) -> str:
    """Make a stable graph node id."""
    return hashlib.sha256(f"{file_path}::{name}".encode()).hexdigest()[:16]
