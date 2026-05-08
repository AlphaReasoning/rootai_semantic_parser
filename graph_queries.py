"""Deterministic graph query engine for semantic IR graphs."""

from __future__ import annotations

import shlex
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class GraphQueryError(ValueError):
    """Raised when a graph query cannot be resolved deterministically."""


class GraphQueryEngine:
    """Run deterministic traversals over a semantic graph."""

    def __init__(self, graph: Dict[str, Any]) -> None:
        self.graph = graph
        self.nodes: Dict[str, Dict[str, Any]] = {node["id"]: node for node in graph.get("nodes", [])}
        self.edges: List[Dict[str, Any]] = sorted(
            graph.get("edges", []),
            key=lambda edge: (
                str(edge.get("source", "")),
                str(edge.get("target", "")),
                str(edge.get("relation", "")),
            ),
        )
        self.out_adj: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.in_adj: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._label_index: Dict[str, List[str]] = defaultdict(list)
        for node in graph.get("nodes", []):
            for key in {
                str(node.get("label", "")),
                str(node.get("qualified_name", "")),
                str(node.get("metadata", {}).get("symbol", "")),
            }:
                if key:
                    self._label_index[key].append(node["id"])
        for edge in self.edges:
            self.out_adj[str(edge.get("source"))].append(edge)
            self.in_adj[str(edge.get("target"))].append(edge)

    def resolve_node(self, ref: str) -> str:
        """Resolve a node id, label, qualified name, or symbol to one node id."""
        if ref in self.nodes:
            return ref
        matches = sorted(set(self._label_index.get(ref, [])))
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise GraphQueryError(f"Unknown node reference: {ref}")
        labels = ", ".join(matches[:5])
        raise GraphQueryError(f"Ambiguous node reference '{ref}' matched {len(matches)} nodes: {labels}")

    def shortest_path(
        self,
        source: str,
        target: str,
        relations: Optional[Set[str]] = None,
        max_depth: Optional[int] = None,
        direction: str = "out",
    ) -> Dict[str, Any]:
        """Return the shortest deterministic path between two nodes."""
        source_id = self.resolve_node(source)
        target_id = self.resolve_node(target)
        if source_id == target_id:
            return {
                "query": "path",
                "found": True,
                "source": self._node_summary(source_id),
                "target": self._node_summary(target_id),
                "nodes": [self._node_summary(source_id)],
                "edges": [],
                "depth": 0,
            }

        queue: Deque[Tuple[str, int]] = deque([(source_id, 0)])
        seen = {source_id}
        parent: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        while queue:
            current, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue
            for edge, neighbor in self._neighbors(current, direction, relations):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                parent[neighbor] = (current, edge)
                if neighbor == target_id:
                    return self._render_path(source_id, target_id, parent)
                queue.append((neighbor, depth + 1))

        return {
            "query": "path",
            "found": False,
            "source": self._node_summary(source_id),
            "target": self._node_summary(target_id),
            "nodes": [],
            "edges": [],
            "depth": None,
        }

    def traverse(
        self,
        start: str,
        algorithm: str = "bfs",
        direction: str = "out",
        relations: Optional[Set[str]] = None,
        max_depth: int = 2,
    ) -> Dict[str, Any]:
        """Return a deterministic BFS or DFS reachability cone."""
        start_id = self.resolve_node(start)
        if algorithm not in {"bfs", "dfs"}:
            raise GraphQueryError("algorithm must be 'bfs' or 'dfs'")
        if max_depth < 0:
            raise GraphQueryError("max_depth must be non-negative")

        frontier: Deque[Tuple[str, int]] = deque([(start_id, 0)])
        seen = {start_id}
        depths = {start_id: 0}
        traversed_edges: List[Dict[str, Any]] = []
        while frontier:
            current, depth = frontier.popleft() if algorithm == "bfs" else frontier.pop()
            if depth >= max_depth:
                continue
            neighbors = self._neighbors(current, direction, relations)
            if algorithm == "dfs":
                neighbors = list(reversed(neighbors))
            for edge, neighbor in neighbors:
                traversed_edges.append(self._edge_summary(edge))
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                depths[neighbor] = depth + 1
                frontier.append((neighbor, depth + 1))

        ordered_nodes = sorted(seen, key=lambda nid: (depths.get(nid, 0), self._node_sort_key(nid)))
        return {
            "query": algorithm,
            "start": self._node_summary(start_id),
            "direction": direction,
            "max_depth": max_depth,
            "nodes": [self._node_summary(nid) | {"depth": depths.get(nid, 0)} for nid in ordered_nodes],
            "edges": traversed_edges,
        }

    def strongly_connected_components(self, relations: Optional[Set[str]] = None, min_size: int = 2) -> Dict[str, Any]:
        """Return Tarjan strongly connected components."""
        index = 0
        stack: List[str] = []
        on_stack: Set[str] = set()
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        components: List[List[str]] = []

        def visit(node_id: str) -> None:
            nonlocal index
            indices[node_id] = index
            lowlinks[node_id] = index
            index += 1
            stack.append(node_id)
            on_stack.add(node_id)

            for _, neighbor in self._neighbors(node_id, "out", relations):
                if neighbor not in indices:
                    visit(neighbor)
                    lowlinks[node_id] = min(lowlinks[node_id], lowlinks[neighbor])
                elif neighbor in on_stack:
                    lowlinks[node_id] = min(lowlinks[node_id], indices[neighbor])

            if lowlinks[node_id] == indices[node_id]:
                component: List[str] = []
                while stack:
                    item = stack.pop()
                    on_stack.remove(item)
                    component.append(item)
                    if item == node_id:
                        break
                if len(component) >= min_size:
                    components.append(sorted(component, key=self._node_sort_key))

        for node_id in sorted(self.nodes, key=self._node_sort_key):
            if node_id not in indices:
                visit(node_id)

        components.sort(key=lambda component: (-len(component), [self._node_sort_key(nid) for nid in component]))
        return {
            "query": "scc",
            "components": [[self._node_summary(nid) for nid in component] for component in components],
            "component_count": len(components),
        }

    def degree_centrality(self, relations: Optional[Set[str]] = None, limit: int = 20) -> Dict[str, Any]:
        """Return deterministic degree centrality rankings."""
        rows: List[Dict[str, Any]] = []
        for node_id in self.nodes:
            out_degree = sum(1 for edge in self.out_adj.get(node_id, []) if self._relation_allowed(edge, relations))
            in_degree = sum(1 for edge in self.in_adj.get(node_id, []) if self._relation_allowed(edge, relations))
            total = in_degree + out_degree
            if total:
                rows.append(self._node_summary(node_id) | {"in_degree": in_degree, "out_degree": out_degree, "degree": total})
        rows.sort(key=lambda row: (-int(row["degree"]), -int(row["out_degree"]), str(row.get("label", "")), str(row.get("id", ""))))
        return {"query": "centrality", "nodes": rows[:limit], "limit": limit}

    def execute(self, expr: str) -> Dict[str, Any]:
        """Execute a small deterministic query DSL."""
        tokens = shlex.split(expr)
        if not tokens:
            raise GraphQueryError("empty query expression")
        command = tokens[0].lower()
        args = self._parse_args(tokens[1:])
        relations = self._parse_relations(args.get("relations") or args.get("relation"))
        if command in {"path", "reachable"}:
            source = args.get("source") or args.get("from")
            target = args.get("target") or args.get("to")
            if not source or not target:
                raise GraphQueryError("path queries require source= and target=")
            depth = self._optional_int(args.get("depth") or args.get("max_depth"))
            return self.shortest_path(source, target, relations=relations, max_depth=depth)
        if command in {"cone", "bfs", "dfs"}:
            start = args.get("start") or args.get("source")
            if not start:
                raise GraphQueryError("cone/bfs/dfs queries require start=")
            depth = self._optional_int(args.get("depth") or args.get("max_depth")) or 2
            algorithm = command if command in {"bfs", "dfs"} else args.get("algorithm", "bfs")
            direction = args.get("direction", "out")
            return self.traverse(start, algorithm=algorithm, direction=direction, relations=relations, max_depth=depth)
        if command == "scc":
            min_size = self._optional_int(args.get("min_size")) or 2
            return self.strongly_connected_components(relations=relations, min_size=min_size)
        if command == "centrality":
            limit = self._optional_int(args.get("limit")) or 20
            return self.degree_centrality(relations=relations, limit=limit)
        raise GraphQueryError(f"unknown query command: {command}")

    def _neighbors(
        self,
        node_id: str,
        direction: str,
        relations: Optional[Set[str]],
    ) -> List[Tuple[Dict[str, Any], str]]:
        if direction not in {"out", "in", "both"}:
            raise GraphQueryError("direction must be one of: out, in, both")
        pairs: List[Tuple[Dict[str, Any], str]] = []
        if direction in {"out", "both"}:
            pairs.extend((edge, str(edge.get("target"))) for edge in self.out_adj.get(node_id, []) if self._relation_allowed(edge, relations))
        if direction in {"in", "both"}:
            pairs.extend((edge, str(edge.get("source"))) for edge in self.in_adj.get(node_id, []) if self._relation_allowed(edge, relations))
        return sorted(pairs, key=lambda item: (self._node_sort_key(item[1]), str(item[0].get("relation", ""))))

    @staticmethod
    def _relation_allowed(edge: Dict[str, Any], relations: Optional[Set[str]]) -> bool:
        return relations is None or str(edge.get("relation")) in relations

    def _render_path(
        self,
        source_id: str,
        target_id: str,
        parent: Dict[str, Tuple[str, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        nodes: List[str] = [target_id]
        edges: List[Dict[str, Any]] = []
        current = target_id
        while current != source_id:
            previous, edge = parent[current]
            edges.append(edge)
            nodes.append(previous)
            current = previous
        nodes.reverse()
        edges.reverse()
        return {
            "query": "path",
            "found": True,
            "source": self._node_summary(source_id),
            "target": self._node_summary(target_id),
            "nodes": [self._node_summary(nid) for nid in nodes],
            "edges": [self._edge_summary(edge) for edge in edges],
            "depth": len(edges),
        }

    def _node_summary(self, node_id: str) -> Dict[str, Any]:
        node = self.nodes.get(node_id, {"id": node_id})
        return {
            "id": node_id,
            "label": node.get("label", node_id),
            "type": node.get("type", "unknown"),
            "file": node.get("file", ""),
            "lineno": node.get("lineno"),
        }

    def _edge_summary(self, edge: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": edge.get("source"),
            "target": edge.get("target"),
            "relation": edge.get("relation"),
            "fragility_score": edge.get("fragility_score"),
        }

    def _node_sort_key(self, node_id: str) -> Tuple[str, str, str]:
        node = self.nodes.get(node_id, {})
        return (str(node.get("label", "")), str(node.get("file", "")), node_id)

    @staticmethod
    def _parse_args(tokens: Sequence[str]) -> Dict[str, str]:
        args: Dict[str, str] = {}
        positionals: List[str] = []
        for token in tokens:
            if "=" in token:
                key, value = token.split("=", 1)
                args[key.strip().lower().replace("-", "_")] = value.strip()
            else:
                positionals.append(token)
        if positionals:
            args.setdefault("source", positionals[0])
        if len(positionals) > 1:
            args.setdefault("target", positionals[1])
        return args

    @staticmethod
    def _parse_relations(value: Optional[str]) -> Optional[Set[str]]:
        if not value or value.lower() in {"all", "*"}:
            return None
        return {item.strip() for item in value.split(",") if item.strip()}

    @staticmethod
    def _optional_int(value: Optional[str]) -> Optional[int]:
        if value is None or value == "":
            return None
        return int(value)


def render_query_text(result: Dict[str, Any]) -> str:
    """Render a deterministic query result as compact text."""
    query = result.get("query")
    if query == "path":
        if not result.get("found"):
            return f"No path: {result.get('source', {}).get('label')} -> {result.get('target', {}).get('label')}"
        labels = [node.get("label", node.get("id")) for node in result.get("nodes", [])]
        relations = [edge.get("relation", "?") for edge in result.get("edges", [])]
        steps: List[str] = []
        for index, label in enumerate(labels):
            steps.append(str(label))
            if index < len(relations):
                steps.append(f"-[{relations[index]}]->")
        return " ".join(steps)
    if query in {"bfs", "dfs"}:
        return "\n".join(
            f"{node.get('depth', 0):>2}  {node.get('label')}  {node.get('file')}:{node.get('lineno') or ''}"
            for node in result.get("nodes", [])
        )
    if query == "centrality":
        return "\n".join(
            f"{node.get('degree', 0):>3}  in={node.get('in_degree', 0):>3} out={node.get('out_degree', 0):>3}  {node.get('label')}"
            for node in result.get("nodes", [])
        )
    if query == "scc":
        lines = []
        for component in result.get("components", []):
            lines.append(" -> ".join(str(node.get("label", node.get("id"))) for node in component))
        return "\n".join(lines) if lines else "No strongly connected components matched."
    return str(result)
