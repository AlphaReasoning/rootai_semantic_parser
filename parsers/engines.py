"""Language parser implementations."""

from __future__ import annotations

import ast
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzers.symbols import SSAVersionTracker, make_node_id
from models import AnalysisOptions, Edge, EdgeRelation, Node, NodeType, SecurityConfig

try:
    from tqdm import tqdm  # noqa: F401
except ImportError:
    pass

try:
    from tree_sitter import Language as TSLanguage
    from tree_sitter import Parser as TSParser
    try:
        from tree_sitter_languages import get_language as ts_get_language
    except ImportError:
        from tree_sitter_language_pack import get_language as ts_get_language
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TSLanguage = None
    TSParser = None
    TREE_SITTER_AVAILABLE = False

try:
    import tree_sitter_javascript
except ImportError:
    tree_sitter_javascript = None

try:
    import tree_sitter_go
except ImportError:
    tree_sitter_go = None

try:
    import tree_sitter_typescript
except ImportError:
    tree_sitter_typescript = None


def resolve_tree_sitter_language(language_name: str):
    """Resolve a tree-sitter language object."""
    if not TREE_SITTER_AVAILABLE:
        raise ImportError("tree-sitter runtime is unavailable")
    if language_name == "javascript" and tree_sitter_javascript is not None:
        return TSLanguage(tree_sitter_javascript.language())
    if language_name == "go" and tree_sitter_go is not None:
        return TSLanguage(tree_sitter_go.language())
    if language_name == "typescript" and tree_sitter_typescript is not None:
        return TSLanguage(tree_sitter_typescript.language_typescript())
    if language_name == "tsx" and tree_sitter_typescript is not None:
        return TSLanguage(tree_sitter_typescript.language_tsx())
    return ts_get_language(language_name)


def safe_unparse(node: Optional[ast.AST]) -> Optional[str]:
    """Safely unparse an AST node."""
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


class LanguageParser:
    """Base class for language parsers."""

    language: str = "unknown"

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        self.config = config
        self.options = options or AnalysisOptions(profile=config.stack if config.stack else "default")
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []

    def parse(self, path: str) -> None:
        """Parse a file."""
        raise NotImplementedError

    @classmethod
    def supports(cls, path: str) -> bool:
        """Return whether the parser supports a file path."""
        del path
        return False

    def _make_id(self, file: str, name: str) -> str:
        return make_node_id(file, name)

    def _make_node(self, nid: str, ntype: NodeType, label: str, file: str, lineno: Optional[int] = None) -> Node:
        is_pii, logic = self.config.classify_node(label, ntype.value)
        return Node(
            id=nid,
            type=ntype.value,
            label=label,
            file=file,
            lineno=lineno,
            qualified_name=f"{file}::{label}",
            language=self.language,
            is_pii_sensitive=is_pii,
            logic_class=logic.value,
        )

    def _edge(self, src: str, tgt: str, rel: EdgeRelation, metadata: Optional[Dict[str, Any]] = None) -> Edge:
        edge = Edge(source=src, target=tgt, relation=rel.value)
        if metadata:
            edge.metadata.update(metadata)
        return edge


class TreeSitterParser(LanguageParser):
    """Shared tree-sitter parser base."""

    def __init__(self, config: SecurityConfig, language_name: str, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, options=options)
        self.language_name = language_name
        if TREE_SITTER_AVAILABLE:
            self._ts_parser = TSParser()
            self._ts_language = resolve_tree_sitter_language(language_name)
            if hasattr(self._ts_parser, "set_language"):
                self._ts_parser.set_language(self._ts_language)
            else:
                self._ts_parser.language = self._ts_language
        else:
            self._ts_parser = None

    def _parse_code(self, code: str):
        return self._ts_parser.parse(bytes(code, "utf8"))

    @staticmethod
    def _get_text(code: str, node) -> str:
        """Return the exact source text spanned by ``node``.

        tree-sitter reports *byte* offsets. Slicing the decoded ``code`` str with
        them silently corrupts every span after the first non-ASCII byte, so the
        node's own byte payload is authoritative here; ``code`` is only used as a
        fallback for trees parsed without retained source.
        """
        raw = getattr(node, "text", None)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
        return code.encode("utf-8")[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _mark_function_entrypoint(node: Node, name: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    """Mark a function node as a likely entrypoint/auth guard."""
    metadata = metadata or node.metadata
    lower_name = name.lower()
    patterns = (
        "handler", "resolver", "mutation", "query", "consumer", "route", "endpoint",
        "controller", "requestmapping", "getmapping", "postmapping", "putmapping",
        "patchmapping", "deletemapping", "restcontroller", "fastapi", "apirouter", "gin",
    )
    metadata["entrypoint"] = bool(metadata.get("entrypoint")) or any(token in lower_name for token in patterns)
    metadata["auth_guard"] = bool(metadata.get("auth_guard")) or any(
        token in lower_name for token in ("auth", "guard", "admin", "permission")
    )


class PythonParser(LanguageParser):
    """Python parser with SSA-aware taint edges."""

    language = "python"
    _ENTRYPOINT_DECORATORS = ("route", "api", "graphql", "resolver", "mutation", "query", "consumer", "handler", "get", "post", "put", "patch", "delete", "websocket")
    _AUTH_GUARD_HINTS = ("login_required", "require_auth", "authenticated", "permission", "admin_required", "staff_only")

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, options=options)
        self.ssa = SSAVersionTracker()
        self._import_aliases: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".py")

    def parse(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
            tree = ast.parse(source, filename=path)
        except (OSError, SyntaxError):
            return

        module_id = self._make_id(path, "__module__")
        self.nodes[module_id] = self._make_node(module_id, NodeType.MODULE, os.path.basename(path), path)
        self._import_aliases = {}
        fn_ranges: List[Tuple[int, int, str]] = []
        class_map: Dict[str, str] = {}
        deferred_calls: List[ast.Call] = []
        deferred_assigns: List[ast.AST] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._record_import(path, module_id, node)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                cid = self._make_id(path, node.name)
                self.nodes[cid] = self._make_node(cid, NodeType.CLASS, node.name, path, node.lineno)
                class_map[node.name] = cid
                self.edges.append(self._edge(module_id, cid, EdgeRelation.CONTAINS))
                for base in node.bases:
                    base_name = self._expr_name(base)
                    if base_name:
                        self.edges.append(
                            self._edge(
                                cid,
                                self._make_id(path, base_name),
                                EdgeRelation.INHERITS,
                                {"static": True, "target_symbol": base_name},
                            )
                        )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                nid = self._make_id(path, node.name)
                self.nodes[nid] = self._make_node(nid, NodeType.FUNCTION, node.name, path, node.lineno)
                decorators = [safe_unparse(item) or "" for item in node.decorator_list]
                metadata = self.nodes[nid].metadata
                metadata["decorators"] = decorators
                metadata["framework"] = "fastapi" if any("router." in d.lower() or "fastapi" in d.lower() for d in decorators) else ""
                metadata["entrypoint"] = any(token in d.lower() for d in decorators for token in self._ENTRYPOINT_DECORATORS) or any(
                    token in node.name.lower() for token in ("handler", "resolver", "endpoint", "route", "controller")
                )
                metadata["auth_guard"] = any(token in d.lower() for d in decorators for token in self._AUTH_GUARD_HINTS)
                _mark_function_entrypoint(self.nodes[nid], node.name, metadata)
                parent_id = module_id
                for cls_id in class_map.values():
                    cls_node = self.nodes.get(cls_id)
                    if cls_node and cls_node.lineno and node.lineno > cls_node.lineno:
                        parent_id = cls_id
                self.edges.append(self._edge(parent_id, nid, EdgeRelation.CONTAINS))
                end = getattr(node, "end_lineno", node.lineno + 999)
                fn_ranges.append((node.lineno, end, nid))
                args_list = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args) + list(getattr(node.args, "kwonlyargs", []))
                if node.args.vararg:
                    args_list.append(node.args.vararg)
                if node.args.kwarg:
                    args_list.append(node.args.kwarg)
                # Recorded for CrossFileCallResolver, which binds a caller's
                # arguments to these parameters positionally.
                metadata["declares"] = node.name
                param_ids: List[str] = []
                for arg in args_list:
                    arg_name = arg.arg
                    ssa_label = arg_name if self.options.quick_mode else self.ssa.get_versioned_id(arg_name)
                    var_id = self._make_id(path, ssa_label)
                    self.nodes[var_id] = self._make_node(var_id, NodeType.VARIABLE, ssa_label, path, node.lineno)
                    self.edges.append(self._edge(nid, var_id, EdgeRelation.DATAFLOW, {"flow_kind": "parameter"}))
                    param_ids.append(var_id)
                metadata["param_ids"] = param_ids
            elif isinstance(node, ast.Call):
                deferred_calls.append(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                deferred_assigns.append(node)
            elif isinstance(node, ast.Return) and node.value is not None:
                enclosing = self._enclosing(getattr(node, "lineno", 0), fn_ranges, module_id)
                for ref_label in self._value_refs(node.value):
                    ref_id = self._reference_id(path, ref_label, getattr(node, "lineno", 0), taint_sources=set())
                    if ref_id:
                        self.edges.append(self._edge(ref_id, enclosing, EdgeRelation.DATAFLOW, {"flow_kind": "return"}))
                        self.edges.append(self._edge(ref_id, enclosing, EdgeRelation.RETURNS))

        fn_ranges.sort()
        deferred_assigns.sort(key=lambda x: getattr(x, "lineno", 0))
        taint_sources = {"request", "args", "form", "params", "environ", "argv", "input"}
        for assign_node in deferred_assigns:
            value_node = getattr(assign_node, "value", None)
            if not value_node:
                continue
            rhs_str = ast.dump(value_node).lower()
            value_refs = self._value_refs(value_node)
            is_source = any(s in rhs_str for s in taint_sources) or any(
                any(s in ref.lower() for s in taint_sources) for ref in value_refs
            )
            assign_line = getattr(assign_node, "lineno", 0)
            enclosing = self._enclosing(assign_line, fn_ranges, module_id)
            targets = assign_node.targets if isinstance(assign_node, ast.Assign) else [assign_node.target]
            new_target_ids: List[str] = []
            for target in targets:
                for sub_targ in ast.walk(target):
                    if isinstance(sub_targ, ast.Name) and isinstance(sub_targ.ctx, ast.Store):
                        var_name = sub_targ.id
                        ssa_label = var_name if self.options.quick_mode else self.ssa.get_versioned_id(var_name)
                        var_id = self._make_id(path, ssa_label)
                        self.nodes[var_id] = self._make_node(var_id, NodeType.VARIABLE, ssa_label, path, assign_line)
                        if is_source:
                            self.nodes[var_id].is_unsafe = True
                        self.edges.append(self._edge(enclosing, var_id, EdgeRelation.DATAFLOW, {"flow_kind": "assignment"}))
                        prev_ver_num = self.ssa.counters.get(var_name, 0) - 1
                        if not self.options.quick_mode and prev_ver_num > 0:
                            prev_label = f"{var_name}_v{prev_ver_num}"
                            self.edges.append(self._edge(self._make_id(path, prev_label), var_id, EdgeRelation.DATAFLOW, {"flow_kind": "ssa"}))
                        new_target_ids.append(var_id)
            # References that are only arguments to a call in the value must not
            # get a direct edge to the target: the value they contribute passes
            # *through* that call. Linking them directly created a shortcut
            # around every transforming call, so `safe = shlex.quote(c)` let
            # taint reach `safe` without ever touching the sanitizer.
            call_arg_refs: Set[str] = set()
            for sub_node in ast.walk(value_node):
                if isinstance(sub_node, ast.Call):
                    for call_arg in list(sub_node.args) + [kw.value for kw in sub_node.keywords]:
                        call_arg_refs.update(self._value_refs(call_arg))

            for ref_label in value_refs:
                if ref_label in call_arg_refs:
                    continue
                rhs_id = self._reference_id(path, ref_label, assign_line, taint_sources=taint_sources)
                if not rhs_id:
                    continue
                for tid in new_target_ids:
                    self.edges.append(self._edge(rhs_id, tid, EdgeRelation.DATAFLOW, {"flow_kind": "assignment_rhs"}))
                    if self.nodes.get(rhs_id) and self.nodes[rhs_id].is_unsafe:
                        self.nodes[tid].is_unsafe = True
            for sub_node in ast.walk(value_node):
                if isinstance(sub_node, ast.Call):
                    callee_name = self._call_name(sub_node)
                    if callee_name:
                        callee_id = self._make_id(path, callee_name)
                        self._ensure_call_target(path, callee_name, getattr(sub_node, "lineno", assign_line))
                        for tid in new_target_ids:
                            self.edges.append(self._edge(callee_id, tid, EdgeRelation.DATAFLOW, {"flow_kind": "call_return"}))

        for call_node in deferred_calls:
            callee_name = self._call_name(call_node)
            if not callee_name:
                continue
            callee_id = self._make_id(path, callee_name)
            call_line = getattr(call_node, "lineno", 0)
            caller_id = self._enclosing(call_line, fn_ranges, module_id)
            self._ensure_call_target(path, callee_name, call_line)
            self.edges.append(self._edge(caller_id, callee_id, EdgeRelation.CALLS, {"static": True, "call_name": callee_name}))
            for arg_index, arg in enumerate(call_node.args):
                for ref_label in self._value_refs(arg):
                    arg_id = self._reference_id(path, ref_label, call_line, taint_sources=taint_sources)
                    if arg_id:
                        self.edges.append(
                            self._edge(
                                arg_id,
                                callee_id,
                                EdgeRelation.DATAFLOW,
                                {"flow_kind": "call_argument", "arg_index": arg_index},
                            )
                        )
                        if self.nodes.get(arg_id) and self.nodes[arg_id].is_unsafe:
                            self.nodes[callee_id].is_unsafe = True

    def _record_import(self, path: str, module_id: str, node: ast.AST) -> None:
        """Record static import bindings for later cross-file resolution."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                self._add_import_node(
                    path,
                    module_id,
                    module_name=alias.name,
                    import_name=None,
                    local_name=local_name,
                    lineno=getattr(node, "lineno", None),
                )
        elif isinstance(node, ast.ImportFrom):
            module_name = "." * int(getattr(node, "level", 0) or 0) + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    continue
                self._add_import_node(
                    path,
                    module_id,
                    module_name=module_name,
                    import_name=alias.name,
                    local_name=alias.asname or alias.name,
                    lineno=getattr(node, "lineno", None),
                )

    def _add_import_node(
        self,
        path: str,
        module_id: str,
        module_name: str,
        import_name: Optional[str],
        local_name: str,
        lineno: Optional[int],
    ) -> None:
        import_id = self._make_id(path, f"import:{local_name}")
        node = self._make_node(import_id, NodeType.IMPORT, local_name, path, lineno)
        node.qualified_name = f"{module_name}.{import_name}" if import_name else module_name
        node.metadata.update(
            {
                "symbol": local_name,
                "import_module": module_name,
                "import_name": import_name,
                "import_alias": local_name,
            }
        )
        self.nodes[import_id] = node
        self._import_aliases[local_name] = node.metadata
        self.edges.append(
            self._edge(
                module_id,
                import_id,
                EdgeRelation.IMPORTS,
                {"module": module_name, "import_name": import_name, "alias": local_name},
            )
        )

    def _ensure_call_target(self, path: str, callee_name: str, lineno: Optional[int]) -> str:
        """Create a synthetic call target node when no local declaration exists."""
        callee_id = self._make_id(path, callee_name)
        if callee_id not in self.nodes:
            node = self._make_node(callee_id, NodeType.FUNCTION, callee_name, path, lineno)
            node.metadata.update(
                {
                    "synthetic": "call_target",
                    "call_name": callee_name,
                    "callee_short": callee_name.split(".")[-1],
                }
            )
            self.nodes[callee_id] = node
        return callee_id

    def _reference_id(self, path: str, label: str, lineno: Optional[int], taint_sources: Set[str]) -> Optional[str]:
        """Resolve or create a graph node for a value expression reference."""
        if "." not in label:
            current_label = label if self.options.quick_mode else self.ssa.get_current_id(label)
            if current_label:
                node_id = self._make_id(path, current_label)
                if node_id in self.nodes:
                    return node_id
            import_meta = self._import_aliases.get(label)
            if import_meta:
                return self._make_id(path, f"import:{label}")
            return None

        node_id = self._make_id(path, label)
        if node_id not in self.nodes:
            node = self._make_node(node_id, NodeType.DATA, label, path, lineno)
            node.metadata.update({"expression": label, "symbol": label})
            if any(source in label.lower() for source in taint_sources):
                node.is_unsafe = True
            self.nodes[node_id] = node
        base_label = label.rsplit(".", 1)[0]
        base_id = self._reference_id(path, base_label, lineno, taint_sources)
        if base_id:
            self.edges.append(self._edge(node_id, base_id, EdgeRelation.ATTRIBUTE_OF))
            self.edges.append(self._edge(base_id, node_id, EdgeRelation.DATAFLOW, {"flow_kind": "attribute"}))
            if self.nodes.get(base_id) and self.nodes[base_id].is_unsafe:
                self.nodes[node_id].is_unsafe = True
        return node_id

    @classmethod
    def _value_refs(cls, node: ast.AST) -> List[str]:
        """Return deterministic value reference labels, including attributes."""
        refs: Set[str] = set()
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Attribute) and isinstance(sub_node.ctx, ast.Load):
                name = cls._expr_name(sub_node)
                if name:
                    refs.add(name)
            elif isinstance(sub_node, ast.Name) and isinstance(sub_node.ctx, ast.Load):
                refs.add(sub_node.id)
        return sorted(refs, key=lambda item: (item.count("."), item))

    @staticmethod
    def _enclosing(line: int, fn_ranges: List[Tuple[int, int, str]], fallback: str) -> str:
        for start, end, fn_id in fn_ranges:
            if start <= line <= end:
                return fn_id
        return fallback

    @classmethod
    def _call_name(cls, call_node: ast.Call) -> Optional[str]:
        return cls._expr_name(call_node.func)

    @classmethod
    def _expr_name(cls, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = cls._expr_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return cls._expr_name(node.func)
        if isinstance(node, ast.Subscript):
            return cls._expr_name(node.value)
        return None
