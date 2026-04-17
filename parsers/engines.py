"""Language parser implementations."""

from __future__ import annotations

import ast
import os
import re
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

    def _edge(self, src: str, tgt: str, rel: EdgeRelation) -> Edge:
        return Edge(source=src, target=tgt, relation=rel.value)


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
        return code[node.start_byte : node.end_byte]


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
        fn_ranges: List[Tuple[int, int, str]] = []
        class_map: Dict[str, str] = {}
        deferred_calls: List[ast.Call] = []
        deferred_assigns: List[ast.AST] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                cid = self._make_id(path, node.name)
                self.nodes[cid] = self._make_node(cid, NodeType.CLASS, node.name, path, node.lineno)
                class_map[node.name] = cid
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
                self.edges.append(self._edge(parent_id, nid, EdgeRelation.IMPORTS))
                end = getattr(node, "end_lineno", node.lineno + 999)
                fn_ranges.append((node.lineno, end, nid))
                args_list = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args) + list(getattr(node.args, "kwonlyargs", []))
                if node.args.vararg:
                    args_list.append(node.args.vararg)
                if node.args.kwarg:
                    args_list.append(node.args.kwarg)
                for arg in args_list:
                    arg_name = arg.arg
                    ssa_label = arg_name if self.options.quick_mode else self.ssa.get_versioned_id(arg_name)
                    var_id = self._make_id(path, ssa_label)
                    self.nodes[var_id] = self._make_node(var_id, NodeType.VARIABLE, ssa_label, path, node.lineno)
                    self.edges.append(self._edge(nid, var_id, EdgeRelation.DATAFLOW))
            elif isinstance(node, ast.Call):
                deferred_calls.append(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                deferred_assigns.append(node)
            elif isinstance(node, ast.Return) and node.value is not None:
                enclosing = self._enclosing(getattr(node, "lineno", 0), fn_ranges, module_id)
                for sub_node in ast.walk(node.value):
                    if isinstance(sub_node, ast.Name) and isinstance(sub_node.ctx, ast.Load):
                        curr_label = sub_node.id if self.options.quick_mode else self.ssa.get_current_id(sub_node.id)
                        if curr_label:
                            self.edges.append(self._edge(self._make_id(path, curr_label), enclosing, EdgeRelation.DATAFLOW))

        fn_ranges.sort()
        deferred_assigns.sort(key=lambda x: getattr(x, "lineno", 0))
        taint_sources = {"request", "args", "form", "params", "environ", "argv", "input"}
        for assign_node in deferred_assigns:
            value_node = getattr(assign_node, "value", None)
            if not value_node:
                continue
            rhs_str = ast.dump(value_node).lower()
            is_source = any(s in rhs_str for s in taint_sources)
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
                        self.edges.append(self._edge(enclosing, var_id, EdgeRelation.DATAFLOW))
                        prev_ver_num = self.ssa.counters.get(var_name, 0) - 1
                        if not self.options.quick_mode and prev_ver_num > 0:
                            prev_label = f"{var_name}_v{prev_ver_num}"
                            self.edges.append(self._edge(self._make_id(path, prev_label), var_id, EdgeRelation.DATAFLOW))
                        new_target_ids.append(var_id)
            for sub_node in ast.walk(value_node):
                if isinstance(sub_node, ast.Name) and isinstance(sub_node.ctx, ast.Load):
                    curr_rhs_label = sub_node.id if self.options.quick_mode else self.ssa.get_current_id(sub_node.id)
                    if curr_rhs_label:
                        rhs_id = self._make_id(path, curr_rhs_label)
                        for tid in new_target_ids:
                            self.edges.append(self._edge(rhs_id, tid, EdgeRelation.DATAFLOW))
                            if self.nodes.get(rhs_id) and self.nodes[rhs_id].is_unsafe:
                                self.nodes[tid].is_unsafe = True
                elif isinstance(sub_node, ast.Call):
                    callee_name = self._call_name(sub_node)
                    if callee_name:
                        callee_id = self._make_id(path, callee_name)
                        for tid in new_target_ids:
                            self.edges.append(self._edge(callee_id, tid, EdgeRelation.DATAFLOW))

        for call_node in deferred_calls:
            callee_name = self._call_name(call_node)
            if not callee_name:
                continue
            callee_id = self._make_id(path, callee_name)
            call_line = getattr(call_node, "lineno", 0)
            caller_id = self._enclosing(call_line, fn_ranges, module_id)
            if callee_id not in self.nodes:
                self.nodes[callee_id] = self._make_node(callee_id, NodeType.FUNCTION, callee_name, path, call_line)
            self.edges.append(self._edge(caller_id, callee_id, EdgeRelation.CALLS))
            for arg in call_node.args:
                for sub_node in ast.walk(arg):
                    if isinstance(sub_node, ast.Name) and isinstance(sub_node.ctx, ast.Load):
                        curr_arg_label = sub_node.id if self.options.quick_mode else self.ssa.get_current_id(sub_node.id)
                        if curr_arg_label:
                            arg_id = self._make_id(path, curr_arg_label)
                            self.edges.append(self._edge(arg_id, callee_id, EdgeRelation.DATAFLOW))
                            if self.nodes.get(arg_id) and self.nodes[arg_id].is_unsafe:
                                self.nodes[callee_id].is_unsafe = True

    @staticmethod
    def _enclosing(line: int, fn_ranges: List[Tuple[int, int, str]], fallback: str) -> str:
        for start, end, fn_id in fn_ranges:
            if start <= line <= end:
                return fn_id
        return fallback

    @staticmethod
    def _call_name(call_node: ast.Call) -> Optional[str]:
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id
        if isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                return f"{call_node.func.value.id}.{call_node.func.attr}"
            return call_node.func.attr
        return None


class JavaScriptParser(TreeSitterParser):
    """JS/TS parser."""
    language = "javascript"
    _FN_RE = re.compile(r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(")
    _ARROW_RE = re.compile(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(")
    _CALL_RE = re.compile(r"\b(\w+)\s*\(")
    _ENTRYPOINT_HINTS = ("handler", "resolver", "mutation", "query", "consumer", "route", "endpoint", "controller", "get", "post", "put", "patch", "delete")
    _AUTH_GUARD_HINTS = ("auth", "authorize", "permission", "admin", "guard")

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, "javascript", options=options)

    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs"))

    def parse(self, path: str) -> None:
        self._parse_regex(path)

    def _parse_regex(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError:
            return
        module_id = self._make_id(path, "__module__")
        self.nodes[module_id] = self._make_node(module_id, NodeType.MODULE, os.path.basename(path), path)
        declared: Set[str] = set()
        matches = list(self._FN_RE.finditer(source)) + list(self._ARROW_RE.finditer(source))
        matches.sort(key=lambda m: m.start())
        fn_ranges: List[Tuple[int, int, str]] = []
        for i, match in enumerate(matches):
            name = match.group(1)
            nid = self._make_id(path, name)
            start_line = source[: match.start()].count("\n") + 1
            end_line = source[: matches[i + 1].start()].count("\n") if i + 1 < len(matches) else source.count("\n") + 1
            self.nodes[nid] = self._make_node(nid, NodeType.FUNCTION, name, path, start_line)
            metadata = self.nodes[nid].metadata
            metadata["framework"] = "fastapi" if "router." in source[max(0, match.start() - 80):match.start()].lower() else ""
            metadata["entrypoint"] = any(token in name.lower() for token in self._ENTRYPOINT_HINTS)
            metadata["auth_guard"] = any(token in name.lower() for token in self._AUTH_GUARD_HINTS)
            _mark_function_entrypoint(self.nodes[nid], name, metadata)
            self.edges.append(self._edge(module_id, nid, EdgeRelation.IMPORTS))
            declared.add(name)
            fn_ranges.append((start_line, end_line, nid))
        for lineno, line in enumerate(source.splitlines(), 1):
            if self._FN_RE.search(line) or self._ARROW_RE.search(line):
                continue
            for match in self._CALL_RE.finditer(line):
                callee = match.group(1)
                if callee in declared:
                    caller_id = module_id
                    for start, end, fid in fn_ranges:
                        if start <= lineno <= end:
                            caller_id = fid
                            break
                    self.edges.append(self._edge(caller_id, self._make_id(path, callee), EdgeRelation.CALLS))


class GoParser(TreeSitterParser):
    """Go parser."""
    language = "go"
    _FUNC_RE = re.compile(r"^func\s+(?:\(\s*\w+\s+[\*\w\.]+\s*\)\s+)?(\w+)\s*\(", re.M)
    _CALL_RE = re.compile(r"\b(\w+)\s*\(")

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, "go", options=options)

    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".go")

    def parse(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError:
            return
        module_id = self._make_id(path, "__module__")
        self.nodes[module_id] = self._make_node(module_id, NodeType.MODULE, os.path.basename(path), path)
        declared: Set[str] = set()
        matches = list(self._FUNC_RE.finditer(source))
        fn_ranges: List[Tuple[int, int, str]] = []
        for i, match in enumerate(matches):
            name = match.group(1)
            nid = self._make_id(path, name)
            start_line = source[: match.start()].count("\n") + 1
            end_line = source[: matches[i + 1].start()].count("\n") if i + 1 < len(matches) else source.count("\n") + 1
            self.nodes[nid] = self._make_node(nid, NodeType.FUNCTION, name, path, start_line)
            self.nodes[nid].metadata["framework"] = "gin" if "gin." in source[max(0, match.start() - 160):match.start()].lower() else ""
            _mark_function_entrypoint(self.nodes[nid], name)
            self.edges.append(self._edge(module_id, nid, EdgeRelation.IMPORTS))
            declared.add(name)
            fn_ranges.append((start_line, end_line, nid))
        for lineno, line in enumerate(source.splitlines(), 1):
            if self._FUNC_RE.search(line):
                continue
            for match in self._CALL_RE.finditer(line):
                callee = match.group(1)
                if callee in declared:
                    caller_id = module_id
                    for start, end, fid in fn_ranges:
                        if start <= lineno <= end:
                            caller_id = fid
                            break
                    self.edges.append(self._edge(caller_id, self._make_id(path, callee), EdgeRelation.CALLS))


class _RegexLanguageParser(LanguageParser):
    """Regex parser base for simpler languages."""
    _FUNC_RE: re.Pattern[str]
    _CALL_RE: re.Pattern[str] = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

    def _parse_with_regex(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError:
            return
        module_id = self._make_id(path, "__module__")
        self.nodes[module_id] = self._make_node(module_id, NodeType.MODULE, os.path.basename(path), path)
        declared: Set[str] = set()
        matches = list(self._FUNC_RE.finditer(source))
        fn_ranges: List[Tuple[int, int, str]] = []
        for i, match in enumerate(matches):
            name = match.group(1)
            nid = self._make_id(path, name)
            start_line = source[: match.start()].count("\n") + 1
            end_line = source[: matches[i + 1].start()].count("\n") if i + 1 < len(matches) else source.count("\n") + 1
            self.nodes[nid] = self._make_node(nid, NodeType.FUNCTION, name, path, start_line)
            _mark_function_entrypoint(self.nodes[nid], name)
            context_window = source[max(0, match.start() - 240):match.start()].lower()
            if any(token in context_window for token in ("@getmapping","@postmapping","@putmapping","@patchmapping","@deletemapping","@requestmapping","@restcontroller","@controller","router.get","router.post","router.put","router.patch","router.delete","mapget","gin.")):
                self.nodes[nid].metadata["entrypoint"] = True
            if "@restcontroller" in context_window or "@controller" in context_window:
                self.nodes[nid].metadata["framework"] = "spring"
            self.edges.append(self._edge(module_id, nid, EdgeRelation.IMPORTS))
            declared.add(name)
            fn_ranges.append((start_line, end_line, nid))
        for lineno, line in enumerate(source.splitlines(), 1):
            for match in self._CALL_RE.finditer(line):
                callee = match.group(1)
                if callee not in declared:
                    continue
                caller_id = module_id
                for start, end, fid in fn_ranges:
                    if start <= lineno <= end:
                        caller_id = fid
                        break
                self.edges.append(self._edge(caller_id, self._make_id(path, callee), EdgeRelation.CALLS))


class JavaParser(_RegexLanguageParser):
    """Java parser with Spring-friendly regex patterns."""
    language = "java"
    _FUNC_RE = re.compile(r"(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\(")
    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".java")
    def parse(self, path: str) -> None:
        self._parse_with_regex(path)


class PHPParser(_RegexLanguageParser):
    """PHP parser."""
    language = "php"
    _FUNC_RE = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(", re.M)
    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".php")
    def parse(self, path: str) -> None:
        self._parse_with_regex(path)


class RubyParser(_RegexLanguageParser):
    """Ruby parser."""
    language = "ruby"
    _FUNC_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*[!?=]?)", re.M)
    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".rb")
    def parse(self, path: str) -> None:
        self._parse_with_regex(path)


class CSharpParser(_RegexLanguageParser):
    """C# parser for controller/action discovery."""
    language = "csharp"
    _FUNC_RE = re.compile(r"(?:public|private|protected)\s+(?:async\s+)?[\w<>\[\]]+\s+([A-Za-z_]\w*)\s*\(")
    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".cs")
    def parse(self, path: str) -> None:
        self._parse_with_regex(path)
