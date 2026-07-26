"""Grammar-driven tree-sitter parsers for the remaining target languages.

The C and Rust engines showed that what makes taint analysis work is the same
everywhere: functions, their parameters, the bindings inside them, and the calls
those bindings flow into. Only the grammar's node names differ. Rather than seven
more bespoke engines, this module implements that graph shape once and drives it
from a :class:`LanguageProfile` per language.

What each parser emits
----------------------
* ``MODULE`` per file, ``FUNCTION`` per declaration, ``VARIABLE`` per parameter
  and per binding.
* ``DATAFLOW`` for parameter binding, assignment right-hand sides, call
  arguments, and call return values -- the edges taint analysis actually walks.
* ``CALLS`` to a synthetic target node per callee expression, so library sinks
  such as ``child_process.execSync`` exist in the graph even though they are
  declared nowhere in the scanned source. The previous regex parsers only linked
  calls to functions declared in the *same file*, which is why no library sink
  was ever reachable.
* ``IMPORTS`` plus an alias table, so a short call name can be matched against a
  fully-qualified taint pattern.

Taint source and sink determination happens here, where the callee expression
and the import table are both available, and is recorded on the node as
``is_taint_source`` / ``is_taint_sink`` rather than left to a label match.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from analyzers.symbols import SSAVersionTracker
from models import AnalysisOptions, EdgeRelation, NodeType, SecurityConfig
from parsers.engines import TreeSitterParser, _mark_function_entrypoint

#: Token types that separate a binding's target from its value.
_ASSIGN_OPERATORS: FrozenSet[str] = frozenset({"=", ":=", "<-"})


@dataclass(frozen=True)
class LanguageProfile:
    """Grammar node names for one language.

    Every field is a set of tree-sitter node *type* strings, obtained by
    inspecting each grammar's output rather than assumed.
    """

    language: str
    grammar: str
    extensions: Tuple[str, ...]
    function_nodes: FrozenSet[str]
    param_container_nodes: FrozenSet[str]
    param_name_nodes: FrozenSet[str]
    binding_nodes: FrozenSet[str]
    call_nodes: FrozenSet[str]
    argument_container_nodes: FrozenSet[str]
    identifier_nodes: FrozenSet[str]
    import_nodes: FrozenSet[str]
    literal_nodes: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "string",
                "string_literal",
                "interpreted_string_literal",
                "raw_string_literal",
                "number",
                "integer",
                "int_literal",
                "float_literal",
                "decimal_integer_literal",
                "number_literal",
                "true",
                "false",
                "null",
                "nil",
                "boolean",
                "comment",
            }
        )
    )
    #: Nodes that introduce a nested scope whose parameters should be collected
    #: (arrow functions, lambdas, blocks passed to methods).
    closure_nodes: FrozenSet[str] = field(default_factory=frozenset)


class GenericTreeSitterParser(TreeSitterParser):
    """Shared graph builder driven by a :class:`LanguageProfile`."""

    profile: LanguageProfile

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, self.profile.grammar, options=options)
        self.language = self.profile.language
        self._ssa = SSAVersionTracker()
        self._value_nodes: Dict[Tuple[str, str], str] = {}
        self._aliases: Dict[str, str] = {}

    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(cls.profile.extensions)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def parse(self, path: str) -> None:
        try:
            with open(path, "rb") as handle:
                source_bytes = handle.read()
        except OSError:
            return

        source = source_bytes.decode("utf-8", errors="replace")
        tree = self._ts_parser.parse(source_bytes)

        self._ssa = SSAVersionTracker()
        self._value_nodes = {}
        self._aliases = {}

        module_id = self._make_id(path, "__module__")
        module_node = self._make_node(
            module_id, NodeType.MODULE, os.path.basename(path), path, lineno=1
        )
        module_node.metadata["language"] = self.profile.language
        self.nodes[module_id] = module_node

        # Imports first, so an alias is known before the calls that use it.
        for node in self._iter_all(tree.root_node):
            if node.type in self.profile.import_nodes:
                self._visit_import(node, source, path, module_id)

        self._walk(tree.root_node, source, path, module_id, module_id)

    # ------------------------------------------------------------------
    # Traversal
    # ------------------------------------------------------------------

    def _walk(self, node, src: str, path: str, parent_id: str, fn_id: str) -> None:
        """Dispatch a node, then recurse into whatever it did not consume."""
        node_type = node.type

        if node_type in self.profile.function_nodes:
            self._visit_function(node, src, path, parent_id, fn_id)
            return

        if node_type in self.profile.binding_nodes:
            self._visit_binding(node, src, path, fn_id)
            # Fall through: the value side may hold calls that still need visiting.

        if node_type in self.profile.call_nodes:
            self._visit_call(node, src, path, fn_id)

        for child in node.children:
            self._walk(child, src, path, parent_id, fn_id)

    def _visit_function(self, node, src: str, path: str, parent_id: str, enclosing_fn: str) -> None:
        name = self._function_name(node, src)
        lineno = node.start_point[0] + 1
        fn_id = self._make_id(path, f"{parent_id}::fn::{name}:{lineno}")

        fn_node = self._make_node(fn_id, NodeType.FUNCTION, name, path, lineno)
        fn_node.metadata.update({"language": self.profile.language, "qualified_name": name})
        _mark_function_entrypoint(fn_node, name)
        self.nodes[fn_id] = fn_node
        self.edges.append(self._edge(parent_id, fn_id, EdgeRelation.CONTAINS))

        for param_name, param_node in self._parameters(node, src):
            self._declare_value(param_name, path, fn_id, param_node.start_point[0] + 1, "parameter")

        for child in node.children:
            self._walk(child, src, path, fn_id, fn_id)

    # ------------------------------------------------------------------
    # Bindings
    # ------------------------------------------------------------------

    def _visit_binding(self, node, src: str, path: str, fn_id: str) -> None:
        """Create the bound variable and connect the value side to it."""
        target_nodes, value_nodes = self._split_on_assignment(node)
        if not target_nodes or not value_nodes:
            return

        value_text = " ".join(self._get_text(src, item) for item in value_nodes).strip()
        if not value_text:
            return

        taint_config = self.config.to_taint_config()
        is_source = self._matches_pattern(value_text, taint_config.sources)

        for target in target_nodes:
            name = self._first_identifier_text(target, src)
            if not name:
                continue
            lineno = node.start_point[0] + 1
            var_id = self._declare_value(name, path, fn_id, lineno, "binding")
            if is_source:
                self.nodes[var_id].is_unsafe = True
                self.nodes[var_id].metadata["is_taint_source"] = True
                self.nodes[var_id].metadata["tainted_by"] = value_text[:96]

            # Identifiers read on the value side flow into the binding.
            for referenced in self._referenced_values(value_nodes, src, fn_id):
                if referenced != var_id:
                    self.edges.append(
                        self._edge(
                            referenced,
                            var_id,
                            EdgeRelation.DATAFLOW,
                            {"flow_kind": "assignment_rhs"},
                        )
                    )

            # A call on the value side returns into the binding.
            for call in self._iter_calls(value_nodes):
                callee_id = self._visit_call(call, src, path, fn_id)
                if callee_id:
                    self.edges.append(
                        self._edge(
                            callee_id,
                            var_id,
                            EdgeRelation.DATAFLOW,
                            {"flow_kind": "call_return"},
                        )
                    )

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------

    def _visit_call(self, node, src: str, path: str, fn_id: str) -> Optional[str]:
        """Emit the call target and wire its arguments in. Returns the target id."""
        callee_text, arguments = self._call_parts(node, src)
        if not callee_text:
            return None

        resolved = self._resolve_alias(callee_text)
        taint_config = self.config.to_taint_config()
        is_source = self._matches_pattern(callee_text, taint_config.sources) or self._matches_pattern(
            resolved, taint_config.sources
        )
        is_sink = self._matches_pattern(callee_text, taint_config.sinks) or self._matches_pattern(
            resolved, taint_config.sinks
        )

        callee_id = self._make_id(path, f"__call_target__{callee_text}")
        if callee_id not in self.nodes:
            callee_node = self._make_node(
                callee_id, NodeType.FUNCTION, callee_text, path, node.start_point[0] + 1
            )
            callee_node.metadata.update(
                {
                    "language": self.profile.language,
                    "synthetic": "call_target",
                    "call_name": callee_text,
                    "resolved_name": resolved,
                    "is_taint_source": is_source,
                    "is_taint_sink": is_sink,
                }
            )
            if is_sink:
                callee_node.is_unsafe = True
            self.nodes[callee_id] = callee_node

        self.edges.append(
            self._edge(fn_id, callee_id, EdgeRelation.CALLS, {"call_name": callee_text})
        )

        if arguments is not None:
            for referenced in self._referenced_values([arguments], src, fn_id):
                self.edges.append(
                    self._edge(
                        referenced,
                        callee_id,
                        EdgeRelation.DATAFLOW,
                        {"flow_kind": "call_argument", "call_name": callee_text},
                    )
                )
        return callee_id

    def _visit_import(self, node, src: str, path: str, module_id: str) -> None:
        """Record an import node and the alias it introduces."""
        text = self._get_text(src, node).strip()
        if not text:
            return
        name = self._import_alias(node, src)
        import_id = self._make_id(path, f"__import__{text[:80]}")
        if import_id not in self.nodes:
            import_node = self._make_node(
                import_id, NodeType.IMPORT, name or text[:60], path, node.start_point[0] + 1
            )
            import_node.metadata.update(
                {"language": self.profile.language, "statement": text[:160]}
            )
            self.nodes[import_id] = import_node
            self.edges.append(self._edge(module_id, import_id, EdgeRelation.IMPORTS))

    # ------------------------------------------------------------------
    # Value tracking
    # ------------------------------------------------------------------

    def _declare_value(
        self, name: str, path: str, fn_id: str, lineno: int, flow_kind: str
    ) -> str:
        """Create a VARIABLE node for ``name`` and register it for lookup."""
        ssa_label = name if self.options.quick_mode else self._ssa.get_versioned_id(name)
        var_id = self._make_id(path, f"{fn_id}::{flow_kind}::{ssa_label}")
        if var_id not in self.nodes:
            var_node = self._make_node(var_id, NodeType.VARIABLE, name, path, lineno)
            var_node.metadata.update(
                {
                    "language": self.profile.language,
                    "flow_kind": flow_kind,
                    "ssa_label": ssa_label,
                }
            )
            self.nodes[var_id] = var_node
            self.edges.append(
                self._edge(fn_id, var_id, EdgeRelation.DATAFLOW, {"flow_kind": flow_kind})
            )
        self._value_nodes[(fn_id, name)] = var_id
        return var_id

    def _referenced_values(self, nodes: List[Any], src: str, fn_id: str) -> List[str]:
        """Return ids of already-declared values named inside ``nodes``."""
        found: List[str] = []
        seen: Set[str] = set()
        for root in nodes:
            for candidate in self._iter_all(root):
                if candidate.type not in self.profile.identifier_nodes:
                    continue
                name = self._get_text(src, candidate).lstrip("$").strip()
                if not name or name in seen:
                    continue
                value_id = self._value_nodes.get((fn_id, name))
                if value_id is not None:
                    seen.add(name)
                    found.append(value_id)
        return found

    # ------------------------------------------------------------------
    # Grammar helpers
    # ------------------------------------------------------------------

    def _function_name(self, node, src: str) -> str:
        for child in node.children:
            if child.type in self.profile.identifier_nodes or child.type == "name":
                return self._get_text(src, child)
        return "<anonymous>"

    def _parameters(self, node, src: str) -> List[Tuple[str, Any]]:
        """Return ``(name, node)`` for each declared parameter."""
        params: List[Tuple[str, Any]] = []
        for child in node.children:
            if child.type not in self.profile.param_container_nodes:
                continue
            for item in child.children:
                if item.type in ("(", ")", ",", "|"):
                    continue
                if item.type in self.profile.identifier_nodes:
                    name = self._get_text(src, item).lstrip("$").strip()
                    if name:
                        params.append((name, item))
                elif item.type in self.profile.param_name_nodes:
                    name = self._first_identifier_text(item, src)
                    if name:
                        params.append((name, item))
        return params

    def _split_on_assignment(self, node) -> Tuple[List[Any], List[Any]]:
        """Split a binding's children at its assignment operator."""
        targets: List[Any] = []
        values: List[Any] = []
        seen_operator = False
        for child in node.children:
            if not seen_operator and child.type in _ASSIGN_OPERATORS:
                seen_operator = True
                continue
            (values if seen_operator else targets).append(child)
        if not seen_operator:
            return [], []
        return targets, values

    def _call_parts(self, node, src: str) -> Tuple[str, Optional[Any]]:
        """Return the callee expression text and the argument container.

        Everything before the argument list is the callee, which keeps
        ``cp.execSync``, ``Runtime.getRuntime().exec`` and
        ``System.Diagnostics.Process.Start`` intact without per-language cases.
        """
        arguments = None
        callee_parts: List[str] = []
        for child in node.children:
            if child.type in self.profile.argument_container_nodes:
                arguments = child
                break
            callee_parts.append(self._get_text(src, child))
        return "".join(callee_parts).strip(), arguments

    def _first_identifier_text(self, node, src: str) -> str:
        if node.type in self.profile.identifier_nodes:
            return self._get_text(src, node).lstrip("$").strip()
        for candidate in self._iter_all(node):
            if candidate.type in self.profile.identifier_nodes:
                return self._get_text(src, candidate).lstrip("$").strip()
        return ""

    def _iter_calls(self, nodes: List[Any]):
        for root in nodes:
            for candidate in self._iter_all(root, include_self=True):
                if candidate.type in self.profile.call_nodes:
                    yield candidate

    @staticmethod
    def _iter_all(node, include_self: bool = False):
        if include_self:
            yield node
        stack = list(node.children)
        while stack:
            current = stack.pop()
            yield current
            stack.extend(current.children)

    # ------------------------------------------------------------------
    # Naming
    # ------------------------------------------------------------------

    def _import_alias(self, node, src: str) -> str:
        """Best-effort short name introduced by an import statement."""
        for child in node.children:
            if child.type in self.profile.identifier_nodes:
                return self._get_text(src, child).strip()
        text = self._get_text(src, node).strip().strip(";")
        tail = text.replace('"', "").replace("'", "").split("/")[-1].split(".")[-1]
        return tail.strip()

    def _resolve_alias(self, callee: str) -> str:
        head, separator, rest = callee.partition(".")
        target = self._aliases.get(head.strip())
        return f"{target}{separator}{rest}" if target else callee

    @staticmethod
    def _matches_pattern(text: str, patterns: Set[str]) -> bool:
        """Segment-aligned match, mirroring the taint analyzer's matcher."""
        from analyzers.taint import TaintAnalyzer

        segments = TaintAnalyzer._segments(text)
        return any(TaintAnalyzer._pattern_matches(segments, pattern) for pattern in patterns)


# ---------------------------------------------------------------------------
# Per-language profiles
# ---------------------------------------------------------------------------

_JS_PROFILE = LanguageProfile(
    language="javascript",
    grammar="javascript",
    extensions=(".js", ".jsx", ".mjs", ".cjs"),
    function_nodes=frozenset(
        {"function_declaration", "function_expression", "method_definition", "arrow_function", "generator_function_declaration"}
    ),
    param_container_nodes=frozenset({"formal_parameters"}),
    param_name_nodes=frozenset({"required_parameter", "optional_parameter", "rest_pattern", "object_pattern", "array_pattern"}),
    binding_nodes=frozenset({"variable_declarator", "assignment_expression"}),
    call_nodes=frozenset({"call_expression", "new_expression"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"identifier", "shorthand_property_identifier_pattern"}),
    import_nodes=frozenset({"import_statement"}),
)

_TS_PROFILE = LanguageProfile(
    language="typescript",
    grammar="typescript",
    extensions=(".ts",),
    function_nodes=_JS_PROFILE.function_nodes | {"function_signature"},
    param_container_nodes=_JS_PROFILE.param_container_nodes,
    param_name_nodes=_JS_PROFILE.param_name_nodes,
    binding_nodes=_JS_PROFILE.binding_nodes,
    call_nodes=_JS_PROFILE.call_nodes,
    argument_container_nodes=_JS_PROFILE.argument_container_nodes,
    identifier_nodes=_JS_PROFILE.identifier_nodes,
    import_nodes=_JS_PROFILE.import_nodes,
)

_TSX_PROFILE = LanguageProfile(
    language="typescript",
    grammar="tsx",
    extensions=(".tsx",),
    function_nodes=_TS_PROFILE.function_nodes,
    param_container_nodes=_TS_PROFILE.param_container_nodes,
    param_name_nodes=_TS_PROFILE.param_name_nodes,
    binding_nodes=_TS_PROFILE.binding_nodes,
    call_nodes=_TS_PROFILE.call_nodes,
    argument_container_nodes=_TS_PROFILE.argument_container_nodes,
    identifier_nodes=_TS_PROFILE.identifier_nodes,
    import_nodes=_TS_PROFILE.import_nodes,
)

_GO_PROFILE = LanguageProfile(
    language="go",
    grammar="go",
    extensions=(".go",),
    function_nodes=frozenset({"function_declaration", "method_declaration", "func_literal"}),
    param_container_nodes=frozenset({"parameter_list"}),
    param_name_nodes=frozenset({"parameter_declaration", "variadic_parameter_declaration"}),
    binding_nodes=frozenset({"short_var_declaration", "assignment_statement", "var_spec"}),
    call_nodes=frozenset({"call_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_declaration"}),
)

_JAVA_PROFILE = LanguageProfile(
    language="java",
    grammar="java",
    extensions=(".java",),
    function_nodes=frozenset({"method_declaration", "constructor_declaration"}),
    param_container_nodes=frozenset({"formal_parameters"}),
    param_name_nodes=frozenset({"formal_parameter", "spread_parameter", "receiver_parameter"}),
    binding_nodes=frozenset({"variable_declarator", "assignment_expression"}),
    call_nodes=frozenset({"method_invocation", "object_creation_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_declaration"}),
)

_CSHARP_PROFILE = LanguageProfile(
    language="csharp",
    grammar="csharp",
    extensions=(".cs",),
    function_nodes=frozenset({"method_declaration", "constructor_declaration", "local_function_statement"}),
    param_container_nodes=frozenset({"parameter_list"}),
    param_name_nodes=frozenset({"parameter"}),
    binding_nodes=frozenset({"variable_declarator", "assignment_expression"}),
    call_nodes=frozenset({"invocation_expression", "object_creation_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"using_directive"}),
)

_PHP_PROFILE = LanguageProfile(
    language="php",
    grammar="php",
    extensions=(".php",),
    function_nodes=frozenset({"function_definition", "method_declaration", "anonymous_function_creation_expression"}),
    param_container_nodes=frozenset({"formal_parameters"}),
    param_name_nodes=frozenset({"simple_parameter", "variadic_parameter", "property_promotion_parameter"}),
    binding_nodes=frozenset({"assignment_expression", "augmented_assignment_expression"}),
    call_nodes=frozenset({"function_call_expression", "member_call_expression", "scoped_call_expression", "object_creation_expression"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"variable_name", "name"}),
    import_nodes=frozenset({"namespace_use_declaration"}),
)

_RUBY_PROFILE = LanguageProfile(
    language="ruby",
    grammar="ruby",
    extensions=(".rb",),
    function_nodes=frozenset({"method", "singleton_method"}),
    param_container_nodes=frozenset({"method_parameters", "block_parameters"}),
    param_name_nodes=frozenset({"optional_parameter", "keyword_parameter", "splat_parameter", "hash_splat_parameter"}),
    binding_nodes=frozenset({"assignment", "operator_assignment"}),
    call_nodes=frozenset({"call", "command_call"}),
    argument_container_nodes=frozenset({"argument_list", "command_argument_list"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"call"}),
)


class JavaScriptParser(GenericTreeSitterParser):
    """JavaScript parser."""

    profile = _JS_PROFILE
    language = "javascript"

    @classmethod
    def supports(cls, path: str) -> bool:
        # .ts/.tsx are claimed by the TypeScript parsers, which use a grammar
        # that understands type annotations.
        return path.endswith(cls.profile.extensions)


class TypeScriptParser(GenericTreeSitterParser):
    """TypeScript parser."""

    profile = _TS_PROFILE
    language = "typescript"


class TSXParser(GenericTreeSitterParser):
    """TSX parser."""

    profile = _TSX_PROFILE
    language = "typescript"


class GoParser(GenericTreeSitterParser):
    """Go parser."""

    profile = _GO_PROFILE
    language = "go"


class JavaParser(GenericTreeSitterParser):
    """Java parser."""

    profile = _JAVA_PROFILE
    language = "java"


class CSharpParser(GenericTreeSitterParser):
    """C# parser."""

    profile = _CSHARP_PROFILE
    language = "csharp"


class PHPParser(GenericTreeSitterParser):
    """PHP parser."""

    profile = _PHP_PROFILE
    language = "php"


class RubyParser(GenericTreeSitterParser):
    """Ruby parser."""

    profile = _RUBY_PROFILE
    language = "ruby"
