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
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from analyzers.symbols import SSAVersionTracker
from models import (
    LANGUAGE_SCOPED_SINKS,
    LANGUAGE_SCOPED_SOURCES,
    AnalysisOptions,
    EdgeRelation,
    NodeType,
    SecurityConfig,
)
from parsers.engines import TreeSitterParser, _mark_function_entrypoint

#: Function body containers. A declaration's own name is never inside one.
_BODY_NODES: FrozenSet[str] = frozenset(
    {"block", "statement_block", "function_body", "compound_statement", "body_statement", "do_block"}
)

#: Token types that separate a binding's target from its value.
_ASSIGN_OPERATORS: FrozenSet[str] = frozenset({"=", ":=", "<-"})

#: Constructs that embed an expression inside a string literal. The literal's
#: prose is not code, but these are: `"$QUERY_STRING"`, `f"ls {path}"` and
#: `"${req.query.c}"` all read a value that taint has to follow.
_INTERPOLATION_NODES: FrozenSet[str] = frozenset(
    {
        "string_interpolation", "interpolation", "template_substitution",
        "simple_expansion", "expansion", "command_substitution",
        "string_expansion", "substitution", "interpolated_string_expression",
        "subshell", "arithmetic_expansion",
    }
)

#: Scope key standing in for "declared on the object, not in this function".
#: Fields outlive the method that writes them, so a write in one method and a
#: read in another must resolve to the same value node. Function-scoped lookup
#: put them in separate scopes and lost the flow entirely -- which is how every
#: MVC controller that stashes request data on ``this`` is written.
_FIELD_SCOPE = "__field__"

#: How each language spells "the current instance". A binding whose target is
#: prefixed with one of these names a field rather than a local.
_INSTANCE_PREFIXES: Tuple[str, ...] = ("this.", "self.", "$this->", "this->", "@")

#: Methods that store their argument into the receiver. The value is now
#: reachable through the collection, so taint has to flow *backwards* into the
#: receiver rather than only forwards into the call.
_COLLECTION_WRITERS: FrozenSet[str] = frozenset(
    {
        "push", "append", "add", "addall", "insert", "put", "putall", "set",
        "setattr", "offer", "enqueue", "unshift", "extend", "update", "write",
        "addelement", "concat", "join",
    }
)


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

    #: Shell-style languages have no named parameters; a function reads $1, $2.
    #: Those are synthesised in order so arguments still bind to something.
    positional_parameters: bool = False

    #: Call names that register an HTTP route, as `app.get(path, handler)` or
    #: `router.post(...)`. Detecting these gives a real entry point and the URL
    #: it is reachable at, instead of guessing from the handler's name.
    route_registrars: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "get", "post", "put", "delete", "patch", "head", "options",
                "all", "use", "route", "handle", "handlefunc", "handler",
                "addroute", "map", "when",
            }
        )
    )

    #: Annotations or decorators that declare a route on the function they
    #: precede: Spring's @GetMapping, Flask's @app.route, C#'s [HttpGet].
    route_annotation_nodes: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {"annotation", "marker_annotation", "attribute", "attribute_list", "decorator"}
        )
    )

    #: Conditional constructs, and the statements that abandon the current path.
    #: A test on a tainted value whose failure branch exits is a validation
    #: guard: the value only reaches later code if it passed the check.
    conditional_nodes: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {"if_statement", "if_expression", "elif_clause", "conditional_expression", "if"}
        )
    )
    exit_nodes: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "return_statement", "throw_statement", "raise_statement",
                "return_expression", "break_statement", "continue_statement",
                "return", "throw", "raise", "exit_statement", "die_statement",
            }
        )
    )


class GenericTreeSitterParser(TreeSitterParser):
    """Shared graph builder driven by a :class:`LanguageProfile`."""

    profile: LanguageProfile

    def __init__(self, config: SecurityConfig, options: Optional[AnalysisOptions] = None) -> None:
        super().__init__(config, self.profile.grammar, options=options)
        self.language = self.profile.language
        self._ssa = SSAVersionTracker()
        self._value_nodes: Dict[Tuple[str, str], str] = {}
        self._aliases: Dict[str, str] = {}
        # name -> declaring function node ids, and that function's parameter
        # value nodes in declaration order. Used to connect a call to the body
        # it actually enters.
        self._functions_by_name: Dict[str, List[str]] = {}
        self._function_params: Dict[str, List[str]] = {}
        # (short callee name, call-target node id, argument value ids) recorded
        # during the walk and resolved afterwards, since a function may be
        # declared below its first use.
        self._call_sites: List[Tuple[str, str, List[str]]] = []
        self._pending_function_name: Optional[str] = None
        #: Built once. to_taint_config() constructs fresh sets, and it was being
        #: called for every binding and every call in the file.
        self._taint_config = config.to_taint_config()
        # Routes registered by name before the handler is declared.
        self._route_handlers_by_name: Dict[str, List[Tuple[str, str, str]]] = {}
        #: (start_byte, end_byte) of an inline handler -> the route it serves.
        self._route_by_span: Dict[Tuple[int, int], Tuple[str, str, str]] = {}
        #: Names declared on the type rather than in a method, per file.
        self._field_names: Set[str] = set()

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
        self._functions_by_name = {}
        self._function_params = {}
        self._call_sites = []
        self._route_handlers_by_name = {}
        self._route_by_span = {}
        # Collected before the walk: a bare assignment cannot be recognised as a
        # field write until the class body's declarations are known, and the
        # declaration may sit below the method that writes it.
        self._field_names = self._collect_field_names(tree.root_node, source)

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
        self._resolve_call_targets()
        self._apply_deferred_routes()

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

        if node_type in self.profile.conditional_nodes:
            self._note_guard(node, src, fn_id)

        if node_type in self.profile.call_nodes:
            self._note_route_registration(node, src, path, fn_id)

        if node_type in self.profile.call_nodes:
            self._visit_call(node, src, path, fn_id)

        for child in node.children:
            self._walk(child, src, path, parent_id, fn_id)

    def _visit_function(self, node, src: str, path: str, parent_id: str, enclosing_fn: str) -> None:
        name = self._function_name(node, src)
        lineno = node.start_point[0] + 1
        declared_route = self._route_by_span.get((node.start_byte, node.end_byte))
        fn_id = self._make_id(path, f"{parent_id}::fn::{name}:{lineno}")

        fn_node = self._make_node(fn_id, NodeType.FUNCTION, name, path, lineno)
        fn_node.metadata.update({"language": self.profile.language, "qualified_name": name})
        _mark_function_entrypoint(fn_node, name)
        if declared_route:
            route_label, route_method, route_target = declared_route
            fn_node.metadata.update(
                {
                    "entrypoint": True,
                    "route": route_label,
                    "http_method": route_method,
                    "route_path": route_target,
                }
            )
        self._note_route_annotation(node, src, fn_node)
        self.nodes[fn_id] = fn_node
        self.edges.append(self._edge(parent_id, fn_id, EdgeRelation.CONTAINS))

        param_ids: List[str] = []
        if self.profile.positional_parameters:
            for position in sorted(self._positional_parameters(node, src)):
                param_ids.append(
                    # Stored without the sigil: value lookups strip "$" before
                    # matching, so "$1" would never resolve.
                    self._declare_value(str(position), path, fn_id, lineno, "parameter")
                )
        for param_name, param_node in self._parameters(node, src):
            param_ids.append(
                self._declare_value(param_name, path, fn_id, param_node.start_point[0] + 1, "parameter")
            )
        self._function_params[fn_id] = param_ids
        self._functions_by_name.setdefault(name, []).append(fn_id)
        # Exposed on the node so cross-file resolution can bind arguments to
        # parameters after the per-file graphs are merged.
        fn_node.metadata["param_ids"] = param_ids
        fn_node.metadata["declares"] = name

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

        taint_config = self._taint_config
        is_source = self._matches_pattern(
            " ".join(self._text_outside_literals(item, src) for item in value_nodes),
            taint_config.sources,
            LANGUAGE_SCOPED_SOURCES,
        )

        bound_functions = [
            item
            for value in value_nodes
            for item in self._iter_all(value, include_self=True)
            if item.type in self.profile.function_nodes
        ]

        for target in target_nodes:
            name, target_scope = self._binding_target(target, src)
            if not name:
                # `this.handleUpdate = (req) => {...}` is the ordinary Node/Express
                # idiom. The target is a member expression with no plain
                # identifier, so bailing here left the handler body unvisited.
                member_text = self._get_text(src, target).strip()
                fallback = member_text.split(".")[-1].strip() if member_text else ""
                for bound in bound_functions:
                    self._pending_function_name = fallback or "<anonymous>"
                    self._visit_function(bound, src, path, fn_id, fn_id)
                    self._pending_function_name = None
                continue
            # `handler <- function(c) {...}` declares handler; the function node
            # itself carries no name, so take it from the binding target.
            for bound in bound_functions:
                self._pending_function_name = name
                self._visit_function(bound, src, path, fn_id, fn_id)
                self._pending_function_name = None
            lineno = node.start_point[0] + 1
            var_id = self._declare_value(name, path, fn_id, lineno, "binding", target_scope)
            if is_source:
                self.nodes[var_id].is_unsafe = True
                self.nodes[var_id].metadata["is_taint_source"] = True
                self.nodes[var_id].metadata["tainted_by"] = value_text[:96]

            # Identifiers that are only arguments to a call in the value do not
            # flow directly into the binding -- their contribution passes through
            # that call. A direct edge would route taint around any sanitizer.
            call_argument_values: Set[str] = set()
            for call in self._iter_calls(value_nodes):
                _, call_arguments = self._call_parts(call, src)
                if call_arguments is not None:
                    call_argument_values.update(
                        self._referenced_values([call_arguments], src, fn_id)
                    )

            for referenced in self._referenced_values(value_nodes, src, fn_id):
                if referenced in call_argument_values:
                    continue
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
        taint_config = self._taint_config
        is_source = self._matches_pattern(
            callee_text, taint_config.sources, LANGUAGE_SCOPED_SOURCES
        ) or self._matches_pattern(resolved, taint_config.sources, LANGUAGE_SCOPED_SOURCES)
        is_sink = self._matches_pattern(
            callee_text, taint_config.sinks, LANGUAGE_SCOPED_SINKS
        ) or self._matches_pattern(resolved, taint_config.sinks, LANGUAGE_SCOPED_SINKS)

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
                    "callee_short": callee_text.split(".")[-1].strip(),
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

        argument_ids: List[str] = []
        if arguments is not None:
            argument_ids = self._referenced_values([arguments], src, fn_id)
            # An argument written inline -- `eval(req.body.x)` -- names no local,
            # so it resolves to nothing. When its text matches a source pattern
            # it is still attacker-controlled data arriving at this call, so give
            # it a node rather than losing the flow.
            inline = self._inline_source_argument(arguments, src, path, fn_id, taint_config)
            if inline is not None and inline not in argument_ids:
                argument_ids.append(inline)
            for position, referenced in enumerate(argument_ids):
                self.edges.append(
                    self._edge(
                        referenced,
                        callee_id,
                        EdgeRelation.DATAFLOW,
                        {
                            "flow_kind": "call_argument",
                            "call_name": callee_text,
                            "arg_index": position,
                        },
                    )
                )
            self._note_collection_write(callee_text, argument_ids, src, fn_id)
        self._call_sites.append((callee_text.split(".")[-1].strip(), callee_id, argument_ids))
        return callee_id

    def _note_collection_write(
        self, callee_text: str, argument_ids: List[str], src: str, fn_id: str
    ) -> None:
        """Flow taint back into a receiver that was just written into.

        ``args.add(param)`` and ``map.put(key, param)`` move data *into* the
        receiver, so a later read of ``args`` is a read of ``param``. Modelling
        calls as forward-only lost that: the taint went into the call node and
        stopped, while the collection stayed clean. Collections built from
        request data and then passed to a sink are common enough in Java and
        JavaScript that the flow simply disappeared.

        The whole container is tainted rather than the written key, which
        over-approximates: ``map.put("a", tainted)`` also taints
        ``map.get("b")``. Distinguishing them needs constant propagation over
        the key, and reporting the flow is the safer direction to be wrong in.
        """
        if "." not in callee_text and "->" not in callee_text:
            return
        separator = "->" if "->" in callee_text else "."
        receiver, _, method = callee_text.rpartition(separator)
        receiver = receiver.strip().split(separator)[-1].strip()
        if not receiver or method.strip().lower() not in _COLLECTION_WRITERS:
            return
        receiver_id = self._lookup_value(receiver, fn_id)
        if receiver_id is None:
            return
        for argument_id in argument_ids:
            if argument_id == receiver_id:
                continue
            self.edges.append(
                self._edge(
                    argument_id,
                    receiver_id,
                    EdgeRelation.DATAFLOW,
                    {"flow_kind": "collection_write", "call_name": callee_text},
                )
            )

    def _apply_deferred_routes(self) -> None:
        """Attach routes registered before their handler was declared."""
        for name, registrations in self._route_handlers_by_name.items():
            for fn_id in self._functions_by_name.get(name, []):
                label, method, route_path = registrations[0]
                metadata = self.nodes[fn_id].metadata
                metadata["entrypoint"] = True
                metadata["route"] = label
                metadata["http_method"] = method
                metadata["route_path"] = route_path

    def _resolve_call_targets(self) -> None:
        """Connect each call to the function body it enters.

        A call produces a synthetic target node; the callee's own declaration is
        a different node with its own parameters. Without an edge between them
        taint stops at the stub, so a sink one call deep -- the ordinary way code
        is written -- was unreachable.

        Deliberately conservative: a name is resolved only when exactly one
        function declares it, so overloads and same-named methods on different
        types are left alone rather than merged into one another. Arguments bind
        to parameters positionally, which is what carries taint into the body.
        """
        for short_name, callee_id, argument_ids in self._call_sites:
            candidates = self._functions_by_name.get(short_name) or []
            if len(candidates) != 1:
                continue
            target_fn = candidates[0]
            if target_fn == callee_id:
                continue

            self.edges.append(
                self._edge(
                    callee_id,
                    target_fn,
                    EdgeRelation.CALLS,
                    {"resolved": True, "call_name": short_name},
                )
            )

            params = self._function_params.get(target_fn) or []
            for position, argument_id in enumerate(argument_ids):
                if position >= len(params):
                    break
                self.edges.append(
                    self._edge(
                        argument_id,
                        params[position],
                        EdgeRelation.DATAFLOW,
                        {
                            "flow_kind": "argument_binding",
                            "call_name": short_name,
                            "position": position,
                        },
                    )
                )

    def _inline_source_argument(
        self, arguments, src: str, path: str, fn_id: str, taint_config
    ) -> Optional[str]:
        """Give an inline attacker-controlled argument expression a node.

        Real handlers frequently pass request data straight into a sink without
        binding it first. The expression names no declared value, so argument
        resolution finds nothing and the flow disappears. Matching the argument
        text against the source vocabulary recovers it as data, rather than
        relying on call-graph reachability to imply it.
        """
        text = self._get_text(src, arguments).strip()
        if not text or not self._matches_pattern(
            self._text_outside_literals(arguments, src),
            taint_config.sources,
            LANGUAGE_SCOPED_SOURCES,
        ):
            return None
        expression = text.strip("()").strip()
        if not expression:
            return None
        value_id = self._make_id(path, f"{fn_id}::inline::{expression[:80]}")
        if value_id not in self.nodes:
            node = self._make_node(
                value_id,
                NodeType.DATA,
                expression[:80],
                path,
                arguments.start_point[0] + 1,
            )
            node.metadata.update(
                {
                    "language": self.profile.language,
                    "expression": expression[:120],
                    "synthetic": "inline_argument",
                    "is_taint_source": True,
                }
            )
            node.is_unsafe = True
            self.nodes[value_id] = node
            # Declaration edge so the value is attributed to its enclosing
            # function, which is what carries the route.
            self.edges.append(
                self._edge(fn_id, value_id, EdgeRelation.DATAFLOW, {"flow_kind": "binding"})
            )
        return value_id

    #: Tests that constrain a value to a known-good set. Passing one of these
    #: bounds what the value can be, so it defends every sink category. A length
    #: or null check does not, and is recorded without that claim.
    _CONSTRAINING_TESTS = (
        " in ", "includes", "indexof", "has(", "contains", "==", "===",
        "fullmatch", "match(", "test(", "startswith", "endswith",
        "allowlist", "whitelist", "isvalid", "validate",
        ".equals", "in_array", "array_search", "array_key_exists",
        "containskey", "hasprefix", "hassuffix", "elem",
    )

    def _note_guard(self, node, src: str, fn_id: str) -> None:
        """Mark values validated by a conditional whose failure branch exits.

        `if (!ALLOWED.includes(c)) return;` means everything after it sees a `c`
        that passed the check. Without modelling this, validated input is
        reported exactly like unvalidated input, which is the largest remaining
        noise source on code that does the right thing.
        """
        children = [c for c in node.children if c.is_named]
        if not children:
            return
        test = children[0]
        body = children[1:]
        if not any(
            candidate.type in self.profile.exit_nodes
            for branch in body
            for candidate in self._iter_all(branch, include_self=True)
        ):
            return

        test_text = self._get_text(src, test).lower()
        constraining = any(token in test_text for token in self._CONSTRAINING_TESTS)
        for value_id in self._referenced_values([test], src, fn_id):
            metadata = self.nodes[value_id].metadata
            metadata["guarded"] = True
            metadata["guard_test"] = self._get_text(src, test)[:120]
            if constraining:
                # Recorded the way an explicit sanitizer is, so the analyzer
                # treats a passed allowlist check as defending the value.
                metadata["sanitizer_for"] = ["*"]

    _HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "all", "use"})

    #: Annotation names that declare an HTTP route on the method they precede.
    _ROUTE_ANNOTATIONS = (
        "getmapping", "postmapping", "putmapping", "deletemapping",
        "patchmapping", "requestmapping", "httpget", "httppost", "httpput",
        "httpdelete", "httppatch", "route", "path",
    )

    def _note_route_annotation(self, node, src: str, fn_node) -> None:
        """Record a route declared by an annotation rather than a call.

        Spring and ASP.NET attach the route to the method itself, so there is no
        registration call to observe. The annotation names both the method and
        the path.
        """
        # Java nests annotations inside a `modifiers` node and C# inside
        # `attribute_list`, so a direct-children scan finds nothing.
        candidates: List[Any] = []
        for child in node.children:
            if child.type in self.profile.route_annotation_nodes:
                candidates.append(child)
            elif child.type in ("modifiers", "attribute_list", "decorators"):
                candidates.extend(
                    item
                    for item in self._iter_all(child, include_self=True)
                    if item.type in self.profile.route_annotation_nodes
                )

        for child in candidates:
            text = self._get_text(src, child).strip()
            lowered = text.lower().lstrip("@[")
            matched = next((name for name in self._ROUTE_ANNOTATIONS if lowered.startswith(name)), None)
            if not matched:
                continue
            route_path = ""
            for quote in ('"', "'"):
                if quote in text:
                    parts = text.split(quote)
                    if len(parts) > 1:
                        route_path = parts[1]
                        break
            method = matched.replace("mapping", "").replace("http", "") or "any"
            label = f"{method.upper()} {route_path}".strip()
            fn_node.metadata["entrypoint"] = True
            fn_node.metadata["route"] = label
            fn_node.metadata["http_method"] = method
            fn_node.metadata["route_path"] = route_path
            return

    def _note_route_registration(self, node, src: str, path: str, fn_id: str) -> None:
        """Record an HTTP route and the handler it dispatches to.

        `app.get("/run", handler)` states two things a name heuristic cannot: that
        the handler is genuinely reachable from outside, and the URL to reach it
        at. Both matter more than the fact of the flow when triaging.
        """
        callee_text, arguments = self._call_parts(node, src)
        if arguments is None or not callee_text:
            return
        segments = [part for part in callee_text.replace("::", ".").split(".") if part]
        if not segments or segments[-1].lower() not in self.profile.route_registrars:
            return

        method = segments[-1].lower()
        route_path = ""
        handlers: List[Any] = []
        for child in arguments.children:
            if not child.is_named:
                continue
            text = self._get_text(src, child).strip()
            if not route_path and text[:1] in {'"', "'", "`"}:
                route_path = text.strip("\"'`")
                continue
            handlers.append(child)
        if not route_path or not route_path.startswith(("/", "*")):
            return

        label = f"{method.upper() if method in self._HTTP_METHODS else 'ANY'} {route_path}"
        for handler in handlers:
            self._attach_route(handler, src, path, fn_id, label, method, route_path)

    def _attach_route(
        self, handler, src: str, path: str, fn_id: str, label: str, method: str, route_path: str
    ) -> None:
        """Mark the handler for a route, whether inline or referenced by name."""
        targets: List[str] = []
        for candidate in self._iter_all(handler, include_self=True):
            if candidate.type in self.profile.function_nodes:
                # Inline handler: `app.get("/x", (req, res) => {...})`. Recorded
                # against its span rather than visited here -- the walk reaches it
                # moments later, and visiting it twice created a second, unrouted
                # copy that the taint path then flowed through.
                self._route_by_span[(candidate.start_byte, candidate.end_byte)] = (
                    label,
                    method,
                    route_path,
                )
                return
        else:
            # `sessionHandler.handleLoginRequest` names the handler in its last
            # segment; the first identifier is the object holding it.
            handler_text = self._get_text(src, handler).strip()
            name = handler_text.split(".")[-1].strip() if "." in handler_text else ""
            if not name:
                name = self._first_identifier_text(handler, src)
            if name:
                targets.extend(self._functions_by_name.get(name, []))
                self._route_handlers_by_name.setdefault(name, []).append(
                    (label, method, route_path)
                )
                # Also recorded on a marker node so a handler declared in another
                # file can pick the route up after the graphs are merged.
                marker_id = self._make_id(path, f"__route__{label}::{name}")
                if marker_id not in self.nodes:
                    marker = self._make_node(
                        marker_id, NodeType.DATA, label, path, handler.start_point[0] + 1
                    )
                    marker.metadata.update(
                        {
                            "language": self.profile.language,
                            "synthetic": "route_registration",
                            "route": label,
                            "http_method": method,
                            "route_path": route_path,
                            "route_for": name,
                        }
                    )
                    self.nodes[marker_id] = marker

        for target in targets:
            metadata = self.nodes[target].metadata
            metadata["entrypoint"] = True
            metadata["route"] = label
            metadata["http_method"] = method
            metadata["route_path"] = route_path

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
        self, name: str, path: str, fn_id: str, lineno: int, flow_kind: str, scope: str = ""
    ) -> str:
        """Create a VARIABLE node for ``name`` and register it for lookup.

        ``scope`` of ``_FIELD_SCOPE`` registers the value against the object
        instead of the current function, so a method that reads the field later
        resolves to this same node.
        """
        ssa_label = name if self.options.quick_mode else self._ssa.get_versioned_id(name)
        # Field identity must not include the writing function, or two methods
        # touching one field would still produce two unconnected nodes.
        owner = _FIELD_SCOPE if scope == _FIELD_SCOPE else fn_id
        var_id = self._make_id(path, f"{owner}::{flow_kind}::{ssa_label}")
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
        if scope == _FIELD_SCOPE:
            self.nodes[var_id].metadata["scope"] = "field"
        self._value_nodes[(owner, name)] = var_id
        return var_id

    def _referenced_values(self, nodes: List[Any], src: str, fn_id: str) -> List[str]:
        """Return ids of already-declared values named inside ``nodes``."""
        found: List[str] = []
        seen: Set[str] = set()
        for root in nodes:
            for candidate in self._iter_all(root):
                if candidate.type in self.profile.identifier_nodes:
                    name = self._get_text(src, candidate).lstrip("$").strip()
                elif self._is_instance_access(candidate, src):
                    # `this.cmd` -- most grammars tag the member as
                    # `property_identifier` rather than `identifier`, so a read
                    # of a field resolved to nothing while the write resolved
                    # fine. Adding the member type wholesale would make every
                    # `.foo` a value reference; only instance access needs it.
                    name = self._instance_member_name(candidate, src)
                else:
                    continue
                if not name or name in seen:
                    continue
                value_id = self._lookup_value(name, fn_id)
                if value_id is not None:
                    seen.add(name)
                    found.append(value_id)
        return found

    def _is_instance_access(self, node, src: str) -> bool:
        """Whether ``node`` reads a member of the current instance."""
        if node.child_count < 2:
            return False
        head = self._get_text(src, node.children[0]).strip().lower()
        return head in {"this", "self", "$this", "@"}

    def _instance_member_name(self, node, src: str) -> str:
        """The field name in ``this.cmd`` / ``self.cmd`` / ``$this->cmd``."""
        text = self._get_text(src, node).strip()
        for prefix in _INSTANCE_PREFIXES:
            if text.lower().startswith(prefix):
                member = text[len(prefix):].strip()
                return re.split(r"[^0-9A-Za-z_]", member, maxsplit=1)[0]
        return ""

    # ------------------------------------------------------------------
    # Grammar helpers
    # ------------------------------------------------------------------

    def _function_name(self, node, src: str) -> str:
        pending = getattr(self, "_pending_function_name", None)
        if pending:
            return pending

        # Breadth-first so the declaration's own name wins over anything nested.
        # C-family grammars put it inside a declarator rather than on the
        # function node, and leaving those unnamed collapsed every function in a
        # file onto one "<anonymous>" entry, which blocked call resolution.
        queue = list(node.children)
        while queue:
            current = queue.pop(0)
            if current.type in self.profile.identifier_nodes or current.type == "name":
                return self._get_text(src, current)
            # Parameter names and nested declarations are not this function's name.
            if (
                current.type in self.profile.param_container_nodes
                or current.type in self.profile.function_nodes
                or current.type in self.profile.argument_container_nodes
                or current.type in _BODY_NODES
            ):
                # Never descend into the body: an anonymous handler would
                # otherwise take the name of the first identifier it happens to
                # use, colliding with that variable and hiding the real handler.
                continue
            queue.extend(current.children)
        return "<anonymous>"

    def _parameters(self, node, src: str) -> List[Tuple[str, Any]]:
        """Return ``(name, node)`` for each declared parameter."""
        params: List[Tuple[str, Any]] = []
        containers = [c for c in node.children if c.type in self.profile.param_container_nodes]
        if not containers:
            # C-family grammars nest the parameter list inside a declarator, and
            # Julia inside a signature, so a direct-children scan finds nothing.
            # Descend, but never through another function -- those parameters
            # belong to the nested declaration.
            queue = list(node.children)
            while queue:
                current = queue.pop(0)
                if current.type in self.profile.function_nodes:
                    continue
                if current.type in self.profile.param_container_nodes:
                    containers.append(current)
                    continue
                queue.extend(current.children)
        for child in containers:
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

    def _positional_parameters(self, node, src: str) -> Set[int]:
        """Return the positional parameter numbers a shell function reads."""
        found: Set[int] = set()
        for descendant in self._iter_all(node):
            text = self._get_text(src, descendant).strip().lstrip("$")
            if text.isdigit() and 1 <= int(text) <= 9:
                found.add(int(text))
        return found

    def _split_on_assignment(self, node) -> Tuple[List[Any], List[Any]]:
        """Split a binding's children at its assignment operator."""
        targets: List[Any] = []
        values: List[Any] = []
        seen_operator = False
        for child in node.children:
            # The operator may be an anonymous token ("=") or a named node whose
            # text is the operator (PowerShell's assignement_operator, R's <-).
            is_operator = child.type in _ASSIGN_OPERATORS or (
                child.child_count == 0 and child.text.decode("utf-8", "replace").strip() in _ASSIGN_OPERATORS
            )
            if not seen_operator and is_operator:
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

        if arguments is None and node.children:
            # Shell-style invocation (`eval "$x"`, `Invoke-Expression $x`): the
            # grammar has no argument container, so the first child names the
            # command and everything after it is an argument.
            return self._get_text(src, node.children[0]).strip(), node

        return "".join(callee_parts).strip(), arguments

    def _first_identifier_text(self, node, src: str) -> str:
        if node.type in self.profile.identifier_nodes:
            return self._get_text(src, node).lstrip("$").strip()
        for candidate in self._iter_all(node):
            if candidate.type in self.profile.identifier_nodes:
                return self._get_text(src, candidate).lstrip("$").strip()
        return ""

    # ------------------------------------------------------------------
    # Scoping: locals, fields, and subscripts
    # ------------------------------------------------------------------

    def _collect_field_names(self, root, src: str) -> Set[str]:
        """Names declared on the type rather than inside a method.

        Walks the tree without descending into function bodies, so what remains
        is the class body: Java's ``private String c;``, C#'s auto-properties,
        Kotlin's ``val`` properties. A later bare-name assignment to one of
        these is a field write even though nothing in the statement says so.
        """
        names: Set[str] = set()
        stack = [root]
        while stack:
            current = stack.pop()
            if current.type in self.profile.function_nodes:
                continue
            if current.type in self.profile.binding_nodes:
                name = self._first_identifier_text(current, src)
                if name:
                    names.add(name)
            stack.extend(current.children)
        return names

    def _binding_target(self, target, src: str) -> Tuple[str, str]:
        """Return ``(name, scope)`` for an assignment target.

        Three shapes, all of which used to collapse to "first identifier in the
        subtree", which is right only for the first one:

        * ``bar = ...`` -- a local, unless the name is a declared field.
        * ``this.cmd = ...`` -- a field. The first identifier is ``this``, so
          the trailing member is the name that matters.
        * ``opts['k'] = ...`` / ``opts.k = ...`` -- a write *into* a value. The
          container is tainted as a whole; tracking the key would need constant
          propagation, and over-approximating here is the safe direction.
        """
        text = self._get_text(src, target).strip()
        lowered = text.lower()
        for prefix in _INSTANCE_PREFIXES:
            if lowered.startswith(prefix):
                member = text[len(prefix):].strip()
                # `this.opts['k']` is still a write to the field `opts`.
                name = re.split(r"[^0-9A-Za-z_]", member, maxsplit=1)[0]
                return (name, _FIELD_SCOPE) if name else ("", "")

        name = self._first_identifier_text(target, src)
        if not name:
            return "", ""
        scope = _FIELD_SCOPE if name in self._field_names else ""
        return name, scope

    def _lookup_value(self, name: str, fn_id: str) -> Optional[str]:
        """Resolve a name to its value node, preferring the local over the field."""
        local = self._value_nodes.get((fn_id, name))
        if local is not None:
            return local
        return self._value_nodes.get((_FIELD_SCOPE, name))

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

    def _text_outside_literals(self, node, src: str) -> str:
        """Node text with the *contents* of string and numeric literals removed.

        Taint patterns are identifier names, so matching them against the inside
        of a string makes every servlet's
        ``getWriter().println("Error processing request.")`` a taint source --
        the literal contains the segment ``request``. Scoring against OWASP
        Benchmark showed that one collision accounted for the largest share of
        false positives, because the string appears in nearly every catch block.

        Leaves are joined by spaces. Segment matching splits on non-identifier
        characters anyway, so ``os.system`` and ``os . system`` are the same
        sequence, and the literal simply contributes nothing.
        """
        literals = self.profile.literal_nodes
        parts: List[str] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in literals:
                # A literal's *contents* are text, but an interpolation inside
                # one is live code: `cmd="$QUERY_STRING"` and `f"ls {path}"`
                # both read a variable. Dropping the whole literal discarded
                # those reads and lost the flow, so descend for them alone.
                stack.extend(
                    child
                    for child in self._iter_all(current, include_self=False)
                    if child.type in _INTERPOLATION_NODES
                )
                continue
            if current.child_count == 0:
                parts.append(self._get_text(src, current))
                continue
            stack.extend(reversed(current.children))
        return " ".join(part for part in parts if part).strip()

    def _matches_pattern(
        self,
        text: str,
        patterns: Set[str],
        scope: Optional[Dict[str, FrozenSet[str]]] = None,
    ) -> bool:
        """Segment-aligned match, mirroring the taint analyzer's matcher.

        ``scope`` suppresses patterns that do not mean anything dangerous in
        this parser's language. The analyzer applies the same restriction, but
        a match here is recorded as ``is_taint_sink`` metadata that the analyzer
        then honours without re-checking, so the two must agree.
        """
        from analyzers.taint import TaintAnalyzer, language_scope

        segments = TaintAnalyzer._segments(text)
        for pattern in patterns:
            if not TaintAnalyzer._pattern_matches(segments, pattern):
                continue
            if scope is not None:
                allowed = language_scope(scope).get(TaintAnalyzer._segments(pattern))
                if allowed is not None and self.profile.language not in allowed:
                    continue
            return True
        return False


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
    # `include`/`require` are their own expression types, not function calls, so
    # PHP's most direct code-execution sink was never visited at all. The
    # keyword sits where a callee would, which is all `_call_parts` needs.
    call_nodes=frozenset({
        "function_call_expression", "member_call_expression", "scoped_call_expression",
        "object_creation_expression", "include_expression", "include_once_expression",
        "require_expression", "require_once_expression",
    }),
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

# ---------------------------------------------------------------------------
# Additional languages
#
# Every profile below was written by inspecting that grammar's own output for a
# canonical "source -> helper -> sink" snippet, not by analogy. Languages whose
# grammar does not expose the constructs this model needs are listed in
# UNSUPPORTED_LANGUAGES with the reason, rather than shipped as a stub that
# silently finds nothing.
# ---------------------------------------------------------------------------

_CPP_PROFILE = LanguageProfile(
    language="cpp",
    grammar="cpp",
    extensions=(".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"),
    function_nodes=frozenset({"function_definition", "lambda_expression"}),
    param_container_nodes=frozenset({"parameter_list"}),
    param_name_nodes=frozenset({"parameter_declaration", "optional_parameter_declaration"}),
    binding_nodes=frozenset({"init_declarator", "assignment_expression"}),
    call_nodes=frozenset({"call_expression", "new_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier", "field_identifier"}),
    import_nodes=frozenset({"preproc_include", "using_declaration"}),
)

_OBJC_PROFILE = LanguageProfile(
    language="objc",
    grammar="objc",
    extensions=(".m", ".mm"),
    function_nodes=frozenset({"function_definition", "method_definition"}),
    param_container_nodes=frozenset({"parameter_list"}),
    param_name_nodes=frozenset({"parameter_declaration"}),
    binding_nodes=frozenset({"init_declarator", "assignment_expression"}),
    call_nodes=frozenset({"call_expression", "message_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier", "field_identifier"}),
    import_nodes=frozenset({"preproc_include", "import_declaration"}),
)

_KOTLIN_PROFILE = LanguageProfile(
    language="kotlin",
    grammar="kotlin",
    extensions=(".kt", ".kts"),
    function_nodes=frozenset({"function_declaration", "anonymous_function", "lambda_literal"}),
    param_container_nodes=frozenset({"function_value_parameters", "lambda_parameters"}),
    param_name_nodes=frozenset({"parameter", "variable_declaration"}),
    binding_nodes=frozenset({"property_declaration", "assignment"}),
    call_nodes=frozenset({"call_expression"}),
    argument_container_nodes=frozenset({"value_arguments", "call_suffix"}),
    identifier_nodes=frozenset({"simple_identifier"}),
    import_nodes=frozenset({"import_header"}),
)

_SWIFT_PROFILE = LanguageProfile(
    language="swift",
    grammar="swift",
    extensions=(".swift",),
    function_nodes=frozenset({"function_declaration", "lambda_literal", "init_declaration"}),
    param_container_nodes=frozenset({"parameter", "lambda_function_type_parameters"}),
    param_name_nodes=frozenset({"parameter", "simple_identifier"}),
    binding_nodes=frozenset({"property_declaration", "assignment"}),
    call_nodes=frozenset({"call_expression"}),
    argument_container_nodes=frozenset({"value_arguments", "call_suffix"}),
    identifier_nodes=frozenset({"simple_identifier"}),
    import_nodes=frozenset({"import_declaration"}),
)

_SCALA_PROFILE = LanguageProfile(
    language="scala",
    grammar="scala",
    extensions=(".scala", ".sc"),
    function_nodes=frozenset({"function_definition", "function_declaration"}),
    param_container_nodes=frozenset({"parameters"}),
    param_name_nodes=frozenset({"parameter"}),
    binding_nodes=frozenset({"val_definition", "var_definition", "assignment_expression"}),
    call_nodes=frozenset({"call_expression"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_declaration"}),
)

_DART_PROFILE = LanguageProfile(
    language="dart",
    grammar="dart",
    extensions=(".dart",),
    function_nodes=frozenset({"function_signature", "method_signature", "function_expression"}),
    param_container_nodes=frozenset({"formal_parameter_list"}),
    param_name_nodes=frozenset({"formal_parameter"}),
    binding_nodes=frozenset({"initialized_variable_definition", "assignment_expression"}),
    call_nodes=frozenset({"argument_part", "new_expression"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_or_export"}),
)

_LUA_PROFILE = LanguageProfile(
    language="lua",
    grammar="lua",
    extensions=(".lua",),
    function_nodes=frozenset({"function_declaration", "function_definition"}),
    param_container_nodes=frozenset({"parameters"}),
    param_name_nodes=frozenset({"identifier"}),
    binding_nodes=frozenset({"variable_declaration", "assignment_statement"}),
    call_nodes=frozenset({"function_call"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"function_call"}),
)

_R_PROFILE = LanguageProfile(
    language="r",
    grammar="r",
    extensions=(".r", ".R"),
    function_nodes=frozenset({"function_definition"}),
    param_container_nodes=frozenset({"parameters"}),
    param_name_nodes=frozenset({"parameter"}),
    # R assigns with `<-`; binary_operator also covers arithmetic, but the
    # assignment split returns nothing unless an assignment operator is present.
    binding_nodes=frozenset({"binary_operator"}),
    call_nodes=frozenset({"call"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"call"}),
)

_SOLIDITY_PROFILE = LanguageProfile(
    language="solidity",
    grammar="solidity",
    extensions=(".sol",),
    function_nodes=frozenset({"function_definition", "modifier_definition", "constructor_definition"}),
    param_container_nodes=frozenset({"parameter_list", "parameter"}),
    param_name_nodes=frozenset({"parameter"}),
    binding_nodes=frozenset({"variable_declaration_statement", "assignment_expression"}),
    call_nodes=frozenset({"call_expression"}),
    argument_container_nodes=frozenset({"call_argument"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_directive"}),
)

_JULIA_PROFILE = LanguageProfile(
    language="julia",
    grammar="julia",
    extensions=(".jl",),
    function_nodes=frozenset({"function_definition", "short_function_definition"}),
    param_container_nodes=frozenset({"parameter_list"}),
    param_name_nodes=frozenset({"identifier", "typed_parameter", "optional_parameter"}),
    binding_nodes=frozenset({"assignment"}),
    call_nodes=frozenset({"call_expression", "macrocall_expression"}),
    argument_container_nodes=frozenset({"argument_list"}),
    identifier_nodes=frozenset({"identifier"}),
    import_nodes=frozenset({"import_statement", "using_statement"}),
)

_PERL_PROFILE = LanguageProfile(
    language="perl",
    grammar="perl",
    extensions=(".pl", ".pm", ".t"),
    function_nodes=frozenset({"subroutine_declaration_statement", "anonymous_subroutine_expression"}),
    param_container_nodes=frozenset({"signature"}),
    param_name_nodes=frozenset({"mandatory_parameter", "optional_parameter"}),
    binding_nodes=frozenset({"assignment_expression", "variable_declaration"}),
    call_nodes=frozenset({"function_call_expression", "method_call_expression"}),
    argument_container_nodes=frozenset({"arguments"}),
    identifier_nodes=frozenset({"varname", "identifier", "scalar_variable"}),
    import_nodes=frozenset({"use_statement"}),
)

_BASH_PROFILE = LanguageProfile(
    language="bash",
    grammar="bash",
    extensions=(".sh", ".bash", ".zsh"),
    function_nodes=frozenset({"function_definition"}),
    # Shell functions take positional $1..$n rather than named parameters, so
    # there is nothing to bind; commands and assignments still carry taint.
    param_container_nodes=frozenset(),
    param_name_nodes=frozenset(),
    binding_nodes=frozenset({"variable_assignment"}),
    call_nodes=frozenset({"command"}),
    argument_container_nodes=frozenset(),
    identifier_nodes=frozenset({"variable_name", "word"}),
    import_nodes=frozenset({"command"}),
    positional_parameters=True,
)

_POWERSHELL_PROFILE = LanguageProfile(
    language="powershell",
    grammar="powershell",
    extensions=(".ps1", ".psm1"),
    function_nodes=frozenset({"function_statement"}),
    param_container_nodes=frozenset({"function_parameter_declaration", "parameter_list"}),
    param_name_nodes=frozenset({"script_parameter", "variable"}),
    binding_nodes=frozenset({"assignment_expression"}),
    call_nodes=frozenset({"command"}),
    argument_container_nodes=frozenset(),
    identifier_nodes=frozenset({"variable", "simple_name"}),
    import_nodes=frozenset({"command"}),
)


#: Grammars evaluated and deliberately not shipped, with the reason. Recorded so
#: the exclusion is a documented decision rather than an oversight.
UNSUPPORTED_LANGUAGES: Dict[str, str] = {
    "dart": "function_signature and function_body are siblings, so the body is not reachable from the declaration this model walks",
    "solidity": "parameters are bare children of function_definition and bindings use a statement wrapper; profile did not resolve calls in testing",
    "julia": "parameters live inside a 'signature' node that wraps a call_expression, so parameter binding does not resolve",
    "perl": "subroutines take arguments via @_ unpacking rather than a declared signature; there is no parameter list to bind to",
    "powershell": "assignment operator node did not split target from value in testing; binding produced no dataflow",
    "groovy": "grammar exposes only 'func' and 'identifier'; no parameter, binding or call nodes to drive dataflow",
    "elixir": "homoiconic grammar reports every construct as 'call'; needs macro-aware handling rather than a node-name profile",
    "zig": "grammar uses generic Decl/Statement/AssignExpr wrappers with no distinct call node",
    "haskell": "no assignment or call nodes in the imperative sense this model requires",
    "clojure": "s-expression grammar; every form is a list, so function/binding/call cannot be distinguished by node type",
    "erlang": "pattern-matching binding forms do not map onto the assignment split this model uses",
}


class CppParser(GenericTreeSitterParser):
    """C++ parser."""

    profile = _CPP_PROFILE
    language = "cpp"


class ObjCParser(GenericTreeSitterParser):
    """Objective-C parser."""

    profile = _OBJC_PROFILE
    language = "objc"


class KotlinParser(GenericTreeSitterParser):
    """Kotlin parser."""

    profile = _KOTLIN_PROFILE
    language = "kotlin"


class SwiftParser(GenericTreeSitterParser):
    """Swift parser."""

    profile = _SWIFT_PROFILE
    language = "swift"


class ScalaParser(GenericTreeSitterParser):
    """Scala parser."""

    profile = _SCALA_PROFILE
    language = "scala"


class DartParser(GenericTreeSitterParser):
    """Dart parser."""

    profile = _DART_PROFILE
    language = "dart"


class LuaParser(GenericTreeSitterParser):
    """Lua parser."""

    profile = _LUA_PROFILE
    language = "lua"


class RParser(GenericTreeSitterParser):
    """R parser."""

    profile = _R_PROFILE
    language = "r"


class SolidityParser(GenericTreeSitterParser):
    """Solidity parser."""

    profile = _SOLIDITY_PROFILE
    language = "solidity"


class JuliaParser(GenericTreeSitterParser):
    """Julia parser."""

    profile = _JULIA_PROFILE
    language = "julia"


class PerlParser(GenericTreeSitterParser):
    """Perl parser."""

    profile = _PERL_PROFILE
    language = "perl"


class BashParser(GenericTreeSitterParser):
    """Bash / shell parser."""

    profile = _BASH_PROFILE
    language = "bash"


class PowerShellParser(GenericTreeSitterParser):
    """PowerShell parser."""

    profile = _POWERSHELL_PROFILE
    language = "powershell"
