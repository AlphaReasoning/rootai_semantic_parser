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

from analyzers.constants import UNKNOWN, ConstantFolder
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

#: Object construction. A constructor builds a value out of what it is handed;
#: it does not read the outside world. Matching source patterns against the
#: *type name* made `new javax.servlet.http.Cookie("x", "y")` an attacker-
#: controlled value because the class is called Cookie, which is one of the
#: highest-volume false positives OWASP Benchmark exposed. Constructors are
#: still matched as sinks -- `new FileInputStream(path)` genuinely opens a file.
_CONSTRUCTION_NODES: FrozenSet[str] = frozenset(
    {"object_creation_expression", "new_expression", "new", "object_creation"}
)

#: Constructs that embed an expression inside a string literal. The literal's
#: prose is not code, but these are: `"$QUERY_STRING"`, `f"ls {path}"` and
#: `"${req.query.c}"` all read a value that taint has to follow.
_INTERPOLATION_NODES: FrozenSet[str] = frozenset(
    {
        "string_interpolation", "interpolation", "template_substitution",
        "simple_expansion", "expansion", "command_substitution",
        "string_expansion", "substitution", "interpolated_string_expression",
        "subshell", "arithmetic_expansion",
        # Only ever consulted *inside* a literal, where a variable reference is
        # by definition an interpolation. PHP's `"WHERE n = $name"` embeds a
        # bare `variable_name`, and missing it would render the whole string as
        # fixed text -- a template with no holes, which this layer reads as
        # proof of safety.
        "variable_name",
    }
)

#: A bare variable reference, in any of the sigil styles used across the
#: supported languages.
_PLAIN_NAME = re.compile(r"^[$@]?[A-Za-z_][A-Za-z0-9_]*$")

#: Scope key standing in for "declared on the object, not in this function".
#: Fields outlive the method that writes them, so a write in one method and a
#: read in another must resolve to the same value node. Function-scoped lookup
#: put them in separate scopes and lost the flow entirely -- which is how every
#: MVC controller that stashes request data on ``this`` is written.
_FIELD_SCOPE = "__field__"

#: How each language spells "the current instance". A binding whose target is
#: prefixed with one of these names a field rather than a local.
_INSTANCE_PREFIXES: Tuple[str, ...] = ("this.", "self.", "$this->", "this->", "@")

#: Builder methods that append their argument to the receiver's contents, and
#: the readers that return those accumulated contents. `StringBuilder`,
#: `StringBuffer`, JS array-join builders and Python list-join all reduce to
#: this: a string assembled across several statements, then handed to a sink.
_BUILDER_APPENDERS = frozenset({"append", "concat", "add", "write", "insert"})
_BUILDER_READERS = frozenset({"tostring", "build", "toboundedstring", "str"})

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
                # Interpolated forms are literals with holes in them, not
                # opaque values: `SELECT ... ORDER BY ${col}` must be split,
                # or the whole query collapses into one hole and the position
                # of `col` becomes unknowable.
                "template_string",
                "template_literal",
                "string_literal_expression",
                # PHP double-quoted strings and heredocs. Missing these made a
                # concatenated query collapse into holes with no syntax, so the
                # position of every value in it became unknowable.
                "encapsed_string",
                "heredoc",
                "heredoc_body",
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

    #: Iteration that binds a name to each element of a collection. It is an
    #: assignment in everything but spelling, and there is no assignment
    #: operator to split on, so it needs its own handling: `for (Cookie c :
    #: request.getCookies())` is how servlets read cookies, and without this the
    #: loop variable was never declared and the flow ended at the collection.
    foreach_nodes: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "enhanced_for_statement", "for_each_statement", "foreach_statement",
                "for_in_statement", "for_of_statement", "for_statement",
                "range_clause", "for_in_clause",
            }
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
        #: Root of the file being parsed, for whole-file scope questions.
        self._root_node: Optional[Any] = None
        #: Start bytes of identifiers that are written to rather than read.
        self._assignment_targets: Set[int] = set()
        self._folder = ConstantFolder(self.profile.literal_nodes, self._get_text)
        #: (scope, name) -> compile-time value, for the branches that depend on
        #: it. Populated in source order as bindings are visited, and cleared
        #: for a name as soon as it is assigned something not constant.
        self._constants: Dict[Tuple[str, str], Any] = {}
        #: (scope, name) -> the string template that name was built from, so a
        #: sink handed a variable can still be told what the consuming parser
        #: will see. `sql = "..." + p; execute(sql)` is the ordinary shape.
        self._templates: Dict[Tuple[str, str], Any] = {}
        #: (scope, name) -> the template a StringBuilder-style variable has
        #: accumulated so far, updated as each `.append()` statement is walked.
        self._builders: Dict[Tuple[str, str], Any] = {}

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
        self._constants = {}
        self._templates = {}
        self._builders = {}
        self._root_node = tree.root_node
        self._assignment_targets = self._collect_assignment_targets(tree.root_node)

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
            self._note_builder_append(node, src, fn_id)
            self._visit_call(node, src, path, fn_id)

        if node_type in self.profile.exit_nodes:
            self._visit_return(node, src, fn_id)

        if node_type in self.profile.foreach_nodes:
            self._visit_foreach(node, src, path, fn_id)

        for child in self._live_children(node, src, fn_id):
            self._walk(child, src, path, parent_id, fn_id)

    # ------------------------------------------------------------------
    # String reconstruction
    # ------------------------------------------------------------------

    #: Operators that join text. Everything else terminates reconstruction,
    #: because `a - b` on strings is not concatenation in any language here.
    _CONCAT_OPERATORS = frozenset({"+", ".", "..", "&", "+=", ".=", "||"})

    def _build_template(self, node, src: str, fn_id: str, depth: int = 0):
        """Rebuild the string ``node`` evaluates to, as literals plus holes.

        This is what makes grammatical position knowable. The consuming parser
        never sees `"SELECT ... " + name`; it sees the string that expression
        produces, and whether `name` lands inside quotes or in an ORDER BY
        target is the difference between "escape it" and "escaping cannot help".

        Unknown constructs become a single hole rather than an error, and the
        template is marked incomplete. An incomplete template still pins the
        position of the holes it did recover; it just cannot be trusted to
        prove safety, which :meth:`_boundary_metadata` enforces.
        """
        from analyzers.boundaries import StringTemplate

        template = StringTemplate()
        self._extend_template(template, node, src, fn_id, depth)
        return template

    def _extend_template(self, template, node, src: str, fn_id: str, depth: int) -> None:
        if node is None or depth > 12:
            if node is not None:
                template.add_hole(self._get_text(src, node)[:80])
                template.complete = False
            return

        node_type = node.type

        # A value the folder can evaluate is fixed text however it was written,
        # which is how a chain of individually harmless assignments turns out to
        # contribute no attacker control at all.
        folded = self._folder.value(node, src, self._scope_constants(fn_id))
        if folded is not UNKNOWN and isinstance(folded, (str, int, float, bool)):
            template.add_literal(str(folded))
            return

        # Wrappers that carry no value of their own. PHP and Ruby wrap each
        # actual argument in an `argument` node, so reading position N gives a
        # wrapper rather than the expression, and the template collapsed to a
        # single opaque hole.
        if "parenthesized" in node_type or node_type in {
            "argument", "keyword_argument", "spread_element", "expression_statement",
        }:
            named = [child for child in node.children if child.is_named]
            if len(named) == 1:
                self._extend_template(template, named[0], src, fn_id, depth + 1)
                return

        if node_type.endswith("binary_expression") or node_type in {"binary_operator", "concatenation"}:
            operands = [child for child in node.children if child.is_named]
            operators = [
                self._get_text(src, child).strip()
                for child in node.children
                if not child.is_named and self._get_text(src, child).strip()
            ]
            joins_text = node_type == "concatenation" or (
                operators and all(op in self._CONCAT_OPERATORS for op in operators)
            )
            if joins_text and len(operands) >= 2:
                for operand in operands:
                    self._extend_template(template, operand, src, fn_id, depth + 1)
                return

        if node_type in self.profile.literal_nodes:
            self._extend_literal(template, node, src, fn_id, depth)
            return

        # Anything else -- an identifier, a call, a subscript -- is a runtime
        # value. A plain name may still resolve to a template built earlier,
        # which is what lets `sql = "..." + p; execute(sql)` be analysed at all.
        #
        # Matched on the text rather than the node type: PHP spells a variable
        # `variable_name` wrapping a `name`, Bash uses `variable_name` too, and
        # neither is in the profile's identifier set, so a type test silently
        # lost the indirection in exactly the languages that need it most.
        text = self._get_text(src, node).strip()
        if _PLAIN_NAME.match(text):
            name = text.lstrip("$@")
            recorded = self._templates.get((fn_id, name)) or self._templates.get((_FIELD_SCOPE, name))
            if recorded is not None:
                template.segments.extend(recorded.segments)
                template.complete = template.complete and recorded.complete
                return
            # A bare name is the value being classified: its position is the
            # finding, and the surrounding skeleton is still fully known.
            template.add_hole(text[:80])
            return

        # A StringBuilder read (`sb.toString()`) or an append chain resolves to
        # the string that was assembled into it, so the consumed query is
        # recovered even though it was never a single literal.
        builder = self._resolve_builder(node, src, fn_id)
        if builder is not None:
            template.segments.extend(builder.segments)
            template.complete = template.complete and builder.complete
            return

        # Anything else -- a call, a subscript, an unresolved expression -- could
        # itself contribute *structure* to the consumed language, not just a
        # value: `"... " + build() + " ..."` where build() returns `x ORDER BY`
        # would move every later hole to the wrong position. We cannot see
        # inside it, so the reconstruction is no longer trustworthy for proving
        # safety. It can still locate danger; it just must not suppress. Marking
        # this incomplete only forgoes a suppression, never a finding.
        template.complete = False
        template.add_hole(text[:80])

    def _resolve_builder(self, node, src: str, fn_id: str, depth: int = 0):
        """Return the template a StringBuilder-style expression assembles.

        Three forms, all reducing to "contents so far, plus this argument":

        * ``sb.toString()`` -- read: the receiver's accumulated contents.
        * ``x.append(a).append(b)`` -- a fluent chain, resolved base-outward.
        * ``sb`` (a bare name) -- the template accumulated for it by the
          statement-separated appends visited earlier.

        Returns ``None`` when the node is not a builder expression, so the
        caller falls through to its ordinary handling.
        """
        from analyzers.boundaries import StringTemplate

        if node is None or depth > 16:
            return None

        # A bare name: its accumulated template, if any statement built one.
        if node.type in self.profile.identifier_nodes:
            name = self._get_text(src, node).strip().lstrip("$@")
            recorded = self._builders.get((fn_id, name)) or self._builders.get((_FIELD_SCOPE, name))
            return recorded

        if node.type not in self.profile.call_nodes:
            return None

        callee_text, arguments = self._call_parts(node, src)
        if not callee_text:
            return None
        receiver_node, method = self._call_receiver(node, src)
        method = method.lower()

        # `new StringBuilder("seed")` -- constructor content, or empty.
        if node.type in _CONSTRUCTION_NODES or "stringbuilder" in callee_text.lower() or "stringbuffer" in callee_text.lower():
            template = StringTemplate()
            operands = [c for c in (arguments.children if arguments else []) if c.is_named]
            if operands:
                self._extend_template(template, operands[0], src, fn_id, depth + 1)
            return template

        if method in _BUILDER_READERS:
            return self._resolve_builder(receiver_node, src, fn_id, depth + 1)

        if method in _BUILDER_APPENDERS:
            base = self._resolve_builder(receiver_node, src, fn_id, depth + 1)
            if base is None:
                return None
            template = StringTemplate(list(base.segments), base.complete)
            operands = [c for c in (arguments.children if arguments else []) if c.is_named]
            if operands:
                self._extend_template(template, operands[0], src, fn_id, depth + 1)
            return template

        return None

    def _call_receiver(self, node, src: str):
        """Return ``(receiver node, method name)`` for a method call.

        For `a.b(x)` the receiver is `a` and the method is `b`; for a chain
        `a.b(x).c(y)` the receiver of the outer call is the whole `a.b(x)`
        sub-expression, which is what lets a fluent builder resolve base-outward.
        """
        children = [c for c in node.children if c.type not in self.profile.argument_container_nodes]
        method = ""
        for child in children:
            if child.type in self.profile.identifier_nodes:
                method = self._get_text(src, child).strip()
        receiver = children[0] if children and children[0] is not (children[-1] if children else None) else None
        # The receiver is everything left of the final `.method`; the first
        # child covers both `sb` and a nested `sb.append(x)` call node.
        if children and children[0].type not in {".", "->"}:
            receiver = children[0]
        return receiver, method

    def _note_builder_init(self, name: str, scope: str, fn_id: str, value_nodes: List[Any], src: str) -> None:
        """Seed a builder's accumulated template from its constructor.

        `new StringBuilder("SELECT ... ORDER BY ")` starts the builder with that
        text, so a later `.append(sort)` extends it rather than replacing it.
        Without seeding, the first append began from empty and the seed literal
        -- often the entire query skeleton -- was lost, and the position of
        every appended value with it.
        """
        key = (_FIELD_SCOPE if scope == _FIELD_SCOPE else fn_id, name)
        if len(value_nodes) != 1:
            self._builders.pop(key, None)
            return
        node = value_nodes[0]
        text = self._get_text(src, node).lower()
        if node.type not in _CONSTRUCTION_NODES and "stringbuilder" not in text and "stringbuffer" not in text:
            self._builders.pop(key, None)
            return
        seeded = self._resolve_builder(node, src, fn_id)
        if seeded is not None:
            self._builders[key] = seeded

    def _note_builder_append(self, node, src: str, fn_id: str) -> None:
        """Accumulate a statement-separated append into its named builder.

        `sb.append("SELECT ... ORDER BY "); sb.append(sort);` builds `sb` across
        two statements. Visited in source order, so appending as they are seen
        keeps the assembled string in the right order. Fluent chains do not need
        this -- they are resolved structurally at read time -- but the common
        Java idiom is statement-separated and would otherwise never resolve.
        """
        from analyzers.boundaries import StringTemplate

        callee_text, arguments = self._call_parts(node, src)
        if not callee_text or arguments is None or "." not in callee_text:
            return
        receiver, _, method = callee_text.rpartition(".")
        receiver = receiver.strip()
        if method.strip().lower() not in _BUILDER_APPENDERS or not _PLAIN_NAME.match(receiver):
            return
        name = receiver.lstrip("$@")
        key = (
            _FIELD_SCOPE if (_FIELD_SCOPE, name) in self._builders and (fn_id, name) not in self._builders else fn_id,
            name,
        )
        existing = self._builders.get((fn_id, name)) or self._builders.get((_FIELD_SCOPE, name))
        template = existing if existing is not None else StringTemplate()
        operands = [c for c in arguments.children if c.is_named]
        if operands:
            self._extend_template(template, operands[0], src, fn_id, 0)
        self._builders[key] = template

    def _extend_literal(self, template, node, src: str, fn_id: str, depth: int) -> None:
        """Split a literal into its fixed text and its interpolations.

        `f"ls {path}"` and `` `SELECT ${col} FROM t` `` are templates already;
        treating the whole literal as fixed text would hide the hole, and
        treating it as a hole would lose the surrounding syntax that decides
        the position.
        """
        interpolations = [
            child
            for child in self._iter_all(node, include_self=False)
            if child.type in _INTERPOLATION_NODES
        ]
        if not interpolations:
            template.add_literal(self._unquote(self._get_text(src, node)))
            return

        interpolations.sort(key=lambda child: child.start_byte)
        cursor = node.start_byte
        raw = src.encode("utf-8")
        for child in interpolations:
            before = raw[cursor : child.start_byte].decode("utf-8", "replace")
            # Only the delimiter comes off, never surrounding whitespace:
            # `ORDER BY ${col}` must keep the space or the rendered template
            # reads `ORDER BYROOTAIHOLE0` and the grammar sees one identifier.
            # Leading delimiter only. The chunk before an interpolation often
            # *ends* in a quote that belongs to the embedded language --
            # `"... WHERE n = '$c'"` -- and stripping it moved the hole from a
            # quoted literal to a bare operand, inverting the required defence.
            template.add_literal(
                self._strip_delimiters(before, trailing=False)
                if cursor == node.start_byte
                else before
            )
            template.add_hole(self._get_text(src, child)[:80])
            cursor = child.end_byte
        tail = raw[cursor : node.end_byte].decode("utf-8", "replace")
        template.add_literal(self._strip_delimiters(tail, leading=False))

    @staticmethod
    def _strip_delimiters(text: str, leading: bool = True, trailing: bool = True) -> str:
        """Remove string delimiters and any prefix sigil, preserving whitespace."""
        result = text
        if leading:
            index = 0
            while index < len(result) and result[index] in "fFrRbBuU@$":
                index += 1
            if index < len(result) and result[index] in "\"'`":
                result = result[index + 1 :]
        if trailing and result and result[-1] in "\"'`":
            result = result[:-1]
        return result

    @staticmethod
    def _unquote(text: str) -> str:
        stripped = text.strip()
        for prefix in ("f", "r", "b", "rb", "br", "u", "$", "@"):
            if stripped[: len(prefix)].lower() == prefix and len(stripped) > len(prefix):
                stripped = stripped[len(prefix) :]
                break
        if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'`":
            return stripped[1:-1]
        return stripped.lstrip("\"'`").rstrip("\"'`")

    def _visit_foreach(self, node, src: str, path: str, fn_id: str) -> None:
        """Bind a loop variable to the collection it iterates.

        ``for (Cookie theCookie : request.getCookies())`` is an assignment with
        no assignment operator, so the split that drives every other binding
        finds nothing and ``theCookie`` is never declared. Reads of it inside
        the body then resolve to nothing and the flow stops at the collection --
        which is precisely how servlets, and most request-collection handling,
        are written.

        Element taint is the collection's taint. Which element is which needs
        constant propagation over the index, so the whole collection's taint is
        attributed to each binding.
        """
        named = [child for child in node.children if child.is_named]
        body_types = _BODY_NODES | self.profile.function_nodes
        header = [child for child in named if child.type not in body_types]
        if len(header) < 2:
            return
        iterable = header[-1]
        # The loop variable is the last identifier before the iterable; a type
        # annotation may precede it (`Cookie theCookie`), and destructuring
        # patterns are left alone rather than guessed at.
        target = header[-2]
        name, target_scope = self._binding_target(target, src)
        if not name:
            return

        var_id = self._declare_value(
            name, path, fn_id, node.start_point[0] + 1, "binding", target_scope
        )
        if self._matches_pattern(
            self._text_outside_literals(iterable, src, skip_arguments=True),
            self._taint_config.sources,
            LANGUAGE_SCOPED_SOURCES,
        ):
            self.nodes[var_id].is_unsafe = True
            self.nodes[var_id].metadata["is_taint_source"] = True
            self.nodes[var_id].metadata["tainted_by"] = self._get_text(src, iterable)[:96]

        for referenced in self._referenced_values([iterable], src, fn_id):
            if referenced != var_id:
                self.edges.append(
                    self._edge(
                        referenced, var_id, EdgeRelation.DATAFLOW, {"flow_kind": "iteration"}
                    )
                )
        for call in self._iter_calls([iterable]):
            callee_id = self._visit_call(call, src, path, fn_id)
            if callee_id:
                self.edges.append(
                    self._edge(
                        callee_id, var_id, EdgeRelation.DATAFLOW, {"flow_kind": "iteration"}
                    )
                )

    def _visit_return(self, node, src: str, fn_id: str) -> None:
        """Record what a function hands back to its caller.

        Without this the only route from callee to caller was the synthetic
        call-target stub, and a tainted argument reached the stub and came
        straight back out as the call's result -- so ``String safe =
        clean(param)`` marked ``safe`` tainted no matter what ``clean`` did.
        Modelling the return means a resolved call carries taint only if the
        body actually returns it.
        """
        for value_id in self._referenced_values([node], src, fn_id):
            self.edges.append(
                self._edge(value_id, fn_id, EdgeRelation.DATAFLOW, {"flow_kind": "return"})
            )
            self.edges.append(self._edge(value_id, fn_id, EdgeRelation.RETURNS))

    # ------------------------------------------------------------------
    # Branch feasibility
    # ------------------------------------------------------------------

    def _live_children(self, node, src: str, fn_id: str) -> List[Any]:
        """Children that can execute, given what is known at compile time.

        A branch whose condition provably never holds contributes no dataflow,
        but reachability sees the assignment inside it and reports the value as
        if it were live. OWASP Benchmark builds its *safe* cases exactly this
        way -- ``if (false)``, an always-true ternary, a switch on a folded
        character -- and it is the single largest false-positive class measured.

        Undecidable conditions return every child, so this only ever removes
        paths that are provably dead.
        """
        node_type = node.type
        if "if_statement" in node_type or node_type in {"if_expression", "if"}:
            return self._live_if_children(node, src, fn_id)
        if "switch" in node_type and "block" not in node_type and "label" not in node_type:
            return self._live_switch_children(node, src, fn_id)
        return list(node.children)

    def _live_if_children(self, node, src: str, fn_id: str) -> List[Any]:
        named = [child for child in node.children if child.is_named]
        if len(named) < 2:
            return list(node.children)
        condition = named[0]
        verdict = self._folder.truth(condition, src, self._scope_constants(fn_id))
        if verdict is None:
            return list(node.children)
        # named[1] is the consequence; anything after it is the else arm.
        return [condition, named[1]] if verdict else [condition] + named[2:]

    def _live_switch_children(self, node, src: str, fn_id: str) -> List[Any]:
        named = [child for child in node.children if child.is_named]
        if len(named) < 2:
            return list(node.children)
        discriminant = self._folder.value(named[0], src, self._scope_constants(fn_id))
        if discriminant is UNKNOWN:
            return list(node.children)

        block = named[1]
        groups = [child for child in block.children if child.is_named]
        selected: List[Any] = []
        matched = False
        for group in groups:
            if not matched and self._group_matches(group, src, discriminant, fn_id):
                matched = True
            if matched:
                selected.append(group)
                # Without a break the next group runs too, so keep collecting
                # until one terminates. Modelling fallthrough wrongly would
                # drop live code, which is the expensive direction to be wrong.
                if self._terminates(group):
                    break
        if not matched:
            # Nothing matched: only a default arm can run.
            selected = [group for group in groups if self._is_default(group, src)]
        return [named[0]] + selected

    def _group_matches(self, group, src: str, discriminant: Any, fn_id: str) -> bool:
        env = self._scope_constants(fn_id)
        for child in group.children:
            if "label" not in child.type and "case" not in child.type:
                continue
            if self._is_default(child, src):
                continue
            for candidate in child.children:
                if not candidate.is_named:
                    continue
                value = self._folder.value(candidate, src, env)
                if value is not UNKNOWN and value == discriminant:
                    return True
        return False

    def _is_default(self, node, src: str) -> bool:
        return self._get_text(src, node).strip().lower().startswith("default")

    def _terminates(self, group) -> bool:
        return any(
            child.type in self.profile.exit_nodes
            for child in self._iter_all(group, include_self=True)
        )

    def _scope_constants(self, fn_id: str) -> Dict[str, Any]:
        """Constant environment visible inside ``fn_id``."""
        return {
            name: value
            for (scope, name), value in self._constants.items()
            if scope in (fn_id, _FIELD_SCOPE)
        }

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

    def _resolve_constant_branches(self, value_nodes: List[Any], src: str, fn_id: str) -> List[Any]:
        """Replace a decidable ternary with the branch that actually runs.

        ``bar = (7 * 18) + num > 200 ? "constant" : param`` assigns the
        constant, always. Keeping both arms let ``param`` flow into ``bar`` and
        on to the sink, which is a path that cannot execute.
        """
        env = self._scope_constants(fn_id)
        resolved: List[Any] = []
        for item in value_nodes:
            branches = None
            if "ternary" in item.type or item.type in {"conditional_expression", "conditional"}:
                branches = self._folder.ternary_branches(item, src, env)
            resolved.append(branches[0] if branches else item)
        return resolved

    def _record_constant(self, name: str, scope: str, fn_id: str, value_nodes: List[Any], src: str) -> None:
        """Remember, or forget, ``name``'s compile-time value.

        Forgetting matters as much as remembering: once a name is assigned
        something unknown, every later branch that tests it must be treated as
        undecidable again.
        """
        key = (_FIELD_SCOPE if scope == _FIELD_SCOPE else fn_id, name)
        value = UNKNOWN
        if len(value_nodes) == 1:
            value = self._folder.value(value_nodes[0], src, self._scope_constants(fn_id))
        if value is UNKNOWN:
            self._constants.pop(key, None)
        else:
            self._constants[key] = value

    def _record_template(self, name: str, scope: str, fn_id: str, value_nodes: List[Any], src: str) -> None:
        """Remember the string ``name`` was built from, or forget it.

        Sinks are almost never handed a literal. `sql = "..." + p;
        execute(sql)` is the ordinary shape, so without this the consuming
        parser would only ever be shown a bare identifier and every position
        would be unknown.
        """
        key = (_FIELD_SCOPE if scope == _FIELD_SCOPE else fn_id, name)
        if len(value_nodes) != 1:
            self._templates.pop(key, None)
            return
        template = self._build_template(value_nodes[0], src, fn_id)
        # A template that is nothing but one hole says nothing the sink did not
        # already know, and keeping it would only chain holes together.
        if len(template.segments) == 1 and template.segments[0][0] == "hole":
            self._templates.pop(key, None)
            return
        self._templates[key] = template

    def _visit_binding(self, node, src: str, path: str, fn_id: str) -> None:
        """Create the bound variable and connect the value side to it."""
        target_nodes, value_nodes = self._split_on_assignment(node)
        if not target_nodes or not value_nodes:
            return

        value_nodes = self._resolve_constant_branches(value_nodes, src, fn_id)
        value_text = " ".join(self._get_text(src, item) for item in value_nodes).strip()
        if not value_text:
            return

        taint_config = self._taint_config
        is_source = self._matches_pattern(
            " ".join(
                self._text_outside_literals(item, src, skip_arguments=True)
                for item in value_nodes
            ),
            taint_config.sources,
            LANGUAGE_SCOPED_SOURCES,
        )

        bound_functions = [
            item
            for value in value_nodes
            for item in self._iter_all(value, include_self=True)
            if item.type in self.profile.function_nodes
        ]

        # The value side is resolved before any target is declared, because a
        # self-referential assignment reads the *previous* value:
        # `param = URLDecoder.decode(param, "UTF-8")` must connect the old
        # `param` to the call. Declaring the target first made the lookup return
        # the node being created, so both ends of the edge were the same node
        # and the chain ended there without a trace. Every `x = f(x)` -- decode,
        # trim, normalise, unescape -- was silently losing its taint.
        #
        # Identifiers that appear only as call arguments get no direct edge:
        # their contribution passes *through* that call, and a direct edge would
        # route taint around any sanitizer sitting in it.
        call_argument_values: Set[str] = set()
        for call in self._iter_calls(value_nodes):
            _, call_arguments = self._call_parts(call, src)
            if call_arguments is not None:
                call_argument_values.update(self._referenced_values([call_arguments], src, fn_id))

        direct_references = [
            referenced
            for referenced in self._referenced_values(value_nodes, src, fn_id)
            if referenced not in call_argument_values
        ]
        # Only the *outermost* calls return into the binding. In
        # `col = parseInt(getParameter(x))` the value of the binding is what
        # parseInt returns; getParameter returns into parseInt, not into col.
        # Wiring every nested call into the binding let taint flow
        # getParameter -> col directly, skipping the sanitiser in between --
        # which is exactly how a numeric cast or an escaper wrapping the source
        # was silently bypassed. Nested calls are wired into their enclosing
        # call by `_visit_call` itself.
        #
        # Visited once here rather than per target, which also stops a
        # multi-target binding from emitting the same call twice.
        call_returns = [
            callee_id
            for call in self._top_level_calls(value_nodes)
            if (callee_id := self._visit_call(call, src, path, fn_id))
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
            self._record_constant(name, target_scope, fn_id, value_nodes, src)
            self._record_template(name, target_scope, fn_id, value_nodes, src)
            self._note_builder_init(name, target_scope, fn_id, value_nodes, src)
            var_id = self._declare_value(name, path, fn_id, lineno, "binding", target_scope)
            if is_source:
                self.nodes[var_id].is_unsafe = True
                self.nodes[var_id].metadata["is_taint_source"] = True
                self.nodes[var_id].metadata["tainted_by"] = value_text[:96]

            for referenced in direct_references:
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
            for callee_id in call_returns:
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
        is_source = node.type not in _CONSTRUCTION_NODES and (
            self._matches_pattern(callee_text, taint_config.sources, LANGUAGE_SCOPED_SOURCES)
            or self._matches_pattern(resolved, taint_config.sources, LANGUAGE_SCOPED_SOURCES)
        )
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
            # A call nested in these arguments returns its value *into this
            # call*: `parseInt(getParameter(x))` feeds getParameter's result to
            # parseInt. Without this the inner call reached only the binding,
            # routing taint around the outer sanitiser.
            for nested in self._immediate_argument_calls(arguments):
                nested_id = self._visit_call(nested, src, path, fn_id)
                if nested_id and nested_id != callee_id:
                    self.edges.append(
                        self._edge(
                            nested_id,
                            callee_id,
                            EdgeRelation.DATAFLOW,
                            {"flow_kind": "call_argument", "call_name": callee_text},
                        )
                    )
                    argument_ids.append(nested_id)
            self._note_collection_write(callee_text, argument_ids, src, fn_id)
            if is_sink:
                self._note_boundary(callee_id, callee_text, arguments, src, fn_id)
        self._note_receiver(callee_text, callee_id, fn_id)
        self._call_sites.append((callee_text.split(".")[-1].strip(), callee_id, argument_ids))
        return callee_id

    def _note_boundary(self, callee_id: str, callee_text: str, arguments, src: str, fn_id: str) -> None:
        """Record what the consuming parser will see at this sink.

        The sink's own name says which language parses its argument; the
        template says where the runtime values land in that language. Together
        they answer "what defence is required here", which the sink name alone
        never can.
        """
        from analyzers.boundaries import analyse, consumer_for

        mapping = consumer_for(callee_text)
        if mapping is None or arguments is None:
            return
        consumer, position = mapping
        operands = [child for child in arguments.children if child.is_named]
        if position >= len(operands):
            return

        from analyzers.boundaries import WHOLE_VALUE_CONSUMERS

        template = self._build_template(operands[position], src, fn_id)
        if not template.segments:
            return
        # A template that is nothing but one hole carries no syntax, so any
        # position a *grammar* reports for it is an artifact of the probe token:
        # `execute(buildQuery(req))` would otherwise be claimed as an identifier
        # position with full confidence. But for format/template/regex a bare
        # value is exactly the vulnerability -- `printf(userInput)` is the bug
        # -- so those consumers keep it.
        if consumer not in WHOLE_VALUE_CONSUMERS and all(
            kind == "hole" for kind, _ in template.segments
        ):
            return
        analysis = analyse(template.render(), consumer)
        if analysis is None:
            return

        metadata = self.nodes[callee_id].metadata
        metadata["boundary"] = {
            **analysis.to_dict(),
            **template.to_dict(),
            # An incomplete reconstruction may have missed a hole, so it can
            # locate danger but must never be read as proof of safety.
            "trustworthy_safe": template.complete,
        }

    def _note_receiver(self, callee_text: str, callee_id: str, fn_id: str) -> None:
        """A method's result derives from the object it was called on.

        ``theCookie.getValue()`` returns the cookie's data; only the arguments
        were connected, so a call with none carried nothing and the chain broke
        at the receiver. Accessor-heavy APIs -- servlets, ORMs, HTTP clients --
        are written almost entirely this way.
        """
        separator = "->" if "->" in callee_text else "."
        if separator not in callee_text:
            return
        receiver = callee_text.rpartition(separator)[0].strip().split(separator)[-1].strip()
        if not receiver:
            return
        receiver_id = self._lookup_value(receiver, fn_id)
        if receiver_id is None or receiver_id == callee_id:
            return
        self.edges.append(
            self._edge(
                receiver_id, callee_id, EdgeRelation.DATAFLOW, {"flow_kind": "receiver"}
            )
        )

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
        resolved_stubs: Set[str] = set()
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
            self.nodes[callee_id].metadata["resolved_to"] = target_fn
            # A stub that is itself a known sink keeps its argument edges even
            # when a local function shares the name. The argument arriving at
            # `system(c)` *is* the finding; suppressing it in favour of walking
            # a same-named declaration loses the very flow being looked for.
            if not (self.nodes[callee_id].metadata.get("is_taint_sink") or self.nodes[callee_id].is_unsafe):
                resolved_stubs.add(callee_id)
            # What the body returns becomes the call's result. The stub is what
            # the caller's binding reads from, so the return lands here.
            self.edges.append(
                self._edge(
                    target_fn,
                    callee_id,
                    EdgeRelation.DATAFLOW,
                    {"flow_kind": "resolved_return", "call_name": short_name},
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

        # Arguments to a call whose body is in the graph must not also flow
        # straight into the stub: the stub returns into the caller's binding, so
        # that edge is a shortcut around the function. It made every wrapper
        # transparent -- `String safe = escapeIt(param)` came back tainted
        # regardless of what `escapeIt` did with it. Library calls keep the
        # shortcut, because their body is not available to walk.
        for edge in self.edges:
            metadata = edge.metadata or {}
            if metadata.get("flow_kind") == "call_argument" and edge.target in resolved_stubs:
                metadata["flow_kind"] = "call_argument_resolved"
                edge.metadata = metadata

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
        # Type predicates. A value that must parse as a number cannot carry a
        # payload for any sink, which is the same reasoning that makes `int()`
        # a universal sanitizer rather than a category-specific one.
        "is_numeric", "isnumeric", "isdigit", "is_int", "is_integer", "ctype_digit",
        "isinstance", "is_a(", "instanceof", "matches(",
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
        test_text = self._get_text(src, test).lower()
        constraining = any(token in test_text for token in self._CONSTRAINING_TESTS)

        bails_out = any(
            candidate.type in self.profile.exit_nodes
            for branch in body
            for candidate in self._iter_all(branch, include_self=True)
        )
        confined = False
        if not bails_out:
            # The other half of the same idea, and the more common half. DVWA's
            # fixed command-exec page wraps the sink in
            # `if (is_numeric($octet[0]) && ...) { shell_exec(...); }` instead of
            # returning early, so the code inside only ever runs on input that
            # satisfied the test.
            #
            # But a wrapping guard defends only what is *inside* it, while the
            # mark lives on the value node and applies everywhere. Sanitizer
            # state is not flow-sensitive, so claiming otherwise would drop real
            # findings -- the expensive direction to be wrong in. The mark is
            # therefore applied only when every use of the value lies within the
            # guarded branch, which is checkable without flow sensitivity and
            # errs towards reporting.
            if not constraining:
                return
            confined = True

        span = (node.start_byte, node.end_byte)
        for value_id, name in self._referenced_named_values([test], src, fn_id):
            if confined and self._used_outside(name, src, span):
                continue
            metadata = self.nodes[value_id].metadata
            metadata["guarded"] = True
            metadata["guard_test"] = self._get_text(src, test)[:120]
            if constraining:
                # Recorded the way an explicit sanitizer is, so the analyzer
                # treats a passed allowlist check as defending the value.
                metadata["sanitizer_for"] = ["*"]

    def _referenced_named_values(
        self, nodes: List[Any], src: str, fn_id: str
    ) -> List[Tuple[str, str]]:
        """``(value_id, name)`` pairs for values named inside ``nodes``."""
        pairs: List[Tuple[str, str]] = []
        for root in nodes:
            for candidate in self._iter_all(root, include_self=True):
                if candidate.type not in self.profile.identifier_nodes:
                    continue
                name = self._get_text(src, candidate).lstrip("$").strip()
                value_id = self._lookup_value(name, fn_id) if name else None
                if value_id is not None and (value_id, name) not in pairs:
                    pairs.append((value_id, name))
        return pairs

    def _used_outside(self, name: str, src: str, span: Tuple[int, int]) -> bool:
        """Whether ``name`` is also read outside the byte range ``span``.

        Conservative by construction: a same-named local in an unrelated
        function counts as an outside use, so the guard simply does not apply.
        Failing to recognise a guard costs precision; claiming one that does not
        hold costs a finding.
        """
        if self._root_node is None:
            return True
        start, end = span
        for candidate in self._iter_all(self._root_node, include_self=True):
            if candidate.type not in self.profile.identifier_nodes:
                continue
            if start <= candidate.start_byte and candidate.end_byte <= end:
                continue
            # An assignment *to* the name outside the branch is not a use of the
            # guarded value; it is where that value came from. DVWA's fixed page
            # builds `$octet` above the guard and reads it only inside, which is
            # exactly the shape a write-blind check would reject.
            if candidate.start_byte in self._assignment_targets:
                continue
            if self._get_text(src, candidate).lstrip("$").strip() == name:
                return True
        return False

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
        # Ordered by position, not by traversal. `_iter_all` walks children with
        # a stack, which yields them right-to-left; callers bind arguments to
        # parameters *positionally*, so `doPost(request, response)` was binding
        # request to the response parameter and vice versa. That put a source on
        # whichever parameter happened to come last and invented flows between
        # unrelated values.
        found: List[Tuple[int, str]] = []
        seen: Set[str] = set()
        for root in nodes:
            # include_self, because the node handed in is frequently the value
            # itself: `String b = a;` and `for (Cookie c : theCookies)` both
            # pass a bare identifier, and descendant-only traversal returned
            # nothing for them -- so a plain copy carried no taint at all.
            for candidate in self._iter_all(root, include_self=True):
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
                    found.append((candidate.start_byte, value_id))
        return [value_id for _, value_id in sorted(found)]

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

    def _collect_assignment_targets(self, root) -> Set[int]:
        """Start bytes of every identifier that appears on a binding's left side."""
        targets: Set[int] = set()
        for node in self._iter_all(root, include_self=True):
            if node.type not in self.profile.binding_nodes:
                continue
            for target, _ in [self._split_on_assignment(node)][0:1]:
                for item in target:
                    for candidate in self._iter_all(item, include_self=True):
                        if candidate.type in self.profile.identifier_nodes:
                            targets.add(candidate.start_byte)
        return targets

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

    def _top_level_calls(self, nodes: List[Any]) -> List[Any]:
        """Calls in ``nodes`` that are not nested inside another call there.

        `parseInt(getParameter(x))` has one top-level call, `parseInt`. The
        inner one is that call's business, not the binding's.
        """
        result: List[Any] = []

        def walk(node) -> None:
            if node.type in self.profile.call_nodes:
                result.append(node)
                return  # its own nested calls belong to it, not the binding
            for child in node.children:
                walk(child)

        for root in nodes:
            walk(root)
        return result

    def _immediate_argument_calls(self, arguments) -> List[Any]:
        """Calls directly inside ``arguments``, not nested within another call.

        These are the values passed to the enclosing call: in `outer(inner(x),
        y())`, both `inner(x)` and `y()`. Their results flow into `outer`, so a
        sanitiser wrapping a source (`escape(getParam(x))`) is on the path
        rather than bypassed.
        """
        result: List[Any] = []

        def walk(node) -> None:
            if node.type in self.profile.call_nodes:
                result.append(node)
                return
            for child in node.children:
                walk(child)

        for child in arguments.children:
            walk(child)
        return result

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

    def _text_outside_literals(self, node, src: str, skip_arguments: bool = False) -> str:
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

        ``skip_arguments`` additionally drops what is passed *into* a call.
        Deciding whether a binding is a source from its text alone made
        ``String bar = new Test().doSomething(request, param)`` a source,
        because the word ``request`` appears in it -- even though the value is
        whatever the method returns. The receiver still counts:
        ``request.getParameter("p")`` derives from ``request`` and must stay a
        source. Arguments do not, and taint that genuinely passes through them
        arrives on a dataflow edge rather than by spelling.
        """
        literals = self.profile.literal_nodes
        containers = self.profile.argument_container_nodes
        parts: List[str] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if skip_arguments and current.type in containers:
                continue
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
