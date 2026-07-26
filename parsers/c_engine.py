"""C language parser — tree-sitter backed, IR v0.3.0.

Architecture contract
---------------------
* Extends ``TreeSitterParser`` — tree-sitter is **required** (no regex fallback).
* Raises ``RuntimeError`` at construction time if the tree-sitter runtime or
  the C grammar are unavailable, preventing silent no-op parses.
* Populates ``self.nodes`` and ``self.edges`` exclusively via the base-class
  helpers ``_make_node()`` and ``_edge()`` so that GraphMerger / SymbolResolver
  remain unchanged.
* All C-specific data is encoded inside ``Node.metadata`` and ``Edge.metadata``
  under the schemas defined in the integration blueprint (IR v0.3.0 §2.2.3).

Override directives applied
---------------------------
1. Translation-unit precedence: ``.c`` files are parsed as full translation units.
   ``.h`` files are parsed as declaration-only units (``is_declaration_only=True``
   on all FUNCTION nodes). When both ``foo.c`` and ``foo.h`` exist in the same
   scan root, ``ParseCache`` will serve the ``.c`` result; the ``.h`` is processed
   strictly on cache miss. The ``supports()`` classmethod returns ``True`` for both
   ``.c`` and ``.h`` — the declaration-only flag is set inside ``parse()``.
2. Macro AST tracing: preprocessor macros (``preproc_def``, ``preproc_function_def``)
   are expanded prior to the S1 semantic pass. ``_visit_preproc_def()`` walks the
   macro body text and emits ``MACRO_EXPANDS_TO`` edges to inlined expression nodes.
   Function-like macros emit additional ``CALLS`` edges to their expanded callees.
3. Tree-sitter binding: grammar loaded via ``tree_sitter_language_pack`` using the
   existing ``resolve_tree_sitter_language()`` dispatcher in engines.py.

Registration
------------
The module-level ``register_parser(CParser)`` call at the bottom fires on
import, injecting the class into ``PARSER_PLUGINS``. During Phase 3 it will also
be added to the hard-coded list in ``iter_parser_classes()``.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzers.symbols import SSAVersionTracker, make_node_id
from models import AnalysisOptions, EdgeRelation, NodeType, SecurityConfig
from parsers.engines import TREE_SITTER_AVAILABLE, TreeSitterParser, _mark_function_entrypoint
from parsers.registry import register_parser

# ---------------------------------------------------------------------------
# Guard: tree-sitter is mandatory.
# ---------------------------------------------------------------------------
if not TREE_SITTER_AVAILABLE:
    raise ImportError(
        "CParser requires the tree-sitter runtime. "
        "Install it with:  pip install tree-sitter tree-sitter-language-pack"
    )


# ---------------------------------------------------------------------------
# Tree-sitter node-type constants for the C grammar (grammar version 15).
# ---------------------------------------------------------------------------
_TS_TRANSLATION_UNIT = "translation_unit"
_TS_FUNCTION_DEF = "function_definition"
_TS_FUNCTION_DECL = "declaration"            # covers prototypes & var decls
_TS_FUNCTION_DECLARATOR = "function_declarator"
_TS_POINTER_DECLARATOR = "pointer_declarator"
_TS_ABSTRACT_DECLARATOR = "abstract_declarator"
_TS_COMPOUND_STMT = "compound_statement"
_TS_EXPRESSION_STMT = "expression_statement"
_TS_RETURN_STMT = "return_statement"
_TS_IF_STMT = "if_statement"
_TS_FOR_STMT = "for_statement"
_TS_WHILE_STMT = "while_statement"
_TS_DO_STMT = "do_statement"
_TS_STRUCT_SPEC = "struct_specifier"
_TS_UNION_SPEC = "union_specifier"
_TS_ENUM_SPEC = "enum_specifier"
_TS_FIELD_DECL_LIST = "field_declaration_list"
_TS_FIELD_DECL = "field_declaration"
_TS_FIELD_IDENTIFIER = "field_identifier"
_TS_TYPE_DEF = "type_definition"
_TS_TYPEDEF_KW = "typedef"
_TS_TYPE_IDENTIFIER = "type_identifier"
_TS_IDENTIFIER = "identifier"
_TS_CALL_EXPR = "call_expression"
_TS_ARGUMENT_LIST = "argument_list"
_TS_PARAMETER_LIST = "parameter_list"
_TS_PARAMETER_DECL = "parameter_declaration"
_TS_PREPROC_INCLUDE = "preproc_include"
_TS_PREPROC_DEF = "preproc_def"
_TS_PREPROC_FUNC_DEF = "preproc_function_def"
_TS_PREPROC_ARG = "preproc_arg"
_TS_PREPROC_PARAMS = "preproc_params"
_TS_PREPROC_CALL = "preproc_call"            # generic #pragma / #line etc.
_TS_PREPROC_IFDEF = "preproc_ifdef"
_TS_PREPROC_IF = "preproc_if"
_TS_PRIMITIVE_TYPE = "primitive_type"
_TS_SIZED_TYPE_SPEC = "sized_type_specifier"
_TS_POINTER_EXPR = "pointer_expression"      # *ptr dereference
_TS_SUBSCRIPT_EXPR = "subscript_expression"  # arr[idx]
_TS_BINARY_EXPR = "binary_expression"
_TS_UNARY_EXPR = "unary_expression"
_TS_ASSIGNMENT_EXPR = "assignment_expression"
_TS_INIT_DECLARATOR = "init_declarator"
_TS_CAST_EXPR = "cast_expression"
_TS_COMMA_EXPR = "comma_expression"
_TS_COND_EXPR = "conditional_expression"
_TS_OFFSETOF_EXPR = "offsetof_expression"
_TS_SIZEOF_EXPR = "sizeof_expression"
_TS_STRING_LITERAL = "string_literal"
_TS_NUMBER_LITERAL = "number_literal"
_TS_CHAR_LITERAL = "char_literal"
_TS_COMMENT = "comment"

# Regex patterns for type analysis.
_RE_POINTER_DEPTH = re.compile(r"\*")
_RE_FUNCTION_PTR = re.compile(r"\(\s*\*")
_RE_FORMAT_FN = re.compile(
    r"^(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|scanf|fscanf|sscanf)$"
)

# Functions known to perform unchecked string operations (classic unsafe C sinks).
_UNSAFE_C_SINKS: Set[str] = {
    "strcpy", "strcat", "sprintf", "gets", "scanf",
    "system", "popen", "exec", "execl", "execle", "execlp",
    "execv", "execve", "execvp", "dlopen", "dlsym",
}
_FORMAT_STRING_SINKS: Set[str] = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "scanf", "fscanf", "sscanf",
}


class CParser(TreeSitterParser):
    """Tree-sitter backed parser for C source and header files.

    Emits IR v0.3.0 nodes and edges including:
    - ``NodeType.FUNCTION``, ``STRUCT``, ``UNION_TYPE``, ``TYPEDEF``,
      ``VARIABLE``, ``UNSAFE``, ``MACRO_EXPANSION``, ``IMPORT``, ``MODULE``
    - ``EdgeRelation.POINTER_ARITH``, ``UNSAFE_DEREFERENCE``,
      ``MACRO_EXPANDS_TO``, ``FIELD_ACCESS``, ``CONTAINS``, ``CALLS``,
      ``DATAFLOW``, ``IMPORTS``, ``RETURNS``
    """

    language: str = "c"

    def __init__(
        self,
        config: SecurityConfig,
        options: Optional[AnalysisOptions] = None,
    ) -> None:
        super().__init__(config, language_name="c", options=options)

        self._ssa: SSAVersionTracker = SSAVersionTracker()

        # Maps macro name → {"kind", "body_text", "defined_in", "is_function_like"}
        self._macro_registry: Dict[str, Dict[str, Any]] = {}

        # Maps struct/union name → list of field dicts.
        self._struct_layouts: Dict[str, List[Dict[str, Any]]] = {}

        # Maps typedef alias → underlying type string.
        self._typedef_map: Dict[str, str] = {}

        # Maps variable name → pointer indirection depth (0 = non-pointer).
        self._pointer_depth_map: Dict[str, int] = {}

        # Current translation unit file (the .c file being parsed).
        self._translation_unit: str = ""

        # Whether the file being parsed is a header (declaration-only).
        self._is_header: bool = False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @classmethod
    def supports(cls, path: str) -> bool:
        """Return True for ``.c`` and ``.h`` files.

        Override directive #1: ``.c`` files are parsed as full translation units;
        ``.h`` files are parsed as declaration-only units. Both return True here;
        the ``parse()`` method sets ``is_declaration_only`` accordingly.
        """
        return path.endswith((".c", ".h"))

    def parse(self, path: str) -> None:
        """Parse a C source or header file and populate ``self.nodes`` / ``self.edges``.

        Execution order
        ---------------
        1. Read source bytes and run tree-sitter parse (S1 entry).
        2. Determine translation-unit vs. declaration-only mode.
        3. Emit MODULE node.
        4. Walk root children: preproc directives first (macro registry), then
           type definitions, then function definitions.
        5. Macro expansion tracing (directive #2) is embedded in step 4.
        """
        with open(path, "rb") as fh:
            source_bytes = fh.read()

        source_str: str = source_bytes.decode("utf-8", errors="replace")
        tree = self._ts_parser.parse(source_bytes)
        root = tree.root_node

        # Override directive #1: set declaration-only flag for header files.
        self._is_header = path.endswith(".h")
        self._translation_unit = path if not self._is_header else ""

        # Reset per-file state.
        self._ssa = SSAVersionTracker()
        self._macro_registry = {}
        self._struct_layouts = {}
        self._typedef_map = {}
        self._pointer_depth_map = {}

        # MODULE node.
        mod_label = os.path.basename(path)
        mod_id = self._make_id(path, "__module__")
        mod_node = self._make_node(mod_id, NodeType.MODULE, mod_label, path, lineno=1)
        mod_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "is_header": self._is_header,
                "included_from": None,
            }
        )
        self.nodes[mod_id] = mod_node

        # Pass 1: scan preprocessor directives to build macro registry.
        for child in root.children:
            if child.type in (_TS_PREPROC_DEF, _TS_PREPROC_FUNC_DEF):
                self._record_macro(child, source_str, path)
            elif child.type in (_TS_PREPROC_IFDEF, _TS_PREPROC_IF):
                # Fix 3: recurse into conditional blocks to find macros inside #ifdef.
                self._record_conditional_macros(child, source_str, path)
            elif child.type == _TS_PREPROC_INCLUDE:
                self._visit_include(child, source_str, path, mod_id)

        # Pass 2: emit all top-level declarations.
        for child in root.children:
            self._visit_top_level(child, source_str, path, mod_id)

    # ------------------------------------------------------------------
    # Top-level dispatch
    # ------------------------------------------------------------------

    def _visit_top_level(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Dispatch a top-level translation_unit child."""
        t = node.type
        if t == _TS_FUNCTION_DEF:
            self._visit_function(node, src, path, parent_id)
        elif t == _TS_FUNCTION_DECL:
            self._visit_declaration(node, src, path, parent_id)
        elif t == _TS_TYPE_DEF:
            self._visit_typedef(node, src, path, parent_id)
        elif t == _TS_STRUCT_SPEC:
            self._visit_struct(node, src, path, parent_id, anonymous=False)
        elif t == _TS_UNION_SPEC:
            self._visit_union(node, src, path, parent_id)
        elif t in (_TS_PREPROC_DEF, _TS_PREPROC_FUNC_DEF):
            self._visit_preproc_def(node, src, path, parent_id)
        elif t in (_TS_PREPROC_IFDEF, _TS_PREPROC_IF):
            # Fix 3: recurse into conditional compilation blocks.
            self._visit_conditional_preproc(node, src, path, parent_id)
        # preproc_include already handled in Pass 1; skip silently.

    # ------------------------------------------------------------------
    # Function definition visitor
    # ------------------------------------------------------------------

    def _visit_function(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit FUNCTION node for a C function_definition."""
        fn_decl = self._first_child(node, _TS_FUNCTION_DECLARATOR)
        if fn_decl is None:
            # May be a pointer-returning function: find inside pointer_declarator.
            ptr_decl = self._first_child(node, _TS_POINTER_DECLARATOR)
            if ptr_decl:
                fn_decl = self._first_child(ptr_decl, _TS_FUNCTION_DECLARATOR)

        fn_name = None
        if fn_decl:
            fn_name = self._child_text(fn_decl, _TS_IDENTIFIER, src)

        if not fn_name:
            fn_name = "<anon_fn>"

        lineno = node.start_point[0] + 1
        fn_id = self._make_id(path, f"{path}::{fn_name}")

        return_type_str = self._extract_type_str(node, src)
        params = self._extract_params(node, src, path, fn_id)
        storage_classes = self._storage_class_specifiers(node, src)
        is_static = "static" in storage_classes
        is_inline = "inline" in storage_classes
        is_variadic = any(p.get("name") == "..." for p in params)

        fn_node = self._make_node(fn_id, NodeType.FUNCTION, fn_name, path, lineno)
        fn_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "return_type_str": return_type_str,
                "is_static": is_static,
                "is_inline": is_inline,
                "is_variadic": is_variadic,
                "calling_convention": "cdecl",
                "params": params,
                "is_declaration_only": self._is_header,
                "included_from": path if self._is_header else None,
            }
        )
        _mark_function_entrypoint(fn_node, fn_name)

        # Mark known-unsafe functions.
        if fn_name in _UNSAFE_C_SINKS:
            fn_node.is_unsafe = True

        self.nodes[fn_id] = fn_node
        self.edges.append(self._edge(parent_id, fn_id, EdgeRelation.CONTAINS))

        # Emit VARIABLE nodes for parameters.
        for p in params:
            if p["name"] in ("", "void", "..."):
                continue
            self._emit_param_node(p, path, fn_id, lineno)

        # Recurse into the function body.
        body = self._first_child(node, _TS_COMPOUND_STMT)
        if body and not self._is_header:
            self._visit_compound(body, src, path, fn_id)

    # ------------------------------------------------------------------
    # Prototype / variable declaration visitor
    # ------------------------------------------------------------------

    def _visit_declaration(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit FUNCTION (prototype) or VARIABLE node for a top-level declaration."""
        # Determine if this is a function prototype.
        fn_decl = self._find_descendant(node, _TS_FUNCTION_DECLARATOR)
        if fn_decl:
            fn_name = self._child_text(fn_decl, _TS_IDENTIFIER, src) or "<proto>"
            fn_id = self._make_id(path, f"{path}::{fn_name}__proto")
            lineno = node.start_point[0] + 1
            return_type_str = self._extract_type_str(node, src)
            params = self._extract_params(node, src, path, fn_id)

            fn_node = self._make_node(fn_id, NodeType.FUNCTION, fn_name, path, lineno)
            fn_node.metadata.update(
                {
                    "language": "c",
                    "translation_unit": self._translation_unit,
                    "return_type_str": return_type_str,
                    "is_static": False,
                    "is_inline": False,
                    "is_variadic": any(p.get("name") == "..." for p in params),
                    "calling_convention": "cdecl",
                    "params": params,
                    "is_declaration_only": True,
                    "included_from": path if self._is_header else None,
                }
            )
            self.nodes[fn_id] = fn_node
            self.edges.append(self._edge(parent_id, fn_id, EdgeRelation.CONTAINS))
            return

        # Otherwise treat as a variable / global declaration.
        # Walk declarator properly: check for pointer_declarator first, then
        # init_declarator, then bare identifier.  Avoid greedy _find_descendant
        # which can pick up identifiers from inside array sizes or comments.
        var_name = None
        ptr_depth_decl = 0

        for child in node.children:
            if child.type == _TS_POINTER_DECLARATOR:
                ptr_depth_decl += 1
                inner = child
                while True:
                    next_ptr = self._first_child(inner, _TS_POINTER_DECLARATOR)
                    if next_ptr:
                        ptr_depth_decl += 1
                        inner = next_ptr
                    else:
                        break
                id_node = self._first_child(inner, _TS_IDENTIFIER)
                if id_node:
                    var_name = self._get_text(src, id_node)
                break
            elif child.type == _TS_INIT_DECLARATOR:
                ptr_dec = self._first_child(child, _TS_POINTER_DECLARATOR)
                if ptr_dec:
                    ptr_depth_decl += 1
                    id_node = self._first_child(ptr_dec, _TS_IDENTIFIER) or self._find_descendant(ptr_dec, _TS_IDENTIFIER)
                else:
                    id_node = self._first_child(child, _TS_IDENTIFIER)
                if id_node:
                    var_name = self._get_text(src, id_node)
                break
            elif child.type == _TS_IDENTIFIER:
                name = self._get_text(src, child)
                # Skip type keywords that are direct children.
                if name and name not in ("const","volatile","static","extern",
                                         "register","inline","auto","unsigned",
                                         "signed","long","short","int","char",
                                         "float","double","void","uint8_t",
                                         "uint16_t","uint32_t","uint64_t",
                                         "size_t","ssize_t"):
                    var_name = name
                    break

        if not var_name:
            return

        type_str = self._extract_type_str(node, src)
        ptr_depth = ptr_depth_decl or len(_RE_POINTER_DEPTH.findall(type_str))
        lineno = node.start_point[0] + 1
        ssa_label = self._ssa.get_versioned_id(var_name)
        var_id = self._make_id(path, f"{path}::global::{ssa_label}")

        var_node = self._make_node(var_id, NodeType.VARIABLE, var_name, path, lineno)
        var_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "c_type_str": type_str,
                "pointer_depth": ptr_depth,
                "is_const": "const" in type_str,
                "is_volatile": "volatile" in type_str,
                "storage_class": self._storage_class(node, src),
                "array_size": None,
                "is_format_string_param": False,
            }
        )
        if ptr_depth > 0:
            var_node.is_unsafe = True
        self.nodes[var_id] = var_node
        self.edges.append(self._edge(parent_id, var_id, EdgeRelation.CONTAINS))
        self._pointer_depth_map[var_name] = ptr_depth

    # ------------------------------------------------------------------
    # typedef visitor
    # ------------------------------------------------------------------

    def _visit_typedef(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit TYPEDEF node and record the alias mapping."""
        lineno = node.start_point[0] + 1

        # Alias name is the last identifier before ';'.
        alias_name = None
        for child in reversed(node.children):
            if child.type == _TS_IDENTIFIER:
                alias_name = self._get_text(src, child)
                break
            if child.type == _TS_TYPE_IDENTIFIER:
                alias_name = self._get_text(src, child)
                break
            # Handle pointer typedef: typedef unsigned char *name;
            if child.type == _TS_POINTER_DECLARATOR:
                inner = self._first_child(child, _TS_IDENTIFIER) or self._first_child(
                    child, _TS_TYPE_IDENTIFIER
                )
                if inner:
                    alias_name = self._get_text(src, inner)
                    break

        if not alias_name:
            return

        # Underlying type is everything between 'typedef' and the alias name.
        underlying = self._extract_typedef_underlying(node, src, alias_name)
        is_fn_ptr = bool(_RE_FUNCTION_PTR.search(self._get_text(src, node)))

        self._typedef_map[alias_name] = underlying

        td_id = self._make_id(path, f"{path}::typedef::{alias_name}")
        td_node = self._make_node(td_id, NodeType.TYPEDEF, alias_name, path, lineno)
        td_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "alias_for": underlying,
                "is_function_pointer": is_fn_ptr,
                "function_ptr_signature": underlying if is_fn_ptr else None,
            }
        )
        self.nodes[td_id] = td_node
        self.edges.append(self._edge(parent_id, td_id, EdgeRelation.CONTAINS))

        # If the typedef wraps a struct, visit it.
        struct = self._first_child(node, _TS_STRUCT_SPEC)
        if struct:
            self._visit_struct(struct, src, path, td_id, anonymous=True)
        union = self._first_child(node, _TS_UNION_SPEC)
        if union:
            self._visit_union(union, src, path, td_id)

    # ------------------------------------------------------------------
    # struct visitor
    # ------------------------------------------------------------------

    def _visit_struct(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        anonymous: bool = False,
    ) -> None:
        """Emit STRUCT node with field layout and FIELD_ACCESS edges."""
        name_node = self._first_child(node, _TS_TYPE_IDENTIFIER)
        struct_name = self._get_text(src, name_node) if name_node else "<anon_struct>"
        lineno = node.start_point[0] + 1
        struct_id = self._make_id(path, f"{path}::struct::{struct_name}")

        fields = self._extract_c_fields(node, src, path, struct_id)
        self._struct_layouts[struct_name] = fields

        is_packed = "__attribute__" in self._get_text(src, node) and "packed" in self._get_text(src, node)

        struct_node = self._make_node(struct_id, NodeType.STRUCT, struct_name, path, lineno)
        struct_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "fields": fields,
                "total_size_bytes": None,      # determined at implementation time
                "alignment_bytes": None,
                "is_packed": is_packed,
                "is_anonymous": anonymous,
            }
        )
        self.nodes[struct_id] = struct_node
        self.edges.append(self._edge(parent_id, struct_id, EdgeRelation.CONTAINS))

    # ------------------------------------------------------------------
    # union visitor
    # ------------------------------------------------------------------

    def _visit_union(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit UNION_TYPE node with field list."""
        name_node = self._first_child(node, _TS_TYPE_IDENTIFIER)
        union_name = self._get_text(src, name_node) if name_node else "<anon_union>"
        lineno = node.start_point[0] + 1
        union_id = self._make_id(path, f"{path}::union::{union_name}")

        fields = self._extract_c_fields(node, src, path, union_id)
        is_anon = name_node is None

        union_node = self._make_node(union_id, NodeType.UNION_TYPE, union_name, path, lineno)
        union_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "fields": fields,
                "is_anonymous": is_anon,
                "total_size_bytes": None,
            }
        )
        self.nodes[union_id] = union_node
        self.edges.append(self._edge(parent_id, union_id, EdgeRelation.CONTAINS))

    # ------------------------------------------------------------------
    # Preprocessor macro pass — directive #2: record & trace expansion
    # ------------------------------------------------------------------

    def _record_macro(self, node, src: str, path: str) -> None:
        """Record a macro definition into ``_macro_registry`` (Pass 1)."""
        is_fn_like = node.type == _TS_PREPROC_FUNC_DEF
        name_node = self._first_child(node, _TS_IDENTIFIER)
        if name_node is None:
            return
        macro_name = self._get_text(src, name_node)
        body_node = self._first_child(node, _TS_PREPROC_ARG)
        body_text = self._get_text(src, body_node).strip() if body_node else ""
        self._macro_registry[macro_name] = {
            "kind": "function_like" if is_fn_like else "object_like",
            "body_text": body_text,
            "defined_in": path,
            "is_function_like": is_fn_like,
        }

    def _record_conditional_macros(self, node, src: str, path: str) -> None:
        """Fix 3: recursively record macro definitions inside #ifdef/#if blocks."""
        for child in node.children:
            if child.type in (_TS_PREPROC_DEF, _TS_PREPROC_FUNC_DEF):
                self._record_macro(child, src, path)
            elif child.type in (_TS_PREPROC_IFDEF, _TS_PREPROC_IF):
                self._record_conditional_macros(child, src, path)

    def _visit_conditional_preproc(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Fix 3: emit nodes for all top-level declarations inside #ifdef/#if blocks.

        The grammar emits child nodes of preproc_ifdef/preproc_if as regular
        translation-unit children interleaved with the preprocessor tokens.
        We walk all children and dispatch any declaration or definition through
        the normal _visit_top_level path, marking them is_conditional=True in
        their metadata so downstream passes know they are conditionally compiled.
        """
        for child in node.children:
            t = child.type
            # Recurse into nested conditional blocks.
            if t in (_TS_PREPROC_IFDEF, _TS_PREPROC_IF):
                self._visit_conditional_preproc(child, src, path, parent_id)
            elif t in (
                _TS_FUNCTION_DEF, _TS_FUNCTION_DECL,
                _TS_TYPE_DEF, _TS_STRUCT_SPEC, _TS_UNION_SPEC,
                _TS_PREPROC_DEF, _TS_PREPROC_FUNC_DEF,
            ):
                self._visit_top_level(child, src, path, parent_id)
                # Stamp is_conditional onto the last-emitted node.
                if self.nodes:
                    last_nid = list(self.nodes.keys())[-1]
                    self.nodes[last_nid].metadata["is_conditional"] = True

    def _visit_preproc_def(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit MACRO_EXPANSION node and trace into expanded token text.

        Override directive #2: the macro body text is scanned for identifiers
        that match known function names or variables. Each match receives a
        DATA or FUNCTION node and a ``MACRO_EXPANDS_TO`` edge, so that the
        taint graph reflects expansion prior to the S1 semantic pass.
        """
        name_node = self._first_child(node, _TS_IDENTIFIER)
        if name_node is None:
            return

        macro_name = self._get_text(src, name_node)
        macro_info = self._macro_registry.get(macro_name, {})
        body_text = macro_info.get("body_text", "")
        is_fn_like = macro_info.get("is_function_like", False)
        lineno = node.start_point[0] + 1

        is_conditional = False  # set True if inside preproc_ifdef (handled by parent walk)
        is_unsafe_expansion = any(
            keyword in body_text.lower()
            for keyword in ("strcpy", "gets", "sprintf", "system", "exec", "memcpy", "ptr", "unsafe")
        )

        m_id = self._make_id(path, f"{path}::macro::{macro_name}:{lineno}")
        m_node = self._make_node(m_id, NodeType.MACRO_EXPANSION, macro_name, path, lineno)
        m_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "macro_name": macro_name,
                "macro_kind": "function_like" if is_fn_like else "object_like",
                "expansion_text": body_text or None,
                "is_conditional": is_conditional,
                "defined_in_header": path if self._is_header else None,
                "is_unsafe_expansion": is_unsafe_expansion,
            }
        )
        if is_unsafe_expansion:
            m_node.is_unsafe = True

        self.nodes[m_id] = m_node
        self.edges.append(self._edge(parent_id, m_id, EdgeRelation.CONTAINS))

        # Trace into expanded AST: tokenize body_text and emit expansion edges.
        # We use a simple word-boundary tokenizer since the preprocessor has
        # already stripped comments and continued lines.
        if body_text:
            seen_tokens: Set[str] = set()
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body_text):
                if token in seen_tokens or token == macro_name:
                    continue
                seen_tokens.add(token)

                exp_id = self._make_id(path, f"__macro_exp__{macro_name}::{token}")
                if exp_id not in self.nodes:
                    # Classify: is it a known function or a data token?
                    ntype = NodeType.FUNCTION if token in _UNSAFE_C_SINKS or token in _FORMAT_STRING_SINKS else NodeType.DATA
                    exp_node = self._make_node(exp_id, ntype, token, path, lineno)
                    exp_node.metadata.update(
                        {
                            "language": "c",
                            "macro_origin": macro_name,
                            "synthetic": True,
                        }
                    )
                    if token in _UNSAFE_C_SINKS:
                        exp_node.is_unsafe = True
                    self.nodes[exp_id] = exp_node

                self.edges.append(
                    self._edge(
                        m_id,
                        exp_id,
                        EdgeRelation.MACRO_EXPANDS_TO,
                        {
                            "macro_name": macro_name,
                            "expansion_kind": "function_like" if is_fn_like else "object_like",
                        },
                    )
                )
                # If the expanded token is a call, also emit a CALLS edge from the
                # macro node so the taint analyser can traverse it.
                if token in _UNSAFE_C_SINKS or token in _FORMAT_STRING_SINKS:
                    self.edges.append(
                        self._edge(
                            m_id,
                            exp_id,
                            EdgeRelation.CALLS,
                            {"call_name": token, "via_macro": macro_name},
                        )
                    )

    # ------------------------------------------------------------------
    # #include visitor
    # ------------------------------------------------------------------

    def _visit_include(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit IMPORT node for a #include directive."""
        include_text = self._get_text(src, node)
        # Extract path from <path> or "path".
        m = re.search(r'[<"]([^>"]+)[>"]', include_text)
        header = m.group(1) if m else include_text.strip()
        lineno = node.start_point[0] + 1

        imp_id = self._make_id(path, f"__include__{header}")
        if imp_id not in self.nodes:
            imp_node = self._make_node(imp_id, NodeType.IMPORT, header, path, lineno)
            imp_node.metadata.update(
                {
                    "language": "c",
                    "import_module": header,
                    "import_name": os.path.basename(header),
                    "system_header": include_text.strip().startswith("<"),
                }
            )
            self.nodes[imp_id] = imp_node
        self.edges.append(self._edge(parent_id, imp_id, EdgeRelation.IMPORTS))

    # ------------------------------------------------------------------
    # Compound statement (body) visitor
    # ------------------------------------------------------------------

    def _visit_compound(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Walk a compound_statement and emit edges for its contents.

        Recursion fix
        -------------
        The original implementation only called ``_first_child`` to find a
        single ``compound_statement`` inside control-flow nodes, missing all
        expression statements nested deeper than one level.  The fix walks
        ALL children of control-flow nodes recursively via a helper so that
        patterns like ``for → compound → if → compound → expr_stmt`` are
        fully traversed.
        """
        for child in node.children:
            t = child.type
            if t == _TS_FUNCTION_DECL:
                # Local variable declaration inside a function body.
                self._visit_local_decl(child, src, path, parent_id)
            elif t == _TS_EXPRESSION_STMT:
                inner = child.children[0] if child.children else child
                self._visit_expr(inner, src, path, parent_id)
            elif t == _TS_RETURN_STMT:
                self._visit_return(child, src, path, parent_id)
            elif t in (_TS_IF_STMT, _TS_FOR_STMT, _TS_WHILE_STMT, _TS_DO_STMT):
                # Recurse into ALL nested compound statements inside this
                # control-flow node (handles else branches, for-loop bodies, etc.)
                self._recurse_control_flow(child, src, path, parent_id)
            elif t == "switch_statement":
                # Gap #11: switch statements.
                self._recurse_control_flow(child, src, path, parent_id)
            elif t == _TS_COMPOUND_STMT:
                self._visit_compound(child, src, path, parent_id)
            # Comments, labels, etc. are silently skipped.

    def _recurse_control_flow(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Recursively walk all compound_statement and expression_statement
        children of a control-flow node (if/for/while/do/switch).

        This replaces the old _first_child approach which stopped at the
        first compound and missed nested expression statements.
        """
        for child in node.children:
            t = child.type
            if t == _TS_COMPOUND_STMT:
                self._visit_compound(child, src, path, parent_id)
            elif t in (_TS_IF_STMT, _TS_FOR_STMT, _TS_WHILE_STMT,
                       _TS_DO_STMT, "switch_statement"):
                self._recurse_control_flow(child, src, path, parent_id)
            elif t == _TS_EXPRESSION_STMT:
                inner = child.children[0] if child.children else child
                self._visit_expr(inner, src, path, parent_id)
            elif t == _TS_RETURN_STMT:
                self._visit_return(child, src, path, parent_id)
            elif t == _TS_FUNCTION_DECL:
                self._visit_local_decl(child, src, path, parent_id)
            # case_statement, default_statement (switch bodies)
            elif t in ("case_statement", "default_statement"):
                self._recurse_control_flow(child, src, path, parent_id)

    # ------------------------------------------------------------------
    # Local declaration visitor
    # ------------------------------------------------------------------

    def _visit_local_decl(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit VARIABLE node for a local variable declaration.

        Root-cause fix
        --------------
        The original child loop incorrectly used ``_TS_IDENTIFIER`` as a
        catch-all for both type-specifier identifiers and declarator names,
        producing garbage ``var_name`` strings and a broken
        ``_pointer_depth_map``.  The fix walks each declarator child
        explicitly, distinguishing ``pointer_declarator`` from plain
        ``identifier`` declarators and reading the name from the innermost
        identifier in both cases.
        """
        # Skip function prototypes inside function bodies.
        if self._find_descendant(node, _TS_FUNCTION_DECLARATOR):
            return

        type_str = self._extract_type_str(node, src)
        lineno = node.start_point[0] + 1

        # Collect all (var_name, ptr_depth, child_node) tuples from declarators.
        declarators: list = []
        for child in node.children:
            if child.type == _TS_INIT_DECLARATOR:
                # init_declarator: pointer_declarator or identifier
                inner = child
                ptr_depth = 0
                while inner.type == _TS_POINTER_DECLARATOR:
                    ptr_depth += 1
                    inner = self._first_child(inner, _TS_POINTER_DECLARATOR) or \
                             self._first_child(inner, _TS_IDENTIFIER) or inner
                    break  # one level is enough; re-walk below
                # Re-walk properly.
                ptr_depth = 0
                declarator_node = self._first_child(child, _TS_POINTER_DECLARATOR)
                if declarator_node:
                    # Count pointer nesting and find the identifier.
                    cur = declarator_node
                    while cur.type == _TS_POINTER_DECLARATOR:
                        ptr_depth += 1
                        next_ptr = self._first_child(cur, _TS_POINTER_DECLARATOR)
                        if next_ptr:
                            cur = next_ptr
                        else:
                            break
                    id_node = self._first_child(cur, _TS_IDENTIFIER)
                else:
                    declarator_node = self._first_child(child, _TS_IDENTIFIER)
                    id_node = declarator_node
                    ptr_depth += len(_RE_POINTER_DEPTH.findall(type_str))

                if id_node:
                    declarators.append((self._get_text(src, id_node), ptr_depth, child))

            elif child.type == _TS_POINTER_DECLARATOR:
                # Bare pointer declarator (no initialiser).
                cur = child
                ptr_depth = 0
                while cur.type == _TS_POINTER_DECLARATOR:
                    ptr_depth += 1
                    next_ptr = self._first_child(cur, _TS_POINTER_DECLARATOR)
                    if next_ptr:
                        cur = next_ptr
                    else:
                        break
                id_node = self._first_child(cur, _TS_IDENTIFIER)
                if id_node:
                    declarators.append((self._get_text(src, id_node), ptr_depth, child))

            elif child.type == _TS_IDENTIFIER:
                # Plain non-pointer declarator.
                # Skip type-specifier keywords that appear as identifier children.
                name = self._get_text(src, child)
                if name and name not in ("const", "volatile", "static", "register",
                                         "inline", "extern", "auto", "unsigned",
                                         "signed", "long", "short", "int", "char",
                                         "float", "double", "void", "uint8_t",
                                         "uint16_t", "uint32_t", "uint64_t",
                                         "int8_t", "int16_t", "int32_t", "int64_t",
                                         "size_t", "ssize_t"):
                    declarators.append((name, len(_RE_POINTER_DEPTH.findall(type_str)), child))

        for var_name, ptr_depth, decl_child in declarators:
            if not var_name:
                continue

            ssa_label = self._ssa.get_versioned_id(var_name)
            var_id = self._make_id(path, f"{parent_id}::local::{ssa_label}:{lineno}")

            # RHS taint check.
            rhs_text = ""
            if decl_child.type == _TS_INIT_DECLARATOR:
                for c in decl_child.children:
                    if c.type not in ("=", _TS_IDENTIFIER, _TS_POINTER_DECLARATOR,
                                      "(", ")", _TS_NUMBER_LITERAL):
                        rhs_text = self._get_text(src, c)
                        break

            is_taint_source = any(
                s in rhs_text for s in self.config.to_taint_config().sources
            ) if rhs_text else False

            var_node = self._make_node(var_id, NodeType.VARIABLE, var_name, path, lineno)
            var_node.metadata.update(
                {
                    "language": "c",
                    "translation_unit": self._translation_unit,
                    "c_type_str": type_str,
                    "pointer_depth": ptr_depth,
                    "is_const": "const" in type_str,
                    "is_volatile": "volatile" in type_str,
                    "storage_class": self._storage_class(node, src),
                    "array_size": self._extract_array_size(node, src),
                    "is_format_string_param": False,
                    "ssa_label": ssa_label,
                }
            )
            if ptr_depth > 0 or is_taint_source:
                var_node.is_unsafe = True

            self.nodes[var_id] = var_node
            self.edges.append(
                self._edge(
                    parent_id,
                    var_id,
                    EdgeRelation.DATAFLOW,
                    {"flow_kind": "local_decl", "ssa_label": ssa_label},
                )
            )
            # Correctly record pointer depth for pointer-arithmetic detection.
            self._pointer_depth_map[var_name] = ptr_depth
            if is_taint_source:
                self.edges.append(
                    self._edge(
                        var_id,
                        parent_id,
                        EdgeRelation.DATAFLOW,
                        {"flow_kind": "taint_source_var", "ssa_label": ssa_label},
                    )
                )

    # ------------------------------------------------------------------
    # Expression visitor
    # ------------------------------------------------------------------

    def _visit_expr(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Route expression nodes to specialized sub-visitors.

        Fix 3
        -----
        ``assignment_expression`` nodes with operators ``+=`` or ``-=`` are
        now forwarded to ``_visit_binary`` because the C tree-sitter grammar
        represents ``buf_ptr += i`` as an assignment_expression (not a
        binary_expression), so the old code silently skipped all compound-
        assignment pointer arithmetic.

        Gap #7 fix
        ----------
        ``unary_expression`` with ``*`` operator is recursed into to catch
        ``*p++`` and ``*ctx->overflow_ptr`` dereference patterns.
        """
        t = node.type
        if t == _TS_CALL_EXPR:
            self._visit_call(node, src, path, parent_id)
        elif t == _TS_ASSIGNMENT_EXPR:
            # Fix 3: intercept compound-assignment operators for pointer arith.
            op_node = node.children[1] if len(node.children) > 1 else None
            op_text = self._get_text(src, op_node) if op_node else ""
            if op_text in ("+=", "-="):
                # Re-use _visit_binary: it expects [lhs, op, rhs] structure.
                # assignment_expression has the same child layout.
                self._visit_binary(node, src, path, parent_id)
            # Walk RHS for nested calls and pointer arithmetic regardless.
            for child in node.children:
                if child.type not in (_TS_IDENTIFIER, "=", "+=", "-=", ","):
                    self._visit_expr(child, src, path, parent_id)
        elif t == _TS_POINTER_EXPR:
            self._visit_pointer_deref(node, src, path, parent_id)
        elif t == _TS_UNARY_EXPR:
            # Gap #7: catch *p++ and similar patterns.
            text = self._get_text(src, node)
            if text.startswith("*"):
                self._visit_pointer_deref(node, src, path, parent_id)
            # Recurse into the operand for nested calls.
            for child in node.children:
                if child.type not in ("*", "!", "~", "-", "+", "&"):
                    self._visit_expr(child, src, path, parent_id)
        elif t == _TS_BINARY_EXPR:
            self._visit_binary(node, src, path, parent_id)
        elif t in (_TS_CAST_EXPR, _TS_COND_EXPR):
            for child in node.children:
                self._visit_expr(child, src, path, parent_id)


    # ------------------------------------------------------------------
    # Call expression visitor
    # ------------------------------------------------------------------

    def _visit_call(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit CALLS edge for a C function call expression."""
        fn_node_ts = node.children[0] if node.children else None
        if fn_node_ts is None:
            return
        callee = self._get_text(src, fn_node_ts)
        lineno = node.start_point[0] + 1

        callee_id = self._make_id(path, f"__call_target__{callee}")
        if callee_id not in self.nodes:
            ct_node = self._make_node(callee_id, NodeType.FUNCTION, callee, path, lineno)
            ct_node.metadata.update(
                {
                    "language": "c",
                    "synthetic": True,
                    "is_format_string_sink": callee in _FORMAT_STRING_SINKS,
                }
            )
            if callee in _UNSAFE_C_SINKS:
                ct_node.is_unsafe = True
            self.nodes[callee_id] = ct_node

        self.edges.append(
            self._edge(
                parent_id,
                callee_id,
                EdgeRelation.CALLS,
                {
                    "call_name": callee,
                    "is_format_string_sink": callee in _FORMAT_STRING_SINKS,
                    "lineno": lineno,
                },
            )
        )

        # Check if this call site expands a tracked macro.
        if callee in self._macro_registry:
            macro_id = self._make_id(path, f"{path}::macro::{callee}:")
            # Best-effort: link call site to the macro's MACRO_EXPANSION node
            # if it was already emitted.
            if macro_id in self.nodes:
                self.edges.append(
                    self._edge(
                        parent_id,
                        macro_id,
                        EdgeRelation.MACRO_EXPANDS_TO,
                        {"call_site_line": lineno, "macro_name": callee},
                    )
                )

        # DATAFLOW edges for arguments that are known taint sources.
        args = self._first_child(node, _TS_ARGUMENT_LIST)
        if args:
            for i, arg in enumerate(args.children):
                if arg.type in (",", "(", ")"):
                    continue
                arg_text = self._get_text(src, arg)
                if any(s in arg_text for s in self.config.to_taint_config().sources):
                    self.edges.append(
                        self._edge(
                            parent_id,
                            callee_id,
                            EdgeRelation.DATAFLOW,
                            {"flow_kind": "call_argument", "arg_index": i, "arg_text": arg_text[:128]},
                        )
                    )

    # ------------------------------------------------------------------
    # Pointer dereference visitor
    # ------------------------------------------------------------------

    def _visit_pointer_deref(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit UNSAFE_DEREFERENCE edge for a pointer dereference expression."""
        deref_text = self._get_text(src, node)
        lineno = node.start_point[0] + 1
        deref_id = self._make_id(path, f"{parent_id}::deref:{lineno}:{node.start_point[1]}")

        if deref_id not in self.nodes:
            d_node = self._make_node(deref_id, NodeType.DATA, deref_text[:64], path, lineno)
            d_node.is_unsafe = True
            d_node.metadata.update(
                {
                    "language": "c",
                    "unsafe_reason": "unchecked_ptr_arith",
                }
            )
            self.nodes[deref_id] = d_node

        self.edges.append(
            self._edge(
                parent_id,
                deref_id,
                EdgeRelation.UNSAFE_DEREFERENCE,
                {"deref_text": deref_text[:128]},
            )
        )

    # ------------------------------------------------------------------
    # Binary expression visitor (pointer arithmetic detection)
    # ------------------------------------------------------------------

    def _visit_binary(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Detect pointer arithmetic and emit POINTER_ARITH edges.

        Fix 5: also catches cast-chain patterns such as ``(char*)ptr + n``
        where the LHS is a cast_expression containing a pointer type.
        The original heuristic (LHS name in _pointer_depth_map) is retained
        as a fast-path; cast detection is the new slow-path.
        """
        children = [c for c in node.children if c.type not in (",",)]
        if len(children) < 3:
            return

        lhs, op, rhs = children[0], children[1], children[2]
        op_text = self._get_text(src, op)
        if op_text not in ("+", "-", "+=", "-="):
            return

        lhs_text = self._get_text(src, lhs)

        # Fast-path: tracked local pointer variable.
        is_ptr_arith = self._pointer_depth_map.get(lhs_text, 0) > 0

        # Fix 5: slow-path — LHS is a cast_expression whose type contains '*'.
        if not is_ptr_arith and lhs.type == _TS_CAST_EXPR:
            cast_text = lhs_text
            is_ptr_arith = "*" in cast_text or "ptr" in cast_text.lower()

        # Also handle subscript or field access as pointer origin.
        if not is_ptr_arith and lhs.type in (_TS_SUBSCRIPT_EXPR,):
            is_ptr_arith = True

        if not is_ptr_arith:
            return

        lineno = node.start_point[0] + 1
        derived_text = self._get_text(src, node)[:64]
        derived_id = self._make_id(path, f"{parent_id}::ptr_arith:{lineno}:{node.start_point[1]}")

        if derived_id not in self.nodes:
            d_node = self._make_node(derived_id, NodeType.DATA, derived_text, path, lineno)
            d_node.is_unsafe = True
            d_node.metadata.update(
                {
                    "language": "c",
                    "unsafe_reason": "unchecked_ptr_arith",
                    "base_var": lhs_text[:64],
                    "operand": op_text,
                }
            )
            self.nodes[derived_id] = d_node

        self.edges.append(
            self._edge(
                parent_id,
                derived_id,
                EdgeRelation.POINTER_ARITH,
                {"base_var": lhs_text[:64], "operator": op_text, "lineno": lineno},
            )
        )

    # ------------------------------------------------------------------
    # Return statement visitor
    # ------------------------------------------------------------------

    def _visit_return(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit RETURNS edge for a return statement and visit the returned value."""
        ret_text = self._get_text(src, node)[:64]
        ret_id = self._make_id(path, f"{parent_id}::return:{node.start_point[0]+1}")
        if ret_id not in self.nodes:
            r_node = self._make_node(
                ret_id, NodeType.DATA, ret_text, path, node.start_point[0] + 1
            )
            r_node.metadata["language"] = "c"
            self.nodes[ret_id] = r_node
        self.edges.append(self._edge(parent_id, ret_id, EdgeRelation.RETURNS))

        # The returned expression can hold calls, dereferences and pointer
        # arithmetic. Without this recursion a call in tail position is invisible
        # to the call graph -- e.g. `return getenv(name);` is a taint source that
        # would never be linked to its caller.
        for child in node.children:
            if child.type in ("return", ";"):
                continue
            self._visit_expr(child, src, path, parent_id)

    # ------------------------------------------------------------------
    # Struct / union field helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _declared_member_name(field_node, src: str) -> Optional[str]:
        """Return the declared member name from a ``field_declaration``.

        Only scalar members expose the identifier as a direct child. Arrays nest
        it under ``array_declarator``, pointers under ``pointer_declarator``, and
        function pointers deeper still, so a direct-children scan silently drops
        exactly the security-relevant members: fixed-size buffers (overflow
        targets), PII buffers, and raw pointers.

        ``field_identifier`` is searched first so that a function-pointer member's
        parameter names cannot be mistaken for the member itself.
        """
        ident = CParser._find_descendant(field_node, _TS_FIELD_IDENTIFIER)
        if ident is None:
            ident = CParser._find_descendant(field_node, _TS_IDENTIFIER)
        return CParser._get_text(src, ident) if ident is not None else None

    def _extract_c_fields(
        self,
        node,
        src: str,
        path: str,
        aggregate_id: str,
    ) -> List[Dict[str, Any]]:
        """Extract ordered field list and emit FIELD_ACCESS edges."""
        fields: List[Dict[str, Any]] = []
        fdl = self._first_child(node, _TS_FIELD_DECL_LIST)
        if fdl is None:
            return fields

        for child in fdl.children:
            if child.type != _TS_FIELD_DECL:
                continue
            fname = self._declared_member_name(child, src)

            if not fname:
                continue

            type_str = self._extract_type_str(child, src)
            bit_width = self._extract_bit_width(child, src)
            ptr_depth = len(_RE_POINTER_DEPTH.findall(type_str))

            fields.append(
                {
                    "name": fname,
                    "type_str": type_str,
                    "bit_width": bit_width,
                    "offset_bytes": None,
                    "pointer_depth": ptr_depth,
                }
            )

            field_id = self._make_id(path, f"{aggregate_id}::field::{fname}")
            if field_id not in self.nodes:
                fv_node = self._make_node(
                    field_id,
                    NodeType.VARIABLE,
                    fname,
                    path,
                    child.start_point[0] + 1,
                )
                fv_node.metadata.update(
                    {
                        "language": "c",
                        "c_type_str": type_str,
                        "pointer_depth": ptr_depth,
                        "bit_width": bit_width,
                    }
                )
                if ptr_depth > 0:
                    fv_node.is_unsafe = True
                self.nodes[field_id] = fv_node

            self.edges.append(
                self._edge(
                    aggregate_id,
                    field_id,
                    EdgeRelation.FIELD_ACCESS,
                    {"field_name": fname, "type_str": type_str},
                )
            )
        return fields

    # ------------------------------------------------------------------
    # Parameter helpers
    # ------------------------------------------------------------------

    def _extract_params(
        self,
        fn_node,
        src: str,
        path: str,
        fn_id: str,
    ) -> List[Dict[str, Any]]:
        """Return ordered parameter list from a function's parameter_list."""
        params: List[Dict[str, Any]] = []
        param_list = self._find_descendant(fn_node, _TS_PARAMETER_LIST)
        if param_list is None:
            return params

        for child in param_list.children:
            if child.type != _TS_PARAMETER_DECL:
                if child.type == "...":
                    params.append({"name": "...", "type_str": "...", "is_pointer": False, "pointer_depth": 0})
                continue

            type_str = self._extract_type_str(child, src)

            # Extract name from declarator: prefer pointer_declarator chain.
            ptr_depth = 0
            name_node = None
            ptr_dec = self._first_child(child, _TS_POINTER_DECLARATOR)
            if ptr_dec:
                cur = ptr_dec
                while cur.type == _TS_POINTER_DECLARATOR:
                    ptr_depth += 1
                    next_ptr = self._first_child(cur, _TS_POINTER_DECLARATOR)
                    if next_ptr:
                        cur = next_ptr
                    else:
                        break
                name_node = self._first_child(cur, _TS_IDENTIFIER)
            else:
                # Plain identifier declarator (e.g. 'int n').
                # Walk children of parameter_declaration: skip type specifiers,
                # take the first plain identifier that is not a keyword.
                for pc in child.children:
                    if pc.type == _TS_IDENTIFIER:
                        candidate = self._get_text(src, pc)
                        if candidate and candidate not in (
                            "const", "volatile", "unsigned", "signed", "long",
                            "short", "int", "char", "float", "double", "void",
                            "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                            "size_t", "ssize_t",
                        ):
                            name_node = pc
                            break
                    elif pc.type in ("type_identifier", "primitive_type"):
                        continue  # skip type name
                # Also fall back to _find_descendant but only for non-type-specifier nodes.
                if name_node is None:
                    name_node = self._first_child(child, _TS_IDENTIFIER)

            pname = self._get_text(src, name_node) if name_node else ""
            if not ptr_depth:
                ptr_depth = len(_RE_POINTER_DEPTH.findall(type_str))
            is_fmt = bool(_RE_FORMAT_FN.search(pname.lower())) or pname.lower() in ("fmt", "format", "msg")

            params.append(
                {
                    "name": pname,
                    "type_str": type_str,
                    "is_pointer": ptr_depth > 0,
                    "pointer_depth": ptr_depth,
                    "is_format_string_param": is_fmt,
                }
            )
        return params

    def _emit_param_node(
        self,
        param: Dict[str, Any],
        path: str,
        fn_id: str,
        lineno: int,
    ) -> None:
        """Emit a VARIABLE node for a function parameter and a DATAFLOW edge."""
        pname = param["name"]
        ssa_label = self._ssa.get_versioned_id(pname)
        var_id = self._make_id(path, f"{fn_id}::param::{ssa_label}")

        var_node = self._make_node(var_id, NodeType.VARIABLE, pname, path, lineno)
        var_node.metadata.update(
            {
                "language": "c",
                "translation_unit": self._translation_unit,
                "c_type_str": param["type_str"],
                "pointer_depth": param["pointer_depth"],
                "is_const": "const" in param["type_str"],
                "is_volatile": "volatile" in param["type_str"],
                "storage_class": "auto",
                "array_size": None,
                "is_format_string_param": param.get("is_format_string_param", False),
                "flow_kind": "parameter",
                "ssa_label": ssa_label,
            }
        )
        if param["pointer_depth"] > 0:
            var_node.is_unsafe = True

        self.nodes[var_id] = var_node
        self.edges.append(
            self._edge(
                fn_id,
                var_id,
                EdgeRelation.DATAFLOW,
                {"flow_kind": "parameter", "ssa_label": ssa_label},
            )
        )
        self._pointer_depth_map[pname] = param["pointer_depth"]

    # ------------------------------------------------------------------
    # Type extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_type_str(node, src: str) -> str:
        """Extract the C type string from a declaration node (best-effort)."""
        parts: List[str] = []
        for child in node.children:
            if child.type in (
                _TS_PRIMITIVE_TYPE, _TS_TYPE_IDENTIFIER, _TS_SIZED_TYPE_SPEC,
                _TS_STRUCT_SPEC, _TS_UNION_SPEC, _TS_ENUM_SPEC,
                "const", "volatile", "static", "extern", "register", "inline",
                "signed", "unsigned", "long", "short",
            ):
                parts.append(CParser._get_text(src, child))
            elif child.type == _TS_POINTER_DECLARATOR:
                parts.append("*")
        return " ".join(parts).strip()

    @staticmethod
    def _extract_typedef_underlying(node, src: str, alias_name: str) -> str:
        """Extract the underlying type from a typedef node."""
        text = CParser._get_text(src, node)
        # Remove 'typedef' and alias_name, collapse whitespace.
        text = re.sub(r"\btypedef\b", "", text)
        text = re.sub(r"\b" + re.escape(alias_name) + r"\b", "", text)
        return re.sub(r"\s+", " ", text).strip(" ;")

    @staticmethod
    def _extract_bit_width(node, src: str) -> Optional[int]:
        """Return the bit-field width integer if present (``int x : 4``), else None."""
        found_colon = False
        for child in node.children:
            if child.type == ":" and not found_colon:
                found_colon = True
                continue
            if found_colon and child.type == _TS_NUMBER_LITERAL:
                try:
                    return int(CParser._get_text(src, child))
                except ValueError:
                    return None
        return None

    @staticmethod
    def _extract_array_size(node, src: str) -> Optional[int]:
        """Return integer array size from ``char buf[N]`` if deterministic, else None."""
        for child in node.children:
            if child.type == "array_declarator":
                for c in child.children:
                    if c.type == _TS_NUMBER_LITERAL:
                        try:
                            return int(CParser._get_text(src, c))
                        except ValueError:
                            return None
        return None

    @staticmethod
    def _storage_class(node, src: str) -> str:
        """Return the C storage class specifier or 'none'."""
        for child in node.children:
            if child.type in ("static", "extern", "register", "auto"):
                return CParser._get_text(src, child)
            if child.type == "storage_class_specifier":
                return CParser._get_text(src, child).strip()
        return "none"

    @staticmethod
    def _storage_class_specifiers(node, src: str) -> Set[str]:
        """Return every storage-class keyword attached to a declaration.

        ``static`` / ``inline`` / ``extern`` are ``storage_class_specifier``
        CHILDREN of the definition, so they sit inside the node's own span and are
        invisible to anything inspecting the preceding source text. ``static
        inline`` produces two separate specifiers, so all of them are collected
        rather than just the first.
        """
        found: Set[str] = set()
        for child in node.children:
            if child.type == "storage_class_specifier":
                found.add(CParser._get_text(src, child).strip())
            elif child.type in ("static", "extern", "register", "auto", "inline"):
                found.add(child.type)
        return found

    # ------------------------------------------------------------------
    # Tree-sitter traversal utilities (mirrors RustParser's helpers)
    # ------------------------------------------------------------------

    @staticmethod
    def _first_child(node, type_name: str):
        """Return the first direct child whose .type == type_name, or None."""
        for c in node.children:
            if c.type == type_name:
                return c
        return None

    @staticmethod
    def _child_text(node, type_name: str, src: str) -> Optional[str]:
        """Return the source text of the first child with the given type, or None."""
        for c in node.children:
            if c.type == type_name:
                return CParser._get_text(src, c)
        return None

    @staticmethod
    def _find_descendant(node, type_name: str):
        """Return the first descendant (BFS) whose .type == type_name, or None."""
        queue = list(node.children)
        while queue:
            current = queue.pop(0)
            if current.type == type_name:
                return current
            queue.extend(current.children)
        return None

    @staticmethod
    def _iter_descendants(node):
        """Yield all descendant nodes via iterative DFS."""
        stack = list(node.children)
        while stack:
            current = stack.pop()
            yield current
            stack.extend(current.children)


# ---------------------------------------------------------------------------
# Plugin self-registration — fires on import.
# ---------------------------------------------------------------------------
register_parser(CParser)
