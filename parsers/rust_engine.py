"""Rust language parser — tree-sitter backed, IR v0.3.0.

Architecture contract
---------------------
* Extends ``TreeSitterParser`` — tree-sitter is **required** (no regex fallback).
* Raises ``RuntimeError`` at construction time if the tree-sitter runtime or the
  Rust grammar are unavailable, preventing silent no-op parses.
* Populates ``self.nodes`` and ``self.edges`` exclusively via the base-class
  helpers ``_make_node()`` and ``_edge()`` so that GraphMerger / SymbolResolver
  remain unchanged.
* All Rust-specific data is encoded inside ``Node.metadata`` and ``Edge.metadata``
  under the schemas defined in the integration blueprint (IR v0.3.0 §2.1.3).
* Macro expansions are traced directly into their expanded AST subtrees prior
  to semantic evaluation (S1 seam), satisfying override directive #2.

Override directives applied
---------------------------
1. Translation-unit precedence: ``supports()`` returns ``True`` for ``.rs`` only.
2. Macro AST tracing: ``_visit_macro_invocation()`` walks the expanded token tree
   and emits ``MACRO_EXPANDS_TO`` edges to every top-level expanded statement node.
3. Tree-sitter binding: grammar loaded via ``tree_sitter_language_pack`` using the
   existing ``resolve_tree_sitter_language()`` dispatcher in engines.py.

Registration
------------
The module-level ``register_parser(RustParser)`` call at the bottom fires on
import, injecting the class into ``PARSER_PLUGINS``. During Phase 3 it will also
be added to the hard-coded list in ``iter_parser_classes()``.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Set, Tuple

from analyzers.symbols import SSAVersionTracker, make_node_id
from models import AnalysisOptions, EdgeRelation, NodeType, SecurityConfig
from parsers.engines import TREE_SITTER_AVAILABLE, TreeSitterParser, _mark_function_entrypoint
from parsers.registry import register_parser

# ---------------------------------------------------------------------------
# Guard: tree-sitter is mandatory for this parser.
# ---------------------------------------------------------------------------
if not TREE_SITTER_AVAILABLE:
    raise ImportError(
        "RustParser requires the tree-sitter runtime. "
        "Install it with:  pip install tree-sitter tree-sitter-language-pack"
    )


# ---------------------------------------------------------------------------
# Tree-sitter node-type constants for the Rust grammar (grammar version 15).
# These are the string values emitted by the Rust grammar's node.type field.
# ---------------------------------------------------------------------------
_TS_SOURCE_FILE = "source_file"
_TS_USE_DECL = "use_declaration"
_TS_FUNCTION_ITEM = "function_item"
_TS_FUNCTION_SIGNATURE = "function_signature_item"   # trait method prototypes
_TS_IMPL_ITEM = "impl_item"
_TS_STRUCT_ITEM = "struct_item"
_TS_ENUM_ITEM = "enum_item"
_TS_TRAIT_ITEM = "trait_item"
_TS_MACRO_DEF = "macro_definition"
_TS_MACRO_INVOCATION = "macro_invocation"
_TS_UNSAFE_BLOCK = "unsafe_block"
_TS_BLOCK = "block"
_TS_IDENTIFIER = "identifier"
_TS_TYPE_IDENTIFIER = "type_identifier"
_TS_VISIBILITY = "visibility_modifier"
_TS_PARAMETERS = "parameters"
_TS_PARAMETER = "parameter"
_TS_LIFETIME = "lifetime"
_TS_LIFETIME_PARAM = "lifetime_parameter"
_TS_TYPE_PARAMS = "type_parameters"
_TS_REFERENCE_TYPE = "reference_type"
_TS_RAW_PTR_TYPE = "raw_pointer_type"
_TS_FIELD_DECL_LIST = "field_declaration_list"
_TS_FIELD_DECL = "field_declaration"
_TS_FIELD_IDENTIFIER = "field_identifier"
_TS_LET_DECL = "let_declaration"
_TS_CALL_EXPR = "call_expression"
_TS_METHOD_CALL = "method_call_expression"
_TS_SCOPED_ID = "scoped_identifier"
_TS_RETURN_EXPR = "return_expression"
_TS_UNARY_EXPR = "unary_expression"       # covers dereference: *ptr
_TS_BINARY_EXPR = "binary_expression"
_TS_ASSIGNMENT_EXPR = "assignment_expression"
_TS_WHERE_CLAUSE = "where_clause"
_TS_EXTERN_CRATE = "extern_crate_declaration"
_TS_MOD_ITEM = "mod_item"
_TS_ATTR_ITEM = "attribute_item"
_TS_DERIVE_ATTR = "derive"
_TS_TOKEN_TREE = "token_tree"
_TS_DECLARATION_LIST = "declaration_list"
_TS_PRIMITIVE_TYPE = "primitive_type"
_TS_GENERIC_TYPE = "generic_type"
_TS_REPR_ATTR = "repr"
_TS_UNSAFE_MOD = "unsafe"
_TS_FUNCTION_MODIFIERS = "function_modifiers"
# Control-flow expression node types (Fix 1)
_TS_IF_EXPR       = "if_expression"
_TS_MATCH_EXPR    = "match_expression"
_TS_MATCH_BLOCK   = "match_block"
_TS_MATCH_ARM     = "match_arm"
_TS_LOOP_EXPR     = "loop_expression"
_TS_WHILE_EXPR    = "while_expression"
_TS_FOR_EXPR      = "for_expression"
_TS_CLOSURE_EXPR  = "closure_expression"
_TS_ELSE_CLAUSE   = "else_clause"
_TS_WHILE_LET     = "while_let_expression"
_TS_IF_LET        = "if_let_expression"

# Ownership categories written into Variable node metadata.
_OWN_OWNED = "owned"
_OWN_SHARED_REF = "shared_ref"
_OWN_MUT_REF = "mut_ref"
_OWN_RAW_CONST = "raw_ptr_const"
_OWN_RAW_MUT = "raw_ptr_mut"

# Functions that are unconditional taint sinks for unsafe memory operations.
_UNSAFE_SINK_LABELS: Set[str] = {
    "std::mem::transmute", "transmute",
    "std::ptr::write", "std::ptr::read",
    "std::ptr::copy", "std::ptr::copy_nonoverlapping",
    "libc::system", "system",
}


class RustParser(TreeSitterParser):
    """Tree-sitter backed parser for Rust source files.

    Emits IR v0.3.0 nodes and edges including:
    - ``NodeType.FUNCTION``, ``STRUCT``, ``TRAIT_IMPL``, ``LIFETIME``,
      ``BORROW_SCOPE``, ``UNSAFE``, ``MACRO_EXPANSION``, ``IMPORT``, ``MODULE``
    - ``EdgeRelation.BORROWS``, ``MOVES``, ``DROPS``, ``UNSAFE_DEREFERENCE``,
      ``LIFETIME_BOUNDS``, ``MACRO_EXPANDS_TO``, ``FIELD_ACCESS``,
      ``CONTAINS``, ``CALLS``, ``DATAFLOW``, ``IMPORTS``, ``RETURNS``
    """

    language: str = "rust"

    def __init__(
        self,
        config: SecurityConfig,
        options: Optional[AnalysisOptions] = None,
    ) -> None:
        super().__init__(config, language_name="rust", options=options)

        # SSA counter — reuses the existing SSAVersionTracker from analyzers.symbols.
        self._ssa: SSAVersionTracker = SSAVersionTracker()

        # Maps lifetime name (e.g. "'a") → LIFETIME node ID, scoped per function.
        self._lifetime_registry: Dict[str, str] = {}

        # Stack of (start_line, borrow_kind) open borrow scopes.
        self._borrow_stack: List[Tuple[int, str]] = []

        # Stack of start lines of open `unsafe` blocks (depth tracking).
        self._unsafe_stack: List[int] = []

        # Maps SSA variable name → ownership category string.
        self._ownership_map: Dict[str, str] = {}

        # Crate name inferred from directory structure (best-effort).
        self._crate_name: str = "unknown"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @classmethod
    def supports(cls, path: str) -> bool:
        """Return True for ``.rs`` files only.

        Override directive #1: ``.h`` and ``.c`` files are handled by CParser.
        Translation-unit precedence means Rust consumes only its own extension.
        """
        return path.endswith(".rs")

    def parse(self, path: str) -> None:
        """Parse a Rust source file and populate ``self.nodes`` / ``self.edges``.

        Execution order
        ---------------
        1. Read source bytes and run tree-sitter parse (S1 entry).
        2. Infer crate context from directory structure.
        3. Emit MODULE node for the file root.
        4. Walk root children for top-level declarations.
        5. Each visitor method populates self.nodes / self.edges in-place.
        """
        with open(path, "rb") as fh:
            source_bytes = fh.read()

        source_str: str = source_bytes.decode("utf-8", errors="replace")
        tree = self._ts_parser.parse(source_bytes)
        root = tree.root_node

        # Crate heuristic: look for Cargo.toml in ancestors.
        self._crate_name = self._infer_crate_name(path)

        # Reset per-file state so this instance can be safely re-used across
        # multiple files (though MultiFileParser creates a fresh instance each time).
        self._ssa = SSAVersionTracker()
        self._lifetime_registry = {}
        self._borrow_stack = []
        self._unsafe_stack = []
        self._ownership_map = {}

        # MODULE node.
        mod_label = os.path.basename(path)
        mod_id = self._make_id(path, "__module__")
        mod_node = self._make_node(mod_id, NodeType.MODULE, mod_label, path, lineno=1)
        mod_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "module_path": self._infer_module_path(path),
            }
        )
        self.nodes[mod_id] = mod_node

        # Walk top-level items.
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
        """Dispatch a top-level tree-sitter node to the appropriate visitor."""
        t = node.type
        if t == _TS_FUNCTION_ITEM:
            self._visit_function(node, src, path, parent_id, impl_type=None)
        elif t == _TS_IMPL_ITEM:
            self._visit_impl(node, src, path, parent_id)
        elif t == _TS_STRUCT_ITEM:
            self._visit_struct(node, src, path, parent_id)
        elif t == _TS_TRAIT_ITEM:
            self._visit_trait(node, src, path, parent_id)
        elif t in (_TS_MACRO_DEF, _TS_MACRO_INVOCATION):
            self._visit_macro(node, src, path, parent_id)
        elif t == _TS_USE_DECL:
            self._visit_use(node, src, path, parent_id)
        elif t == _TS_EXTERN_CRATE:
            self._visit_extern_crate(node, src, path, parent_id)
        elif t == _TS_MOD_ITEM:
            self._visit_mod(node, src, path, parent_id)
        # Other node types (comments, attributes, semicolons) are silently skipped.

    # ------------------------------------------------------------------
    # Function visitor
    # ------------------------------------------------------------------

    def _visit_function(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        impl_type: Optional[str],
    ) -> None:
        """Emit FUNCTION node and traverse its body for nested constructs.

        Handles: lifetime parameters, parameter ownership classification,
        unsafe fn marker, visibility, where clauses, and body traversal.
        """
        # Reset per-function lifetime registry.
        self._lifetime_registry = {}

        fn_name = self._child_text(node, _TS_IDENTIFIER, src)
        if not fn_name:
            fn_name = self._child_text(node, _TS_TYPE_IDENTIFIER, src) or "<anon>"

        qualified = f"{self._infer_module_path(path)}::{fn_name}"
        if impl_type:
            qualified = f"{self._infer_module_path(path)}::{impl_type}::{fn_name}"

        fn_id = self._make_id(path, qualified)
        lineno = node.start_point[0] + 1

        modifiers = self._function_modifier_types(node)
        is_unsafe_fn = _TS_UNSAFE_MOD in modifiers
        visibility = self._extract_visibility(node, src)
        lifetimes = self._extract_lifetime_params(node, src, path, fn_id)
        where_text = self._extract_where_clause(node, src)
        is_async = "async" in modifiers
        is_const = "const" in modifiers
        abi = self._extract_abi(node, src)

        fn_node = self._make_node(fn_id, NodeType.FUNCTION, fn_name, path, lineno)
        fn_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "module_path": self._infer_module_path(path),
                "qualified_name": qualified,
                "lifetimes": lifetimes,
                "is_async": is_async,
                "is_const": is_const,
                "is_unsafe_fn": is_unsafe_fn,
                "visibility": visibility,
                "where_clause": where_text,
                "abi": abi,
                "impl_type": impl_type,
            }
        )
        _mark_function_entrypoint(fn_node, fn_name)
        if is_unsafe_fn:
            fn_node.is_unsafe = True

        self.nodes[fn_id] = fn_node
        self.edges.append(self._edge(parent_id, fn_id, EdgeRelation.CONTAINS))

        # Parameters.
        params_node = self._first_child(node, _TS_PARAMETERS)
        if params_node:
            self._visit_parameters(params_node, src, path, fn_id)

        # Body.
        body = self._first_child(node, _TS_BLOCK)
        if body:
            self._visit_block(body, src, path, fn_id, enclosing_fn_id=fn_id)

    # ------------------------------------------------------------------
    # impl block visitor
    # ------------------------------------------------------------------

    def _visit_impl(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit TRAIT_IMPL node and recurse into its function items."""
        # Determine implementing type name.
        impl_type = None
        trait_name = None
        for child in node.children:
            if child.type in (_TS_TYPE_IDENTIFIER, _TS_GENERIC_TYPE):
                if impl_type is None:
                    impl_type = self._get_text(src, child)
                else:
                    trait_name = impl_type
                    impl_type = self._get_text(src, child)

        if not impl_type:
            impl_type = "<unknown>"

        label = f"impl::{impl_type}" if not trait_name else f"impl::{trait_name}::{impl_type}"
        impl_id = self._make_id(path, f"{self._infer_module_path(path)}::{label}")
        lineno = node.start_point[0] + 1

        lifetimes = self._extract_lifetime_params(node, src, path, impl_id)
        is_unsafe_impl = any(c.type == _TS_UNSAFE_MOD for c in node.children)

        impl_node = self._make_node(impl_id, NodeType.TRAIT_IMPL, label, path, lineno)
        impl_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "trait_name": trait_name or "",
                "implementing_type": impl_type,
                "lifetimes": lifetimes,
                "is_unsafe_impl": is_unsafe_impl,
                "auto_trait": trait_name is None,
            }
        )
        self.nodes[impl_id] = impl_node
        self.edges.append(self._edge(parent_id, impl_id, EdgeRelation.CONTAINS))

        decl_list = self._first_child(node, _TS_DECLARATION_LIST)
        if decl_list:
            for child in decl_list.children:
                if child.type == _TS_FUNCTION_ITEM:
                    self._visit_function(child, src, path, impl_id, impl_type=impl_type)
                elif child.type in (_TS_MACRO_DEF, _TS_MACRO_INVOCATION):
                    self._visit_macro(child, src, path, impl_id)

    # ------------------------------------------------------------------
    # Struct visitor
    # ------------------------------------------------------------------

    def _visit_struct(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit STRUCT node with field layout and repr metadata."""
        name = self._child_text(node, _TS_TYPE_IDENTIFIER, src) or "<anon_struct>"
        struct_id = self._make_id(path, f"{self._infer_module_path(path)}::{name}")
        lineno = node.start_point[0] + 1

        lifetimes = self._extract_lifetime_params(node, src, path, struct_id)
        derives = self._extract_derives(node, src)
        repr_val = self._extract_repr(node, src)
        fields = self._extract_struct_fields(node, src, path, struct_id)

        struct_node = self._make_node(struct_id, NodeType.STRUCT, name, path, lineno)
        struct_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "repr": repr_val,
                "derives": derives,
                "is_tuple_struct": self._is_tuple_struct(node),
                "fields": fields,
                "lifetime_params": lifetimes,
            }
        )
        self.nodes[struct_id] = struct_node
        self.edges.append(self._edge(parent_id, struct_id, EdgeRelation.CONTAINS))

    # ------------------------------------------------------------------
    # Trait visitor (declaration only — impl handled separately)
    # ------------------------------------------------------------------

    def _visit_trait(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit INTERFACE node for trait declarations."""
        name = self._child_text(node, _TS_TYPE_IDENTIFIER, src) or "<anon_trait>"
        trait_id = self._make_id(path, f"{self._infer_module_path(path)}::{name}")
        lineno = node.start_point[0] + 1
        is_unsafe = any(c.type == _TS_UNSAFE_MOD for c in node.children)

        trait_node = self._make_node(trait_id, NodeType.INTERFACE, name, path, lineno)
        trait_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "is_unsafe_trait": is_unsafe,
            }
        )
        self.nodes[trait_id] = trait_node
        self.edges.append(self._edge(parent_id, trait_id, EdgeRelation.CONTAINS))

        # Visit default method implementations inside the trait body.
        decl_list = self._first_child(node, _TS_DECLARATION_LIST)
        if decl_list:
            for child in decl_list.children:
                if child.type == _TS_FUNCTION_ITEM:
                    self._visit_function(child, src, path, trait_id, impl_type=None)

    # ------------------------------------------------------------------
    # Macro visitor — directive #2: trace into expanded AST
    # ------------------------------------------------------------------

    def _visit_macro(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit MACRO_EXPANSION node and trace into its token-tree body.

        Override directive #2: macro expansions trace directly into the
        expanded AST prior to the S1 semantic pass. For declarative macros
        (macro_rules!) we walk the token_tree body and emit ``MACRO_EXPANDS_TO``
        edges to each top-level token group. For invocations we walk the
        argument token tree and emit DATAFLOW / CALLS edges to resolved
        callees or data nodes so that the taint graph reflects the expansion.
        """
        lineno = node.start_point[0] + 1

        if node.type == _TS_MACRO_DEF:
            # macro_rules! definition.
            macro_name = self._child_text(node, _TS_IDENTIFIER, src) or "<macro>"
            macro_kind = "declarative"
        else:
            # Invocation: <path>!(<args>)  or  <scoped_id>!(<args>)
            path_node = node.children[0] if node.children else None
            macro_name = self._get_text(src, path_node) if path_node else "<macro>"
            macro_name = macro_name.rstrip("!")
            macro_kind = "proc_macro" if "::" in macro_name else "declarative"

        is_unsafe_expansion = any(
            self._get_text(src, c).lower() in ("unsafe", "transmute", "ptr")
            for c in self._iter_descendants(node)
            if c.type == _TS_IDENTIFIER
        )

        m_id = self._make_id(path, f"{self._infer_module_path(path)}::macro::{macro_name}:{lineno}")

        m_node = self._make_node(m_id, NodeType.MACRO_EXPANSION, macro_name, path, lineno)
        m_node.metadata.update(
            {
                "language": "rust",
                "crate": self._crate_name,
                "macro_name": macro_name,
                "macro_kind": macro_kind,
                "expansion_site_line": lineno,
                "is_unsafe_expansion": is_unsafe_expansion,
            }
        )
        if is_unsafe_expansion:
            m_node.is_unsafe = True

        self.nodes[m_id] = m_node
        self.edges.append(self._edge(parent_id, m_id, EdgeRelation.CONTAINS))

        # Trace into expanded AST: walk the token_tree children and emit
        # MACRO_EXPANDS_TO edges to each sub-node that represents a callable
        # or data reference (identifiers, scoped paths).
        for child in self._iter_descendants(node):
            if child.type in (_TS_IDENTIFIER, _TS_SCOPED_ID):
                expansion_label = self._get_text(src, child)
                if not expansion_label or expansion_label in (macro_name, "macro_rules"):
                    continue
                exp_id = self._make_id(path, f"__macro_exp__{macro_name}::{expansion_label}:{child.start_point[0]+1}")
                if exp_id not in self.nodes:
                    exp_node = self._make_node(
                        exp_id,
                        NodeType.DATA,
                        expansion_label,
                        path,
                        child.start_point[0] + 1,
                    )
                    exp_node.metadata["macro_origin"] = macro_name
                    self.nodes[exp_id] = exp_node
                self.edges.append(
                    self._edge(
                        m_id,
                        exp_id,
                        EdgeRelation.MACRO_EXPANDS_TO,
                        {"macro_name": macro_name, "expansion_kind": macro_kind},
                    )
                )

    # ------------------------------------------------------------------
    # use / extern crate visitors
    # ------------------------------------------------------------------

    def _visit_use(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit IMPORT node for a ``use`` declaration."""
        use_text = self._get_text(src, node)
        # Strip 'use ' prefix and trailing ';'
        module_path = use_text.removeprefix("use ").rstrip(";").strip()
        import_name = module_path.split("::")[-1].strip("{}").strip()

        imp_id = self._make_id(path, f"__use__{module_path}")
        imp_node = self._make_node(
            imp_id,
            NodeType.IMPORT,
            import_name,
            path,
            node.start_point[0] + 1,
        )
        imp_node.metadata.update(
            {
                "language": "rust",
                "import_module": module_path,
                "import_name": import_name,
            }
        )
        self.nodes[imp_id] = imp_node
        self.edges.append(self._edge(parent_id, imp_id, EdgeRelation.IMPORTS))

    def _visit_extern_crate(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit IMPORT node for an ``extern crate`` declaration."""
        crate_name = self._child_text(node, _TS_IDENTIFIER, src) or "<extern>"
        imp_id = self._make_id(path, f"__extern_crate__{crate_name}")
        imp_node = self._make_node(
            imp_id,
            NodeType.IMPORT,
            crate_name,
            path,
            node.start_point[0] + 1,
        )
        imp_node.metadata.update(
            {"language": "rust", "import_module": crate_name, "import_name": crate_name}
        )
        self.nodes[imp_id] = imp_node
        self.edges.append(self._edge(parent_id, imp_id, EdgeRelation.IMPORTS))

    def _visit_mod(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
    ) -> None:
        """Emit MODULE node for an inline ``mod`` block and recurse."""
        mod_name = self._child_text(node, _TS_IDENTIFIER, src) or "<mod>"
        mod_id = self._make_id(path, f"{self._infer_module_path(path)}::{mod_name}")
        lineno = node.start_point[0] + 1

        mod_node = self._make_node(mod_id, NodeType.MODULE, mod_name, path, lineno)
        mod_node.metadata.update(
            {"language": "rust", "crate": self._crate_name, "inline_mod": True}
        )
        self.nodes[mod_id] = mod_node
        self.edges.append(self._edge(parent_id, mod_id, EdgeRelation.CONTAINS))

        # Inline mod body.
        decl_list = self._first_child(node, _TS_DECLARATION_LIST)
        if decl_list:
            for child in decl_list.children:
                self._visit_top_level(child, src, path, mod_id)

    # ------------------------------------------------------------------
    # Parameter visitor — ownership + lifetime classification
    # ------------------------------------------------------------------

    def _visit_parameters(
        self,
        params_node,
        src: str,
        path: str,
        fn_id: str,
    ) -> None:
        """Emit VARIABLE nodes for each function parameter with ownership metadata."""
        for child in params_node.children:
            if child.type != _TS_PARAMETER:
                continue

            param_name = self._child_text(child, _TS_IDENTIFIER, src)
            if not param_name or param_name == "self":
                continue

            ownership, lifetime_ann = self._classify_param_type(child, src)
            ssa_label = self._ssa.get_versioned_id(param_name)

            var_id = self._make_id(path, f"{fn_id}::param::{ssa_label}")
            is_unsafe_ptr = ownership in (_OWN_RAW_CONST, _OWN_RAW_MUT)

            var_node = self._make_node(
                var_id,
                NodeType.VARIABLE,
                param_name,
                path,
                child.start_point[0] + 1,
            )
            var_node.metadata.update(
                {
                    "language": "rust",
                    "ownership": ownership,
                    "lifetime_annotation": lifetime_ann,
                    "is_mut": "mut" in self._get_text(src, child),
                    "ssa_version": int(ssa_label.split("_v")[-1]) if "_v" in ssa_label else 0,
                    "flow_kind": "parameter",
                }
            )
            if is_unsafe_ptr:
                var_node.is_unsafe = True

            self.nodes[var_id] = var_node
            self.edges.append(
                self._edge(
                    fn_id,
                    var_id,
                    EdgeRelation.DATAFLOW,
                    {"flow_kind": "parameter", "ownership": ownership},
                )
            )
            self._ownership_map[ssa_label] = ownership

            # If this is a reference parameter, emit a BORROWS edge from param → fn.
            if ownership in (_OWN_SHARED_REF, _OWN_MUT_REF):
                self.edges.append(
                    self._edge(
                        var_id,
                        fn_id,
                        EdgeRelation.BORROWS,
                        {
                            "borrow_kind": "mutable" if ownership == _OWN_MUT_REF else "shared",
                            "lifetime": lifetime_ann or "",
                        },
                    )
                )

            # Lifetime node cross-reference.
            if lifetime_ann and lifetime_ann in self._lifetime_registry:
                lt_id = self._lifetime_registry[lifetime_ann]
                self.edges.append(
                    self._edge(var_id, lt_id, EdgeRelation.LIFETIME_BOUNDS)
                )

    # ------------------------------------------------------------------
    # Block / body visitor
    # ------------------------------------------------------------------

    def _visit_block(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        enclosing_fn_id: str,
    ) -> None:
        """Walk a block and emit edges for statements inside it.

        Fix 1: now handles all Rust control-flow expression types:
        if/if-let, match, loop, while/while-let, for, closure, plus
        the original: let bindings, unsafe blocks, bare calls, returns,
        and nested blocks.
        """
        for child in node.children:
            t = child.type

            if t == _TS_LET_DECL:
                self._visit_let(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_UNSAFE_BLOCK:
                self._visit_unsafe_block(child, src, path, parent_id, enclosing_fn_id)

            elif t in (_TS_IF_EXPR, _TS_IF_LET):
                self._visit_if(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_MATCH_EXPR:
                self._visit_match(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_LOOP_EXPR:
                inner = self._first_child(child, _TS_BLOCK)
                if inner:
                    self._visit_block(inner, src, path, parent_id, enclosing_fn_id)

            elif t in (_TS_WHILE_EXPR, _TS_WHILE_LET):
                self._visit_while_for(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_FOR_EXPR:
                self._visit_while_for(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_CLOSURE_EXPR:
                self._visit_closure(child, src, path, parent_id, enclosing_fn_id)

            elif t in ("expression_statement",):
                # Unwrap the inner expression.
                inner = child.children[0] if child.children else child
                self._visit_expression(inner, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_CALL_EXPR:
                self._visit_call(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_METHOD_CALL:
                self._visit_method_call(child, src, path, parent_id, enclosing_fn_id)

            elif t in (_TS_MACRO_DEF, _TS_MACRO_INVOCATION):
                self._visit_macro(child, src, path, parent_id)

            elif t == _TS_RETURN_EXPR:
                self._visit_return(child, src, path, parent_id, enclosing_fn_id)

            elif t == _TS_BLOCK:
                self._visit_block(child, src, path, parent_id, enclosing_fn_id)

        # Fix 2: emit DROPS edges for let-bound variables that go out of scope
        # at the end of this block (syntactic approximation of NLL drop order).
        for child in node.children:
            if child.type == _TS_LET_DECL:
                pat = self._first_child(child, "identifier")
                if pat is None:
                    continue
                var_name = self._get_text(src, pat)
                ssa_label = self._ssa.get_current_id(var_name)
                if ssa_label:
                    drop_id = self._make_id(path, f"{enclosing_fn_id}::let::{ssa_label}")
                    if drop_id in self.nodes:
                        ownership = self._ownership_map.get(ssa_label, _OWN_OWNED)
                        # Only emit DROPS for owned values (references don't drop).
                        if ownership == _OWN_OWNED:
                            self.edges.append(
                                self._edge(
                                    parent_id,
                                    drop_id,
                                    EdgeRelation.DROPS,
                                    {"scope_end_line": node.end_point[0] + 1},
                                )
                            )

    # ------------------------------------------------------------------
    # Control-flow visitors (Fix 1)
    # ------------------------------------------------------------------

    def _visit_if(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Recurse into if / if-let expression branches."""
        for child in node.children:
            if child.type == _TS_BLOCK:
                self._visit_block(child, src, path, parent_id, fn_id)
            elif child.type == _TS_ELSE_CLAUSE:
                # else { block } or else if { ... }
                for gc in child.children:
                    if gc.type == _TS_BLOCK:
                        self._visit_block(gc, src, path, parent_id, fn_id)
                    elif gc.type in (_TS_IF_EXPR, _TS_IF_LET):
                        self._visit_if(gc, src, path, parent_id, fn_id)
            # Condition may contain a call — check it.
            elif child.type in (_TS_CALL_EXPR,):
                self._visit_call(child, src, path, parent_id, fn_id)
            elif child.type == _TS_METHOD_CALL:
                self._visit_method_call(child, src, path, parent_id, fn_id)

    def _visit_match(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Recurse into match expression arms."""
        # Scrutinee may itself be a call (e.g. match self.process(input) {...})
        if node.children:
            scrutinee = node.children[0]
            if scrutinee.type == _TS_CALL_EXPR:
                self._visit_call(scrutinee, src, path, parent_id, fn_id)
            elif scrutinee.type == _TS_METHOD_CALL:
                self._visit_method_call(scrutinee, src, path, parent_id, fn_id)

        match_block = self._first_child(node, _TS_MATCH_BLOCK)
        if match_block is None:
            return
        for arm in match_block.children:
            if arm.type != _TS_MATCH_ARM:
                continue
            # Each arm: pattern => body
            # Body is the last child of the arm.
            body = arm.children[-1] if arm.children else None
            if body is None:
                continue
            if body.type == _TS_BLOCK:
                self._visit_block(body, src, path, parent_id, fn_id)
            elif body.type == _TS_CALL_EXPR:
                self._visit_call(body, src, path, parent_id, fn_id)
            elif body.type == _TS_METHOD_CALL:
                self._visit_method_call(body, src, path, parent_id, fn_id)
            elif body.type in (_TS_MACRO_INVOCATION, _TS_MACRO_DEF):
                self._visit_macro(body, src, path, parent_id)
            else:
                # Generic expression body — recurse via expression visitor.
                self._visit_expression(body, src, path, parent_id, fn_id)

    def _visit_while_for(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Recurse into while / while-let / for body blocks."""
        body = self._first_child(node, _TS_BLOCK)
        if body:
            self._visit_block(body, src, path, parent_id, fn_id)

    def _visit_closure(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Recurse into closure body (block or single expression)."""
        for child in node.children:
            if child.type == _TS_BLOCK:
                self._visit_block(child, src, path, parent_id, fn_id)
            elif child.type == _TS_CALL_EXPR:
                self._visit_call(child, src, path, parent_id, fn_id)
            elif child.type == _TS_METHOD_CALL:
                self._visit_method_call(child, src, path, parent_id, fn_id)

    # ------------------------------------------------------------------
    # let declaration visitor
    # ------------------------------------------------------------------

    def _visit_let(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Emit VARIABLE node and DATAFLOW/MOVES edges for a let binding.

        Fix 4
        -----
        After emitting the variable node, inspect the RHS node.  If it is a
        ``macro_invocation`` (e.g. ``let _ = taint_exec!("USER_CMD")``) call
        ``_visit_macro`` to emit the MACRO_EXPANSION node, then wire a
        ``MACRO_EXPANDS_TO`` edge from the variable node to the macro node
        and a ``DATAFLOW`` edge from the macro node back to the variable so
        that TaintAnalyzer can traverse the taint path through the macro.
        """
        # Fix 4 root cause: accept '_' wildcard pattern (type is literally "_")
        # in addition to named identifiers so that `let _ = taint_exec!(...)` is
        # processed rather than silently returned from.
        pat = (
            self._first_child(node, "identifier")
            or self._first_child(node, "_")
            or self._first_child(node, "pattern")
        )
        if pat is None:
            return

        # Use '_' as the canonical name for wildcard bindings.
        var_name = self._get_text(src, pat) if pat.type != "_" else "_"
        ssa_label = self._ssa.get_versioned_id(var_name)
        var_id = self._make_id(path, f"{fn_id}::let::{ssa_label}")
        lineno = node.start_point[0] + 1

        is_mut = any(c.type == "mutable_specifier" for c in node.children)
        type_node = self._first_child(node, "type_annotation")
        type_str = self._get_text(src, type_node.children[-1]).strip() if type_node and type_node.children else ""
        ownership = self._classify_type_string(type_str)
        lifetime_ann = self._extract_lifetime_from_type_str(type_str)
        is_unsafe_ptr = ownership in (_OWN_RAW_CONST, _OWN_RAW_MUT)

        # Locate RHS node (everything after '=').
        rhs_node = None
        rhs_text = ""
        found_eq = False
        for c in node.children:
            if found_eq and c.type not in (";",):
                rhs_node = c
                rhs_text = self._get_text(src, c)
                break
            if c.type == "=":
                found_eq = True

        is_taint_source = any(
            kw in rhs_text for kw in self.config.to_taint_config().sources
        ) if rhs_text else False

        var_node = self._make_node(var_id, NodeType.VARIABLE, var_name, path, lineno)
        var_node.metadata.update(
            {
                "language": "rust",
                "ownership": ownership,
                "lifetime_annotation": lifetime_ann,
                "is_mut": is_mut,
                "ssa_version": int(ssa_label.split("_v")[-1]) if "_v" in ssa_label else 0,
                "type_str": type_str,
                "flow_kind": "let_binding",
            }
        )
        if is_unsafe_ptr or is_taint_source:
            var_node.is_unsafe = True

        self.nodes[var_id] = var_node

        # DATAFLOW/MOVES edge from enclosing function → variable.
        rel = EdgeRelation.MOVES if found_eq else EdgeRelation.DATAFLOW
        self.edges.append(
            self._edge(
                fn_id,
                var_id,
                rel,
                {"flow_kind": "let_binding", "ownership": ownership, "ssa_label": ssa_label},
            )
        )
        self._ownership_map[ssa_label] = ownership

        # Fix 4: if the RHS is a macro_invocation, emit the macro node and
        # wire MACRO_EXPANDS_TO + DATAFLOW edges.
        if rhs_node is not None and rhs_node.type in (_TS_MACRO_INVOCATION, _TS_MACRO_DEF):
            pre_macro_count = len(self.nodes)
            self._visit_macro(rhs_node, src, path, var_id)
            # The macro visitor emits its node as the last addition; grab it.
            new_ids = list(self.nodes.keys())[pre_macro_count:]
            for macro_nid in new_ids:
                macro_node = self.nodes[macro_nid]
                if macro_node.type == NodeType.MACRO_EXPANSION.value:
                    # MACRO_EXPANDS_TO: variable → macro expansion node.
                    self.edges.append(
                        self._edge(
                            var_id,
                            macro_nid,
                            EdgeRelation.MACRO_EXPANDS_TO,
                            {"via_let_binding": True, "ssa_label": ssa_label},
                        )
                    )
                    # DATAFLOW: macro → variable so taint propagates out.
                    if macro_node.metadata.get("is_taint_source"):
                        self.edges.append(
                            self._edge(
                                macro_nid,
                                var_id,
                                EdgeRelation.DATAFLOW,
                                {"flow_kind": "macro_return", "ssa_label": ssa_label},
                            )
                        )

        # Fix 4 part 2: if the RHS is a plain call_expression to a taint
        # source, also emit a DATAFLOW edge from the call-result stub to
        # the variable so TaintAnalyzer can walk source → var.
        elif rhs_node is not None and rhs_node.type == _TS_CALL_EXPR:
            self._visit_call(rhs_node, src, path, var_id, fn_id)

    # ------------------------------------------------------------------
    # unsafe block visitor
    # ------------------------------------------------------------------

    def _visit_unsafe_block(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Emit UNSAFE node marking the unsafe block boundary.

        Counts raw-pointer dereferences and transmute calls inside the block
        to populate the ``raw_ptr_count`` and ``transmute_count`` metadata.
        """
        lineno = node.start_point[0] + 1
        self._unsafe_stack.append(lineno)

        raw_ptr_count = 0
        transmute_count = 0
        union_access_count = 0

        for desc in self._iter_descendants(node):
            if desc.type == _TS_UNARY_EXPR:
                text = self._get_text(src, desc)
                if text.startswith("*"):
                    raw_ptr_count += 1
                    # Emit UNSAFE_DEREFERENCE edge.
                    deref_id = self._make_id(
                        path,
                        f"{fn_id}::deref:{desc.start_point[0]+1}:{desc.start_point[1]}",
                    )
                    if deref_id not in self.nodes:
                        d_node = self._make_node(
                            deref_id, NodeType.DATA, text[:64], path, desc.start_point[0] + 1
                        )
                        d_node.is_unsafe = True
                        self.nodes[deref_id] = d_node
                    self.edges.append(
                        self._edge(
                            parent_id,
                            deref_id,
                            EdgeRelation.UNSAFE_DEREFERENCE,
                            {"inside_unsafe_block": True},
                        )
                    )

            elif desc.type in (_TS_CALL_EXPR, _TS_METHOD_CALL):
                call_text = self._get_text(src, desc)
                if "transmute" in call_text:
                    transmute_count += 1

        unsafe_label = f"unsafe_block@{lineno}"
        unsafe_id = self._make_id(path, f"{fn_id}::{unsafe_label}")
        unsafe_node = self._make_node(unsafe_id, NodeType.UNSAFE, unsafe_label, path, lineno)
        unsafe_node.is_unsafe = True
        unsafe_node.metadata.update(
            {
                "language": "rust",
                "unsafe_reason": "block",
                "raw_ptr_count": raw_ptr_count,
                "transmute_count": transmute_count,
                "union_access_count": union_access_count,
            }
        )
        self.nodes[unsafe_id] = unsafe_node
        self.edges.append(
            self._edge(parent_id, unsafe_id, EdgeRelation.UNSAFE_ACCESS, {"unsafe_reason": "block"})
        )

        # Recurse into the block body.
        inner_block = self._first_child(node, _TS_BLOCK)
        if inner_block:
            self._visit_block(inner_block, src, path, unsafe_id, fn_id)

        self._unsafe_stack.pop()

    # ------------------------------------------------------------------
    # Expression-level visitors
    # ------------------------------------------------------------------

    def _visit_expression(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Route expression nodes to specialized visitors."""
        t = node.type
        if t == _TS_CALL_EXPR:
            self._visit_call(node, src, path, parent_id, fn_id)
        elif t == _TS_METHOD_CALL:
            self._visit_method_call(node, src, path, parent_id, fn_id)
        elif t == _TS_UNSAFE_BLOCK:
            self._visit_unsafe_block(node, src, path, parent_id, fn_id)
        elif t in (_TS_MACRO_INVOCATION, _TS_MACRO_DEF):
            self._visit_macro(node, src, path, parent_id)
        elif t == _TS_UNARY_EXPR and self._get_text(src, node).startswith("*"):
            # Bare dereference expression outside unsafe block.
            deref_id = self._make_id(
                path, f"{fn_id}::deref:{node.start_point[0]+1}:{node.start_point[1]}"
            )
            if deref_id not in self.nodes:
                d_node = self._make_node(
                    deref_id,
                    NodeType.DATA,
                    self._get_text(src, node)[:64],
                    path,
                    node.start_point[0] + 1,
                )
                # Outside unsafe block → flag as potentially unsafe.
                d_node.is_unsafe = bool(self._unsafe_stack)
                self.nodes[deref_id] = d_node
            self.edges.append(
                self._edge(
                    parent_id,
                    deref_id,
                    EdgeRelation.UNSAFE_DEREFERENCE,
                    {"inside_unsafe_block": bool(self._unsafe_stack)},
                )
            )

    def _visit_call(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Emit CALLS edge for a function call expression.

        Fix 1 changes
        -------------
        * ``synthetic`` metadata value changed from ``True`` (bool) to the
          string ``"call_target"`` so that ``SymbolResolver._resolve_endpoint``
          recognises the stub and attempts to rewrite the edge target.
        * When the callee is a known taint *source* (e.g. ``env::var``,
          ``std::env::var``, ``stdin``), a DATAFLOW edge is emitted *from* the
          callee stub *into* the ``parent_id`` context so that TaintAnalyzer's
          BFS can propagate taint from the call result to the let-bound
          variable.
        """
        fn_expr = node.children[0] if node.children else None
        if fn_expr is None:
            return
        callee = self._get_text(src, fn_expr)
        # Normalise qualified path to short name for taint-config lookup.
        callee_short = callee.split("::")[-1]
        lineno = node.start_point[0] + 1

        tc = self.config.to_taint_config()
        is_source = any(
            src_kw in callee or src_kw in callee_short
            for src_kw in tc.sources
        )
        is_sink = any(
            sink_kw in callee or sink_kw in callee_short
            for sink_kw in tc.sinks
        ) or callee in _UNSAFE_SINK_LABELS

        callee_id = self._make_id(path, f"__call_target__{callee}")
        if callee_id not in self.nodes:
            ct_node = self._make_node(callee_id, NodeType.FUNCTION, callee, path, lineno)
            # Fix 1: use string value so SymbolResolver._resolve_endpoint triggers.
            ct_node.metadata["synthetic"] = "call_target"
            ct_node.metadata["call_name"] = callee
            ct_node.metadata["call_name_short"] = callee_short
            ct_node.metadata["language"] = "rust"
            ct_node.metadata["is_taint_source"] = is_source
            ct_node.metadata["is_taint_sink"] = is_sink
            if is_sink:
                ct_node.is_unsafe = True
            self.nodes[callee_id] = ct_node

        self.edges.append(
            self._edge(
                parent_id,
                callee_id,
                EdgeRelation.CALLS,
                {
                    "call_name": callee,
                    "inside_unsafe": bool(self._unsafe_stack),
                    "lineno": lineno,
                },
            )
        )

        # Fix 1 part A: taint-source calls emit a reverse DATAFLOW edge so the
        # TaintAnalyzer BFS can reach the let-bound variable that receives
        # the return value of this call.
        if is_source:
            self.edges.append(
                self._edge(
                    callee_id,
                    parent_id,
                    EdgeRelation.DATAFLOW,
                    {"flow_kind": "taint_source_return", "call_name": callee},
                )
            )

        # Fix 1 part B: for sink calls, walk the arguments node and emit
        # DATAFLOW edges from each identifier argument → callee_stub.
        # This gives TaintAnalyzer the path: source_var → callee_sink.
        if is_sink and len(node.children) > 1:
            args_node = node.children[-1] if node.children else None
            if args_node and args_node.type == "arguments":
                for arg in args_node.children:
                    if arg.type in ("identifier", "scoped_identifier"):
                        arg_text = self._get_text(src, arg)
                        ssa_current = self._ssa.get_current_id(arg_text)
                        arg_var_id_candidate = self._make_id(
                            path, f"{fn_id}::let::{ssa_current}"
                        ) if ssa_current else None
                        arg_source_id = arg_var_id_candidate if (
                            arg_var_id_candidate and arg_var_id_candidate in self.nodes
                        ) else None
                        # Also try parent_id directly when called from _visit_let.
                        if arg_source_id is None and parent_id in self.nodes:
                            arg_source_id = parent_id
                        if arg_source_id:
                            self.edges.append(
                                self._edge(
                                    arg_source_id,
                                    callee_id,
                                    EdgeRelation.DATAFLOW,
                                    {"flow_kind": "arg_to_sink", "call_name": callee},
                                )
                            )


    def _visit_method_call(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Emit CALLS edge for a method call expression (receiver.method()).

        Fix 1: synthetic tag changed to string ``"call_target"`` and
        is_taint_sink is stamped for known sinks.
        """
        method_field = self._first_child(node, _TS_IDENTIFIER)
        method_name = self._get_text(src, method_field) if method_field else "<method>"
        lineno = node.start_point[0] + 1

        tc = self.config.to_taint_config()
        is_sink = any(sink_kw in method_name for sink_kw in tc.sinks)

        callee_id = self._make_id(path, f"__call_target__method::{method_name}:{lineno}")
        if callee_id not in self.nodes:
            ct_node = self._make_node(callee_id, NodeType.FUNCTION, method_name, path, lineno)
            ct_node.metadata.update({
                "synthetic": "call_target",
                "call_name": method_name,
                "language": "rust",
                "is_method": True,
                "is_taint_sink": is_sink,
            })
            if is_sink:
                ct_node.is_unsafe = True
            self.nodes[callee_id] = ct_node

        self.edges.append(
            self._edge(
                parent_id,
                callee_id,
                EdgeRelation.CALLS,
                {"call_name": method_name, "is_method": True, "lineno": lineno},
            )
        )

    def _visit_return(
        self,
        node,
        src: str,
        path: str,
        parent_id: str,
        fn_id: str,
    ) -> None:
        """Emit RETURNS edge for a return expression."""
        ret_text = self._get_text(src, node)
        ret_id = self._make_id(path, f"{fn_id}::return:{node.start_point[0]+1}")
        if ret_id not in self.nodes:
            r_node = self._make_node(
                ret_id, NodeType.DATA, ret_text[:64], path, node.start_point[0] + 1
            )
            r_node.metadata["language"] = "rust"
            self.nodes[ret_id] = r_node
        self.edges.append(self._edge(parent_id, ret_id, EdgeRelation.RETURNS))

    # ------------------------------------------------------------------
    # Lifetime extraction helpers
    # ------------------------------------------------------------------

    def _extract_lifetime_params(
        self,
        node,
        src: str,
        path: str,
        scope_id: str,
    ) -> List[str]:
        """Extract lifetime parameter names from a type_parameters node.

        Emits a LIFETIME node for each unique lifetime found and stores it
        in ``self._lifetime_registry`` for later cross-referencing.
        Returns the list of lifetime name strings (e.g. ["'a", "'b"]).
        """
        names: List[str] = []
        tp = self._first_child(node, _TS_TYPE_PARAMS)
        if tp is None:
            return names

        for child in tp.children:
            if child.type == _TS_LIFETIME_PARAM:
                lt_child = self._first_child(child, _TS_LIFETIME)
                if lt_child:
                    lt_name = self._get_text(src, lt_child)
                    names.append(lt_name)
                    lt_id = self._make_id(path, f"{scope_id}::lifetime::{lt_name}")
                    if lt_id not in self.nodes:
                        lt_node = self._make_node(
                            lt_id,
                            NodeType.LIFETIME,
                            lt_name,
                            path,
                            child.start_point[0] + 1,
                        )
                        lt_node.metadata.update(
                            {
                                "language": "rust",
                                "name": lt_name,
                                "is_static": lt_name == "'static",
                                "is_anonymous": lt_name == "'_",
                                "scope_node_id": scope_id,
                            }
                        )
                        self.nodes[lt_id] = lt_node
                        self.edges.append(
                            self._edge(scope_id, lt_id, EdgeRelation.CONTAINS)
                        )
                    self._lifetime_registry[lt_name] = lt_id
        return names

    def _classify_param_type(self, param_node, src: str) -> Tuple[str, Optional[str]]:
        """Return (ownership_category, lifetime_annotation_or_None) for a parameter."""
        # Walk children of the parameter to find the type node.
        type_text = ""
        for child in param_node.children:
            if child.type not in (_TS_IDENTIFIER, ":", ",", "(", ")"):
                type_text = self._get_text(src, child)
                break
        return self._classify_type_string(type_text), self._extract_lifetime_from_type_str(type_text)

    @staticmethod
    def _classify_type_string(type_str: str) -> str:
        """Map a raw Rust type string to an ownership category constant."""
        s = type_str.strip()
        if s.startswith("*const"):
            return _OWN_RAW_CONST
        if s.startswith("*mut"):
            return _OWN_RAW_MUT
        if s.startswith("&mut"):
            return _OWN_MUT_REF
        if s.startswith("&"):
            return _OWN_SHARED_REF
        return _OWN_OWNED

    @staticmethod
    def _extract_lifetime_from_type_str(type_str: str) -> Optional[str]:
        """Extract a lifetime annotation like ``'a`` from a type string."""
        import re as _re
        m = _re.search(r"'[a-z_]+", type_str)
        return m.group(0) if m else None

    # ------------------------------------------------------------------
    # Struct field helpers
    # ------------------------------------------------------------------

    def _extract_struct_fields(
        self,
        node,
        src: str,
        path: str,
        struct_id: str,
    ) -> List[Dict[str, Any]]:
        """Return ordered field list for a struct, emitting FIELD_ACCESS edges."""
        fields: List[Dict[str, Any]] = []
        fdl = self._first_child(node, _TS_FIELD_DECL_LIST)
        if fdl is None:
            return fields

        for child in fdl.children:
            if child.type != _TS_FIELD_DECL:
                continue
            fname_node = self._first_child(child, _TS_FIELD_IDENTIFIER)
            if fname_node is None:
                continue
            fname = self._get_text(src, fname_node)
            type_text = ""
            past_colon = False
            for c in child.children:
                if past_colon and c.type != ",":
                    type_text = self._get_text(src, c)
                    break
                if c.type == ":":
                    past_colon = True

            fields.append({"name": fname, "type_str": type_text, "offset_hint": None})

            # Emit a VARIABLE node for the field and a FIELD_ACCESS edge.
            field_id = self._make_id(path, f"{struct_id}::field::{fname}")
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
                        "language": "rust",
                        "type_str": type_text,
                        "ownership": self._classify_type_string(type_text),
                    }
                )
                self.nodes[field_id] = fv_node
            self.edges.append(
                self._edge(
                    struct_id,
                    field_id,
                    EdgeRelation.FIELD_ACCESS,
                    {"field_name": fname, "type_str": type_text},
                )
            )
        return fields

    # ------------------------------------------------------------------
    # Attribute helpers
    # ------------------------------------------------------------------

    def _extract_derives(self, node, src: str) -> List[str]:
        """Return list of derive macro names from #[derive(...)] attributes."""
        derives: List[str] = []
        for child in node.children:
            if child.type != _TS_ATTR_ITEM:
                continue
            text = self._get_text(src, child)
            if "derive" in text:
                import re as _re
                m = _re.search(r"derive\(([^)]+)\)", text)
                if m:
                    derives.extend(d.strip() for d in m.group(1).split(","))
        return derives

    def _extract_repr(self, node, src: str) -> Optional[str]:
        """Return the repr string from #[repr(...)] if present."""
        for child in node.children:
            if child.type == _TS_ATTR_ITEM:
                text = self._get_text(src, child)
                if "repr" in text:
                    import re as _re
                    m = _re.search(r"repr\(([^)]+)\)", text)
                    if m:
                        return m.group(1)
        return None

    def _extract_visibility(self, node, src: str) -> str:
        """Return the visibility string (pub, pub(crate), etc.) or 'private'."""
        vis = self._first_child(node, _TS_VISIBILITY)
        return self._get_text(src, vis).strip() if vis else "private"

    def _extract_where_clause(self, node, src: str) -> str:
        """Return the raw where-clause text or empty string."""
        wc = self._first_child(node, _TS_WHERE_CLAUSE)
        return self._get_text(src, wc).strip() if wc else ""

    @staticmethod
    def _function_modifier_types(node) -> Set[str]:
        """Return the modifier keywords attached to a function item.

        The Rust grammar groups ``unsafe`` / ``async`` / ``const`` / ``extern "C"``
        into a single ``function_modifiers`` child rather than attaching them
        directly to the ``function_item``, so scanning only direct children misses
        every one of them. Direct children are still included for grammar
        versions that inline a lone modifier.
        """
        found: Set[str] = {c.type for c in node.children}
        modifiers = RustParser._first_child(node, _TS_FUNCTION_MODIFIERS)
        if modifiers is not None:
            found |= {c.type for c in modifiers.children}
        return found

    def _extract_abi(self, node, src: str) -> Optional[str]:
        """Return the extern ABI string (e.g. 'C') if present, else None."""
        candidates = list(node.children)
        modifiers = self._first_child(node, _TS_FUNCTION_MODIFIERS)
        if modifiers is not None:
            candidates.extend(modifiers.children)
        for child in candidates:
            if child.type == "extern_modifier":
                text = self._get_text(src, child)
                import re as _re
                m = _re.search(r'"([^"]+)"', text)
                return m.group(1) if m else "C"
        return None

    def _is_tuple_struct(self, node) -> bool:
        """Return True if the struct has a tuple-style field list."""
        return self._first_child(node, "ordered_field_declaration_list") is not None

    # ------------------------------------------------------------------
    # Tree-sitter traversal utilities
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
                return RustParser._get_text(src, c)
        return None

    @staticmethod
    def _iter_descendants(node):
        """Yield all descendant tree-sitter nodes via iterative DFS."""
        stack = list(node.children)
        while stack:
            current = stack.pop()
            yield current
            stack.extend(current.children)

    # ------------------------------------------------------------------
    # Context inference helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_crate_name(path: str) -> str:
        """Walk ancestors looking for Cargo.toml; return its package name."""
        import re as _re
        current = os.path.dirname(os.path.abspath(path))
        for _ in range(8):  # max 8 levels up
            cargo = os.path.join(current, "Cargo.toml")
            if os.path.isfile(cargo):
                try:
                    with open(cargo, encoding="utf-8") as fh:
                        content = fh.read()
                    m = _re.search(r'^\s*name\s*=\s*"([^"]+)"', content, _re.M)
                    if m:
                        return m.group(1)
                except OSError:
                    pass
                return os.path.basename(current)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return os.path.basename(os.path.dirname(os.path.abspath(path)))

    @staticmethod
    def _infer_module_path(path: str) -> str:
        """Convert a filesystem path to a dotted Rust module path (best-effort)."""
        base = os.path.splitext(os.path.basename(path))[0]
        # Walk up to src/ boundary.
        parts: List[str] = []
        current = os.path.dirname(os.path.abspath(path))
        for _ in range(10):
            bn = os.path.basename(current)
            if bn in ("src", "lib", "bin", "examples", "tests", "benches"):
                break
            parts.append(bn)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        parts.reverse()
        parts.append(base if base not in ("mod", "lib", "main") else "")
        return "::".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Plugin self-registration — fires on import.
# ---------------------------------------------------------------------------
register_parser(RustParser)
