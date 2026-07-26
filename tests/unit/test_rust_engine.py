"""Tests for the tree-sitter backed Rust parser (IR v0.3.0).

Sources are written inline per-test rather than reusing ``tests/fixtures/rust_crate``
so that each assertion names the exact construct it covers.  The shipped fixture
crate is still exercised as an end-to-end smoke test at the bottom of this module.

All inline sources are deliberately ASCII-only.  See
``test_non_ascii_comment_does_not_corrupt_labels`` for why that matters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import (
    AnalysisOptions,
    EdgeRelation,
    Node,
    NodeType,
    SecurityConfig,
)
from rootai_semantic_parser.parsers.registry import iter_parser_classes
from rootai_semantic_parser.parsers.rust_engine import RustParser

FIXTURE_CRATE = Path(__file__).resolve().parents[1] / "fixtures" / "rust_crate"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(tmp_path: Path, name: str, source: str) -> RustParser:
    """Write ``source`` to ``name`` under ``tmp_path`` and parse it."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    parser = RustParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(path))
    return parser


def _labels(parser: RustParser, node_type: NodeType) -> Set[str]:
    return {n.label for n in parser.nodes.values() if n.type == node_type.value}


def _by_label(parser: RustParser, label: str, node_type: Optional[NodeType] = None) -> Node:
    matches = [
        n
        for n in parser.nodes.values()
        if n.label == label and (node_type is None or n.type == node_type.value)
    ]
    assert matches, f"no node labelled {label!r} (type={node_type}) in {sorted(_all_labels(parser))}"
    return matches[0]


def _all_labels(parser: RustParser) -> Set[str]:
    return {n.label for n in parser.nodes.values()}


def _edge_pairs(parser: RustParser, relation: EdgeRelation) -> Set[Tuple[str, str]]:
    """Return (source_label, target_label) pairs for edges of ``relation``.

    Edges may point at synthetic ids that were never materialised as nodes, so
    endpoints are resolved defensively.
    """
    pairs: Set[Tuple[str, str]] = set()
    for edge in parser.edges:
        if edge.relation != relation.value:
            continue
        src = parser.nodes.get(edge.source)
        tgt = parser.nodes.get(edge.target)
        pairs.add((src.label if src else "?", tgt.label if tgt else "?"))
    return pairs


def _edge_metadata(parser: RustParser, relation: EdgeRelation) -> List[Dict]:
    return [dict(e.metadata) for e in parser.edges if e.relation == relation.value]


# ---------------------------------------------------------------------------
# Dispatch and registration
# ---------------------------------------------------------------------------


def test_supports_only_rust_extension() -> None:
    """RustParser claims .rs and nothing else (translation-unit precedence)."""
    assert RustParser.supports("src/lib.rs") is True
    assert RustParser.supports("src/net.c") is False
    assert RustParser.supports("include/net.h") is False
    assert RustParser.supports("app.py") is False


def test_rust_parser_is_registered_for_dispatch() -> None:
    """MultiFileParser can reach a Rust parser through the shared registry.

    Compared by name rather than identity: the ``rootai_semantic_parser`` compat
    shim re-executes module files when they are imported through the alias path,
    so two equivalent RustParser class objects can coexist.
    """
    registered = [cls for cls in iter_parser_classes() if cls.__name__ == "RustParser"]
    assert registered, [cls.__name__ for cls in iter_parser_classes()]
    assert all(cls.supports("src/lib.rs") for cls in registered)

    # No built-in parser may also claim .rs, or dispatch order would decide the winner.
    # Only classes exposing supports() are consulted: tests/unit/test_plugins.py leaks a
    # supports-less DummyParser into the process-global PARSER_PLUGINS.
    others = [
        cls
        for cls in iter_parser_classes()
        if cls.__name__ != "RustParser" and callable(getattr(cls, "supports", None))
    ]
    assert not [cls for cls in others if cls.supports("src/lib.rs")]


def test_rust_parser_declares_its_language() -> None:
    assert RustParser.language == "rust"


# ---------------------------------------------------------------------------
# Module / item structure
# ---------------------------------------------------------------------------


def test_module_node_records_crate_inferred_from_cargo_toml(tmp_path: Path) -> None:
    """The MODULE node carries crate context read out of the nearest Cargo.toml."""
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "vuln_server"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    parser = _parse(tmp_path, "src/lib.rs", "pub fn noop() {}\n")

    module = _by_label(parser, "lib.rs", NodeType.MODULE)
    assert module.language == "rust"
    assert module.metadata["crate"] == "vuln_server"


def test_module_path_is_empty_at_crate_root_and_set_for_submodules(tmp_path: Path) -> None:
    """Crate roots (lib.rs / mod.rs / main.rs) carry no module prefix; others do."""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "demo"\n', encoding="utf-8")

    root = _parse(tmp_path, "src/lib.rs", "pub fn noop() {}\n")
    assert _by_label(root, "lib.rs", NodeType.MODULE).metadata["module_path"] == ""

    submodule = _parse(tmp_path, "src/auth.rs", "pub fn noop() {}\n")
    assert _by_label(submodule, "auth.rs", NodeType.MODULE).metadata["module_path"] == "auth"

    nested = _parse(tmp_path, "src/net/tcp.rs", "pub fn noop() {}\n")
    assert _by_label(nested, "tcp.rs", NodeType.MODULE).metadata["module_path"] == "net::tcp"


def test_use_declarations_emit_import_nodes_and_edges(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "use std::env;\nuse std::process::Command;\n\npub fn noop() {}\n",
    )

    assert {"env", "Command"} <= _labels(parser, NodeType.IMPORT)
    imported = {tgt for _, tgt in _edge_pairs(parser, EdgeRelation.IMPORTS)}
    assert {"env", "Command"} <= imported


def test_struct_fields_emit_field_access_edges(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub struct Config {\n"
        "    pub host: String,\n"
        "    pub secret_key: String,\n"
        "}\n",
    )

    assert "Config" in _labels(parser, NodeType.STRUCT)
    field_targets = {tgt for src, tgt in _edge_pairs(parser, EdgeRelation.FIELD_ACCESS) if src == "Config"}
    assert {"host", "secret_key"} <= field_targets


def test_trait_declaration_and_impl_block(tmp_path: Path) -> None:
    """A trait becomes an Interface node; `impl ... for` becomes a TraitImpl node."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub struct Runner;\n"
        "pub trait Processor {\n"
        "    fn process(&self, input: &str) -> String;\n"
        "}\n"
        "impl Processor for Runner {\n"
        "    fn process(&self, input: &str) -> String { String::new() }\n"
        "}\n",
    )

    assert "Processor" in _labels(parser, NodeType.INTERFACE)
    assert any(
        label.startswith("impl::") for label in _labels(parser, NodeType.TRAIT_IMPL)
    ), sorted(_labels(parser, NodeType.TRAIT_IMPL))
    assert "process" in _labels(parser, NodeType.FUNCTION)


def test_impl_methods_are_contained_by_their_impl_block(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub struct Runner;\nimpl Runner {\n    pub fn execute_cmd(&self) {}\n}\n",
    )

    contains = _edge_pairs(parser, EdgeRelation.CONTAINS)
    assert any(
        src.startswith("impl::") and tgt == "execute_cmd" for src, tgt in contains
    ), sorted(contains)


def test_function_metadata_captures_visibility_and_modifiers(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn exposed() {}\nfn private_helper() {}\n",
    )

    assert _by_label(parser, "exposed", NodeType.FUNCTION).metadata["visibility"] == "pub"
    private = _by_label(parser, "private_helper", NodeType.FUNCTION)
    assert private.metadata["visibility"] != "pub"
    assert private.metadata["language"] == "rust"


# ---------------------------------------------------------------------------
# Ownership, borrows, lifetimes
# ---------------------------------------------------------------------------


def test_reference_parameters_are_classified_and_borrow(tmp_path: Path) -> None:
    """`&T` / `&mut T` params get an ownership class and a BORROWS edge to the fn."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn authenticate(user_input: &str, scratch: &mut String) -> bool { true }\n",
    )

    assert _by_label(parser, "user_input", NodeType.VARIABLE).metadata["ownership"] == "shared_ref"
    assert _by_label(parser, "scratch", NodeType.VARIABLE).metadata["ownership"] == "mut_ref"

    borrows = _edge_pairs(parser, EdgeRelation.BORROWS)
    assert ("user_input", "authenticate") in borrows
    assert ("scratch", "authenticate") in borrows

    kinds = {meta.get("borrow_kind") for meta in _edge_metadata(parser, EdgeRelation.BORROWS)}
    assert {"shared", "mutable"} <= kinds


def test_owned_parameter_does_not_borrow(tmp_path: Path) -> None:
    parser = _parse(tmp_path, "lib.rs", "pub fn consume(value: String) {}\n")

    assert _by_label(parser, "value", NodeType.VARIABLE).metadata["ownership"] == "owned"
    assert ("value", "consume") not in _edge_pairs(parser, EdgeRelation.BORROWS)


def test_raw_pointer_parameters_are_marked_unsafe(tmp_path: Path) -> None:
    """Raw pointers are the Rust escape hatch, so the params carry is_unsafe."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn read_raw(src: *const u8, dst: *mut u8) {}\n",
    )

    src_var = _by_label(parser, "src", NodeType.VARIABLE)
    dst_var = _by_label(parser, "dst", NodeType.VARIABLE)
    assert src_var.metadata["ownership"] == "raw_ptr_const"
    assert dst_var.metadata["ownership"] == "raw_ptr_mut"
    assert src_var.is_unsafe is True
    assert dst_var.is_unsafe is True


def test_lifetime_parameters_emit_lifetime_nodes(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub struct Config<'a> { pub host: &'a str }\n"
        "impl<'a> Config<'a> {\n"
        "    pub fn host_of(&self) -> &'a str { self.host }\n"
        "}\n",
    )

    assert "'a" in _labels(parser, NodeType.LIFETIME)
    impl_nodes = [n for n in parser.nodes.values() if n.type == NodeType.TRAIT_IMPL.value]
    assert any("'a" in (n.metadata.get("lifetimes") or []) for n in impl_nodes)


def test_let_bindings_emit_moves_and_scope_drops(tmp_path: Path) -> None:
    """Each `let` produces a MOVES edge in, and a DROPS edge at scope end."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn build() {\n"
        "    let owned = String::new();\n"
        "    let other = String::new();\n"
        "}\n",
    )

    moves = _edge_pairs(parser, EdgeRelation.MOVES)
    assert ("build", "owned") in moves
    assert ("build", "other") in moves

    drops = _edge_pairs(parser, EdgeRelation.DROPS)
    assert ("build", "owned") in drops
    assert all("scope_end_line" in meta for meta in _edge_metadata(parser, EdgeRelation.DROPS))


# ---------------------------------------------------------------------------
# Unsafe handling
# ---------------------------------------------------------------------------


def test_unsafe_block_emits_unsafe_node_and_deref_edge(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn peek(p: *const u8) {\n    unsafe { let v = *p; }\n}\n",
    )

    unsafe_nodes = [n for n in parser.nodes.values() if n.type == NodeType.UNSAFE.value]
    assert unsafe_nodes, "expected an Unsafe node for the unsafe block"
    assert unsafe_nodes[0].metadata.get("unsafe_reason") == "block"

    deref_meta = _edge_metadata(parser, EdgeRelation.UNSAFE_DEREFERENCE)
    assert deref_meta, "expected an unsafe_deref edge for *p"
    assert deref_meta[0].get("inside_unsafe_block") is True
    assert any(rel.relation == EdgeRelation.UNSAFE_ACCESS.value for rel in parser.edges)


def test_known_unsafe_sink_calls_are_flagged(tmp_path: Path) -> None:
    """`std::mem::transmute` is an unconditional unsafe sink."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn convert(s: &[u8]) -> u8 {\n    std::mem::transmute(s)\n}\n",
    )

    sink = _by_label(parser, "std::mem::transmute", NodeType.FUNCTION)
    assert sink.is_unsafe is True


def test_unsafe_fn_modifier_is_detected(tmp_path: Path) -> None:
    """Regression: modifiers live under a `function_modifiers` child.

    Scanning only the function_item's direct children found none of them, so
    `unsafe fn` was never flagged.
    """
    parser = _parse(tmp_path, "lib.rs", "pub unsafe fn danger(p: *mut u8) -> u8 { 1 }\n")

    fn = _by_label(parser, "danger", NodeType.FUNCTION)
    assert fn.metadata["is_unsafe_fn"] is True
    assert fn.is_unsafe is True


def test_async_and_const_modifiers_are_detected(tmp_path: Path) -> None:
    """`is_async` / `is_const` shared the `function_modifiers` defect."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub async fn fetch() {}\npub const fn sizer() -> usize { 0 }\npub fn plain() {}\n",
    )

    fetch = _by_label(parser, "fetch", NodeType.FUNCTION)
    assert fetch.metadata["is_async"] is True
    assert fetch.metadata["is_const"] is False

    sizer = _by_label(parser, "sizer", NodeType.FUNCTION)
    assert sizer.metadata["is_const"] is True
    assert sizer.metadata["is_async"] is False

    plain = _by_label(parser, "plain", NodeType.FUNCTION)
    assert plain.metadata["is_async"] is False
    assert plain.metadata["is_const"] is False
    assert plain.metadata["is_unsafe_fn"] is False


def test_stacked_modifiers_are_all_detected(tmp_path: Path) -> None:
    """`function_modifiers` holds one child per keyword when several are stacked."""
    parser = _parse(tmp_path, "lib.rs", "pub async unsafe fn both() {}\n")

    fn = _by_label(parser, "both", NodeType.FUNCTION)
    assert fn.metadata["is_async"] is True
    assert fn.metadata["is_unsafe_fn"] is True
    assert fn.is_unsafe is True


def test_extern_abi_is_extracted(tmp_path: Path) -> None:
    """`extern_modifier` also sits under `function_modifiers`, not the item."""
    parser = _parse(tmp_path, "lib.rs", 'pub extern "C" fn exported() {}\n')

    assert _by_label(parser, "exported", NodeType.FUNCTION).metadata["abi"] == "C"


# ---------------------------------------------------------------------------
# Taint sources and macros
# ---------------------------------------------------------------------------


def test_env_var_binding_is_marked_as_taint_source(tmp_path: Path) -> None:
    """`std::env::var` is a configured taint source, so the binding is unsafe."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        "use std::env;\n"
        "pub fn run_from_env() {\n"
        '    let cmd_name = env::var("CMD").unwrap_or_default();\n'
        "}\n",
    )

    assert _by_label(parser, "cmd_name", NodeType.VARIABLE).is_unsafe is True


def test_macro_invocation_emits_expansion_node_and_edges(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "macro_rules! taint_exec {\n"
        "    ($src:expr) => {{ std::process::Command::new($src).output() }};\n"
        "}\n"
        "pub fn run_macro_path() {\n"
        '    let _ = taint_exec!("USER_CMD");\n'
        "}\n",
    )

    assert "taint_exec" in _labels(parser, NodeType.MACRO_EXPANSION)
    assert _edge_pairs(parser, EdgeRelation.MACRO_EXPANDS_TO), "expected macro_expands_to edges"


def test_call_expressions_emit_calls_edges(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "lib.rs",
        "pub fn helper() {}\npub fn caller() {\n    helper();\n}\n",
    )

    assert ("caller", "helper") in _edge_pairs(parser, EdgeRelation.CALLS)


# ---------------------------------------------------------------------------
# Shipped fixture crate + end-to-end integration
# ---------------------------------------------------------------------------


def test_shipped_fixture_crate_parses_without_error() -> None:
    """The checked-in fixture crate parses and yields the expected IR node kinds."""
    parser = RustParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(FIXTURE_CRATE / "src" / "lib.rs"))

    kinds = {n.type for n in parser.nodes.values()}
    assert {
        NodeType.MODULE.value,
        NodeType.FUNCTION.value,
        NodeType.STRUCT.value,
        NodeType.TRAIT_IMPL.value,
        NodeType.LIFETIME.value,
        NodeType.MACRO_EXPANSION.value,
    } <= kinds

    relations = {e.relation for e in parser.edges}
    assert {
        EdgeRelation.CONTAINS.value,
        EdgeRelation.CALLS.value,
        EdgeRelation.MOVES.value,
        EdgeRelation.DROPS.value,
    } <= relations


def test_rust_sources_flow_through_multifileparser(tmp_path: Path) -> None:
    """RustParser is selected by the repo walker and its nodes reach the merged graph."""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "demo"\n', encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text(
        "use std::env;\n"
        "pub fn handler() {\n"
        '    let cmd = env::var("CMD").unwrap_or_default();\n'
        "}\n",
        encoding="utf-8",
    )

    parser = MultiFileParser(
        str(tmp_path),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    graph = parser.get_graph()

    rust_nodes = [n for n in graph["nodes"] if n.get("language") == "rust"]
    assert rust_nodes, "no rust nodes reached the merged graph"
    assert "handler" in {n["label"] for n in rust_nodes}


# ---------------------------------------------------------------------------
# Regression: byte-offset vs character-offset
# ---------------------------------------------------------------------------


def test_non_ascii_comment_does_not_corrupt_labels(tmp_path: Path) -> None:
    """Regression: tree-sitter reports BYTE offsets.

    Slicing the decoded source str with them shifted every span following the
    first non-ASCII byte, degrading labels into source fragments. Text is now
    taken from each node's own byte payload (TreeSitterParser._get_text).
    """
    parser = _parse(
        tmp_path,
        "lib.rs",
        "// ── section header ──\n"
        "pub fn handle(cmd: &str) -> bool {\n"
        "    let flag = cmd.len();\n"
        "    flag > 0\n"
        "}\n",
    )

    assert "handle" in _labels(parser, NodeType.FUNCTION)
    assert "cmd" in _labels(parser, NodeType.VARIABLE)
    assert "flag" in _labels(parser, NodeType.VARIABLE)


def test_multibyte_identifiers_and_literals_are_read_intact(tmp_path: Path) -> None:
    """Non-ASCII inside string literals must not shift later spans either."""
    parser = _parse(
        tmp_path,
        "lib.rs",
        'pub fn greet() -> &\'static str { "café ☕ naïve" }\n'
        "pub fn after(marker: &str) -> usize { marker.len() }\n",
    )

    assert {"greet", "after"} <= _labels(parser, NodeType.FUNCTION)
    assert "marker" in _labels(parser, NodeType.VARIABLE)
