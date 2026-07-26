"""Tests for the tree-sitter backed C parser (IR v0.3.0).

Sources are written inline per-test rather than reusing ``tests/fixtures/c_project``
so that each assertion names the exact construct it covers.  The shipped fixture
project is still exercised as an end-to-end smoke test at the bottom of this module.

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
from rootai_semantic_parser.parsers.c_engine import CParser
from rootai_semantic_parser.parsers.registry import iter_parser_classes

FIXTURE_PROJECT = Path(__file__).resolve().parents[1] / "fixtures" / "c_project"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(tmp_path: Path, name: str, source: str) -> CParser:
    """Write ``source`` to ``name`` under ``tmp_path`` and parse it."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    parser = CParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(path))
    return parser


def _labels(parser: CParser, node_type: NodeType) -> Set[str]:
    return {n.label for n in parser.nodes.values() if n.type == node_type.value}


def _all_labels(parser: CParser) -> Set[str]:
    return {n.label for n in parser.nodes.values()}


def _by_label(parser: CParser, label: str, node_type: Optional[NodeType] = None) -> Node:
    matches = [
        n
        for n in parser.nodes.values()
        if n.label == label and (node_type is None or n.type == node_type.value)
    ]
    assert matches, f"no node labelled {label!r} (type={node_type}) in {sorted(_all_labels(parser))}"
    return matches[0]


def _edge_pairs(parser: CParser, relation: EdgeRelation) -> Set[Tuple[str, str]]:
    """Return (source_label, target_label) pairs for edges of ``relation``."""
    pairs: Set[Tuple[str, str]] = set()
    for edge in parser.edges:
        if edge.relation != relation.value:
            continue
        src = parser.nodes.get(edge.source)
        tgt = parser.nodes.get(edge.target)
        pairs.add((src.label if src else "?", tgt.label if tgt else "?"))
    return pairs


def _edge_metadata(parser: CParser, relation: EdgeRelation) -> List[Dict]:
    return [dict(e.metadata) for e in parser.edges if e.relation == relation.value]


# ---------------------------------------------------------------------------
# Dispatch and registration
# ---------------------------------------------------------------------------


def test_supports_c_sources_and_headers() -> None:
    assert CParser.supports("src/net.c") is True
    assert CParser.supports("include/net.h") is True
    assert CParser.supports("src/lib.rs") is False
    assert CParser.supports("app.py") is False


def test_c_parser_is_registered_for_dispatch() -> None:
    """MultiFileParser can reach CParser through the shared registry."""
    registered = list(iter_parser_classes())
    assert CParser in registered, [cls.__name__ for cls in registered]
    assert [cls.__name__ for cls in registered].count("CParser") == 1

    # No other parser may claim .c/.h, or dispatch order would decide the winner.
    others = [cls for cls in registered if cls is not CParser]
    assert not [cls for cls in others if cls.supports("src/net.c") or cls.supports("include/net.h")]


def test_c_parser_declares_its_language() -> None:
    assert CParser.language == "c"


# ---------------------------------------------------------------------------
# Translation units vs. headers
# ---------------------------------------------------------------------------


def test_source_file_is_a_full_translation_unit(tmp_path: Path) -> None:
    parser = _parse(tmp_path, "net.c", "int net_init(void) { return 0; }\n")

    module = _by_label(parser, "net.c", NodeType.MODULE)
    assert module.metadata["is_header"] is False
    assert module.metadata["translation_unit"].endswith("net.c")
    assert _by_label(parser, "net_init", NodeType.FUNCTION).metadata["is_declaration_only"] is False


def test_header_file_is_declaration_only(tmp_path: Path) -> None:
    """Override directive #1: .h files are parsed as declaration-only units."""
    parser = _parse(tmp_path, "net.h", "int net_init(void) { return 0; }\n")

    module = _by_label(parser, "net.h", NodeType.MODULE)
    assert module.metadata["is_header"] is True
    assert module.metadata["translation_unit"] == ""

    fn = _by_label(parser, "net_init", NodeType.FUNCTION)
    assert fn.metadata["is_declaration_only"] is True
    assert fn.metadata["included_from"].endswith("net.h")


def test_include_directives_emit_import_nodes(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        '#include <stdio.h>\n#include "net.h"\n\nint main(void) { return 0; }\n',
    )

    assert {"stdio.h", "net.h"} <= _labels(parser, NodeType.IMPORT)
    assert _edge_pairs(parser, EdgeRelation.IMPORTS)


# ---------------------------------------------------------------------------
# Type declarations
# ---------------------------------------------------------------------------


def test_typedef_nodes_are_emitted(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.h",
        "typedef unsigned int net_addr_t;\ntypedef unsigned short net_port_t;\n",
    )

    assert {"net_addr_t", "net_port_t"} <= _labels(parser, NodeType.TYPEDEF)


def test_struct_declaration_emits_scalar_fields(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.h",
        "struct client_ctx {\n    int fd;\n    int authenticated;\n};\n",
    )

    assert "client_ctx" in _labels(parser, NodeType.STRUCT)
    fields = {tgt for src, tgt in _edge_pairs(parser, EdgeRelation.FIELD_ACCESS) if src == "client_ctx"}
    assert {"fd", "authenticated"} <= fields


def test_struct_array_and_pointer_fields_are_emitted(tmp_path: Path) -> None:
    """Regression: only scalar members expose the identifier as a direct child.

    Arrays nest it under array_declarator and pointers under pointer_declarator,
    so a direct-children scan dropped exactly the security-relevant members.
    """
    parser = _parse(
        tmp_path,
        "net.h",
        "struct client_ctx {\n"
        "    int fd;\n"
        "    char token[64];\n"
        "    unsigned char *overflow_ptr;\n"
        "};\n",
    )

    fields = {tgt for src, tgt in _edge_pairs(parser, EdgeRelation.FIELD_ACCESS) if src == "client_ctx"}
    assert {"fd", "token", "overflow_ptr"} <= fields

    # A pointer member stays flagged unsafe; a fixed-size buffer records its extent.
    assert _by_label(parser, "overflow_ptr", NodeType.VARIABLE).is_unsafe is True


def test_function_pointer_member_uses_the_member_name(tmp_path: Path) -> None:
    """The member name must win over the function pointer's parameter names."""
    parser = _parse(
        tmp_path,
        "net.h",
        "struct handlers {\n    int (*on_recv)(int sock, char *buf);\n};\n",
    )

    fields = {tgt for src, tgt in _edge_pairs(parser, EdgeRelation.FIELD_ACCESS) if src == "handlers"}
    assert "on_recv" in fields
    assert not ({"sock", "buf"} & fields)


def test_union_declaration_emits_union_type_node(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.h",
        "union payload_u {\n    unsigned int as_int;\n    char as_bytes[4];\n};\n",
    )

    assert "payload_u" in _labels(parser, NodeType.UNION_TYPE)


def test_pointer_depth_is_recorded_on_variables(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "int handle(int plain, char *once) { return 0; }\n",
    )

    assert _by_label(parser, "plain", NodeType.VARIABLE).metadata["pointer_depth"] == 0
    assert _by_label(parser, "once", NodeType.VARIABLE).metadata["pointer_depth"] == 1


# ---------------------------------------------------------------------------
# Preprocessor macros
# ---------------------------------------------------------------------------


def test_object_and_function_like_macros_are_distinguished(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.h",
        "#define MAX_BUF 4096\n#define SAFE_COPY(dst, src, n) strncpy((dst), (src), (n))\n",
    )

    assert _by_label(parser, "MAX_BUF", NodeType.MACRO_EXPANSION).metadata["macro_kind"] == "object_like"
    assert _by_label(parser, "SAFE_COPY", NodeType.MACRO_EXPANSION).metadata["macro_kind"] == "function_like"


def test_macro_expanding_to_unsafe_sink_is_flagged(tmp_path: Path) -> None:
    """A function-like macro wrapping sprintf inherits the unsafe marker."""
    parser = _parse(
        tmp_path,
        "net.h",
        "#define UNSAFE_FMT(buf, fmt) sprintf((buf), (fmt))\n",
    )

    assert _by_label(parser, "UNSAFE_FMT", NodeType.MACRO_EXPANSION).is_unsafe is True
    assert _edge_pairs(parser, EdgeRelation.MACRO_EXPANDS_TO)


def test_macros_inside_conditional_blocks_are_discovered(tmp_path: Path) -> None:
    """Macros guarded by #ifdef must still be registered."""
    parser = _parse(
        tmp_path,
        "net.h",
        "#ifdef DEBUG\n"
        '#  define LOG(msg) fprintf(stderr, "%s", (msg))\n'
        "#else\n"
        "#  define LOG(msg) ((void)0)\n"
        "#endif\n",
    )

    assert "LOG" in _labels(parser, NodeType.MACRO_EXPANSION)


# ---------------------------------------------------------------------------
# Unsafe C constructs
# ---------------------------------------------------------------------------


def test_classic_unsafe_sink_calls_are_flagged(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "void dispatch(char *buf) {\n"
        "    strcpy(buf, \"x\");\n"
        "    system(buf);\n"
        "}\n",
    )

    assert _by_label(parser, "strcpy", NodeType.FUNCTION).is_unsafe is True
    assert _by_label(parser, "system", NodeType.FUNCTION).is_unsafe is True


def test_pointer_arithmetic_emits_edge_and_unsafe_marker(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "void walk(unsigned char *buf_ptr, int i) {\n    buf_ptr += i;\n}\n",
    )

    assert _edge_pairs(parser, EdgeRelation.POINTER_ARITH), "expected a pointer_arith edge"
    arith = _by_label(parser, "buf_ptr += i")
    assert arith.is_unsafe is True
    assert arith.metadata["unsafe_reason"] == "unchecked_ptr_arith"


def test_raw_pointer_dereference_emits_unsafe_deref_edge(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "struct ctx { unsigned char *overflow_ptr; };\n"
        "void poke(struct ctx *c) {\n"
        "    *c->overflow_ptr = 1;\n"
        "}\n",
    )

    assert _edge_pairs(parser, EdgeRelation.UNSAFE_DEREFERENCE), "expected an unsafe_deref edge"
    assert _by_label(parser, "*c->overflow_ptr").is_unsafe is True


def test_pointer_parameters_are_marked_unsafe(tmp_path: Path) -> None:
    parser = _parse(tmp_path, "net.c", "int recv_into(char *buf, int len) { return 0; }\n")

    assert _by_label(parser, "buf", NodeType.VARIABLE).is_unsafe is True
    assert _by_label(parser, "len", NodeType.VARIABLE).is_unsafe is False


# ---------------------------------------------------------------------------
# Taint sources and flow edges
# ---------------------------------------------------------------------------


def test_getenv_binding_is_marked_as_taint_source(tmp_path: Path) -> None:
    """`getenv` is a configured taint source, so the binding is unsafe."""
    parser = _parse(
        tmp_path,
        "net.c",
        'int net_init(void) {\n    char *env_name = getenv("SERVER_NAME");\n    return 0;\n}\n',
    )

    assert _by_label(parser, "env_name", NodeType.VARIABLE).is_unsafe is True


def test_calls_and_returns_edges_are_emitted(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "int helper(void) { return 1; }\n"
        "int caller(void) {\n    helper();\n    return 0;\n}\n",
    )

    assert ("caller", "helper") in _edge_pairs(parser, EdgeRelation.CALLS)
    assert _edge_pairs(parser, EdgeRelation.RETURNS), "expected returns edges"


def test_call_in_return_position_emits_calls_edge(tmp_path: Path) -> None:
    """Regression: _visit_return recorded the return text but never walked it.

    A call in tail position produced no CALLS edge, hiding taint sources such as
    the fixture's `net_get_env` -> `return getenv(name);`.
    """
    parser = _parse(
        tmp_path,
        "net.c",
        "int helper(void) { return 1; }\n"
        "int caller(void) {\n    return helper();\n}\n",
    )

    assert ("caller", "helper") in _edge_pairs(parser, EdgeRelation.CALLS)


def test_taint_source_in_return_position_is_reachable(tmp_path: Path) -> None:
    """`return getenv(name);` must link the caller to the taint source."""
    parser = _parse(
        tmp_path,
        "net.c",
        "char *net_get_env(const char *name) {\n    return getenv(name);\n}\n",
    )

    assert ("net_get_env", "getenv") in _edge_pairs(parser, EdgeRelation.CALLS)
    assert _edge_pairs(parser, EdgeRelation.RETURNS), "returns edge must still be emitted"


def test_unsafe_sink_in_return_position_is_flagged(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "int run(char *cmd) {\n    return system(cmd);\n}\n",
    )

    assert ("run", "system") in _edge_pairs(parser, EdgeRelation.CALLS)
    assert _by_label(parser, "system", NodeType.FUNCTION).is_unsafe is True


def test_function_metadata_records_signature(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        "static int counted(int a, char *b) { return 0; }\n",
    )

    fn = _by_label(parser, "counted", NodeType.FUNCTION)
    assert fn.metadata["return_type_str"]
    assert [p["name"] for p in fn.metadata["params"]] == ["a", "b"]
    assert fn.metadata["calling_convention"] == "cdecl"


def test_static_storage_class_is_detected(tmp_path: Path) -> None:
    """Regression: storage_class_specifier is a CHILD of the definition.

    Detection previously read the source text *preceding* the node, which never
    contains a specifier that sits inside the node's own span -- so internal
    linkage was indistinguishable from exported.
    """
    parser = _parse(
        tmp_path,
        "net.c",
        "static int counted(int a) { return 0; }\nint exported(int a) { return 0; }\n",
    )

    assert _by_label(parser, "counted", NodeType.FUNCTION).metadata["is_static"] is True
    assert _by_label(parser, "exported", NodeType.FUNCTION).metadata["is_static"] is False


def test_stacked_storage_class_specifiers_are_all_detected(tmp_path: Path) -> None:
    """`static inline` yields two separate specifiers; both must be seen."""
    parser = _parse(tmp_path, "net.c", "static inline int fast(int a) { return a; }\n")

    fn = _by_label(parser, "fast", NodeType.FUNCTION)
    assert fn.metadata["is_static"] is True
    assert fn.metadata["is_inline"] is True


def test_inline_without_static_is_detected(tmp_path: Path) -> None:
    parser = _parse(tmp_path, "net.c", "inline int only_inline(int a) { return a; }\n")

    fn = _by_label(parser, "only_inline", NodeType.FUNCTION)
    assert fn.metadata["is_inline"] is True
    assert fn.metadata["is_static"] is False


# ---------------------------------------------------------------------------
# Shipped fixture project + end-to-end integration
# ---------------------------------------------------------------------------


def test_shipped_fixture_header_parses_without_error() -> None:
    """The checked-in fixture header parses and yields the expected IR node kinds."""
    parser = CParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(FIXTURE_PROJECT / "include" / "net.h"))

    kinds = {n.type for n in parser.nodes.values()}
    assert {
        NodeType.MODULE.value,
        NodeType.FUNCTION.value,
        NodeType.TYPEDEF.value,
        NodeType.STRUCT.value,
        NodeType.UNION_TYPE.value,
        NodeType.MACRO_EXPANSION.value,
    } <= kinds


def test_shipped_fixture_source_parses_without_error() -> None:
    parser = CParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(FIXTURE_PROJECT / "src" / "net.c"))

    assert parser.nodes
    relations = {e.relation for e in parser.edges}
    assert {
        EdgeRelation.CONTAINS.value,
        EdgeRelation.CALLS.value,
        EdgeRelation.DATAFLOW.value,
    } <= relations


def test_c_sources_flow_through_multifileparser(tmp_path: Path) -> None:
    """CParser is selected by the repo walker and its nodes reach the merged graph."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "net.c").write_text(
        'int net_init(void) {\n'
        '    char *env_name = getenv("SERVER_NAME");\n'
        "    strcpy(g_name, env_name);\n"
        "    return 0;\n"
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

    c_nodes = [n for n in graph["nodes"] if n.get("language") == "c"]
    assert c_nodes, "no C nodes reached the merged graph"
    assert "net_init" in {n["label"] for n in c_nodes}


# ---------------------------------------------------------------------------
# Regression: byte-offset vs character-offset
# ---------------------------------------------------------------------------


def test_non_ascii_comment_does_not_corrupt_labels(tmp_path: Path) -> None:
    """Regression: tree-sitter reports BYTE offsets.

    Slicing the decoded source str with them shifted every span following the
    first non-ASCII byte, degrading labels into source fragments and flagging
    unrelated whitespace nodes as is_unsafe. Text is now taken from each node's
    own byte payload (TreeSitterParser._get_text).
    """
    parser = _parse(
        tmp_path,
        "net.c",
        "/* -- net_init " + "─" * 8 + " */\n"
        "int net_init(void) {\n"
        '    char *env_name = getenv("SERVER_NAME");\n'
        "    return 0;\n"
        "}\n",
    )

    assert "net_init" in _labels(parser, NodeType.FUNCTION)
    assert "env_name" in _labels(parser, NodeType.VARIABLE)


def test_non_ascii_source_produces_no_whitespace_only_labels(tmp_path: Path) -> None:
    """The corruption signature was nodes labelled with stray source fragments."""
    parser = _parse(
        tmp_path,
        "net.c",
        "/* " + "─" * 20 + " */\n"
        "int net_init(void) {\n"
        '    char *env_name = getenv("NAME");\n'
        "    strcpy(g_buf, env_name);\n"
        "    return 0;\n"
        "}\n",
    )

    named = [
        n
        for n in parser.nodes.values()
        if n.type in (NodeType.VARIABLE.value, NodeType.FUNCTION.value)
    ]
    assert named
    for node in named:
        assert node.label.strip() == node.label, f"padded label {node.label!r}"
        assert node.label, "empty label"
        assert "\n" not in node.label, f"multi-line label {node.label!r}"


def test_multibyte_string_literal_does_not_shift_later_spans(tmp_path: Path) -> None:
    parser = _parse(
        tmp_path,
        "net.c",
        'int greet(void) { printf("café ☕ naïve"); return 0; }\n'
        "int after(int marker) { return marker; }\n",
    )

    assert {"greet", "after"} <= _labels(parser, NodeType.FUNCTION)
    assert "marker" in _labels(parser, NodeType.VARIABLE)
