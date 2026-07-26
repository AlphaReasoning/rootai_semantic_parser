"""Tests for what taint analysis propagates through, and what it refuses to.

Two levels are covered: the analyzer's relation policy and seeding rules, tested
against hand-built graphs, and end-to-end source-to-sink detection per language,
tested through MultiFileParser. Each end-to-end case is paired with a negative
control using a constant, so a test passing cannot simply mean "reports
everything".
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from rootai_semantic_parser.analyzers.taint import TaintAnalyzer
from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import (
    AnalysisOptions,
    EdgeRelation,
    SecurityConfig,
    TaintConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node(
    node_id: str,
    label: str,
    *,
    is_unsafe: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": node_id,
        "label": label,
        "type": "Variable",
        "file": "x.c",
        "lineno": 1,
        "is_unsafe": is_unsafe,
        "metadata": metadata or {},
    }


def _edge(source: str, target: str, relation: EdgeRelation, **metadata: Any) -> Dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "relation": relation.value,
        "fragility_score": 0.5,
        "metadata": metadata,
    }


def _run(nodes: List[Dict], edges: List[Dict]) -> List:
    config = TaintConfig(sources={"getenv"}, sinks={"system"}, sanitizers=set())
    analyzer = TaintAnalyzer(
        {"nodes": nodes, "edges": edges},
        config,
        options=AnalysisOptions(min_score=0.0),
    )
    return analyzer.run()


def _scan(files: Dict[str, str]) -> List[Dict]:
    directory = tempfile.mkdtemp()
    for name, body in files.items():
        target = Path(directory) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    parser = MultiFileParser(
        directory,
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


def _explanations(paths: List[Dict]) -> List[str]:
    return [p["explanation"] for p in paths]


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def test_matching_source_keyword_seeds_taint() -> None:
    paths = _run(
        [_node("a", "getenv"), _node("b", "system")],
        [_edge("a", "b", EdgeRelation.DATAFLOW)],
    )
    assert len(paths) == 1


def test_is_unsafe_alone_does_not_seed_taint() -> None:
    """Regression: is_unsafe marks memory-unsafe constructs, not attacker control.

    Seeding from it made every pointer parameter a taint source.
    """
    paths = _run(
        [_node("a", "some_pointer", is_unsafe=True), _node("b", "system")],
        [_edge("a", "b", EdgeRelation.DATAFLOW)],
    )
    assert paths == []


def test_parser_declared_taint_source_seeds_taint() -> None:
    """A parser can know a value is tainted when the label does not say so."""
    paths = _run(
        [
            _node("a", "buf", metadata={"is_taint_source": True, "tainted_by": "read"}),
            _node("b", "system"),
        ],
        [_edge("a", "b", EdgeRelation.DATAFLOW)],
    )
    assert len(paths) == 1


def test_parser_declared_sink_is_honoured() -> None:
    """Rust resolves Command::new to a sink via `use`; the label still says otherwise."""
    paths = _run(
        [
            _node("a", "getenv"),
            _node("b", "Command::new(&cmd).output", metadata={"is_taint_sink": True}),
        ],
        [_edge("a", "b", EdgeRelation.DATAFLOW)],
    )
    assert len(paths) == 1


def test_node_matching_source_and_sink_is_not_a_finding() -> None:
    """Regression: one label satisfying both keyword sets produced `system -> system`."""
    paths = _run([_node("a", "getenv_system")], [])
    assert paths == []


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


def _match(label: str, pattern: str) -> bool:
    return TaintAnalyzer._pattern_matches(TaintAnalyzer._segments(label), pattern)


def test_segments_split_an_expression_into_identifier_names() -> None:
    assert TaintAnalyzer._segments("os.system(cmd)") == ("os", "system", "cmd")
    assert TaintAnalyzer._segments("ctx->recv_buf") == ("ctx", "recv_buf")
    assert TaintAnalyzer._segments("Command::new(&value)") == ("command", "new", "value")


def test_ssa_suffixes_are_stripped_before_matching() -> None:
    """Parsers version bindings, so a pattern must still match user_input_v2."""
    assert TaintAnalyzer._segments("user_input_v12") == ("user_input",)
    assert _match("user_input_v2", "user_input")


def test_single_name_pattern_requires_a_whole_segment() -> None:
    """Regression: plain substring containment was the dominant FP source."""
    assert _match("eval(payload)", "eval")
    assert not _match("EvaluationCase", "eval")
    assert not _match("evaluate_graph_queries", "eval")
    assert not _match("load_evaluation_cases", "eval")

    assert _match("exec(code)", "exec")
    assert not _match("cursor.execute", "exec")
    assert not _match("GraphQueryEngine.execute", "exec")
    assert not _match("_render_execute_step", "exec")

    assert _match("read(fd, buf, n)", "read")
    assert not _match("test_multibyte_literals_are_read_intact", "read")

    assert _match("system(cmd)", "system")
    assert not _match("reaching_system_v1", "system")


def test_dotted_pattern_matches_a_consecutive_run_of_segments() -> None:
    assert _match("os.system(cmd)", "os.system")
    assert _match("result = os.system(cmd)", "os.system")
    assert not _match("os.path.join(a, b)", "os.system")
    assert not _match("system.os", "os.system")


def test_scoped_pattern_matches_rust_and_c_forms() -> None:
    assert _match("std::mem::transmute(x)", "std::mem::transmute")
    assert not _match("mem::transmute_copy", "std::mem::transmute")


def test_matching_is_case_insensitive() -> None:
    assert _match("OS.System(cmd)", "os.system")


# ---------------------------------------------------------------------------
# Relation policy
# ---------------------------------------------------------------------------


def test_structural_relations_do_not_carry_taint() -> None:
    """contains/imports/drops/lifetime_bounds describe structure, not data."""
    for relation in (
        EdgeRelation.CONTAINS,
        EdgeRelation.IMPORTS,
        EdgeRelation.DROPS,
        EdgeRelation.LIFETIME_BOUNDS,
        EdgeRelation.MOVES,
    ):
        paths = _run(
            [_node("a", "getenv"), _node("b", "system")],
            [_edge("a", "b", relation)],
        )
        assert paths == [], relation.value


def test_value_carrying_relations_propagate() -> None:
    for relation in (
        EdgeRelation.DATAFLOW,
        EdgeRelation.UNSAFE_DEREFERENCE,
        EdgeRelation.POINTER_ARITH,
        EdgeRelation.BORROWS,
        EdgeRelation.MACRO_EXPANDS_TO,
    ):
        paths = _run(
            [_node("a", "getenv"), _node("b", "system")],
            [_edge("a", "b", relation)],
        )
        assert len(paths) == 1, relation.value


def test_field_access_propagates_in_both_directions() -> None:
    """A tainted struct yields tainted members, and a tainted member taints reads."""
    forward = _run(
        [_node("s", "getenv"), _node("f", "system")],
        [_edge("s", "f", EdgeRelation.FIELD_ACCESS)],
    )
    assert len(forward) == 1

    backward = _run(
        [_node("s", "system"), _node("f", "getenv")],
        [_edge("s", "f", EdgeRelation.FIELD_ACCESS)],
    )
    assert len(backward) == 1


def test_a_call_edge_alone_does_not_carry_data() -> None:
    """Regression: calls are control flow, not data flow.

    Propagating along the call edge, combined with treating a parameter edge as
    value flow into its function, meant any tainted value in a function
    implicated everything that function invoked -- a parameter merely named
    "req" was enough. Data reaches a callee through argument_binding.
    """
    paths = _run(
        [_node("a", "getenv"), _node("b", "system")],
        [_edge("a", "b", EdgeRelation.CALLS)],
    )
    assert paths == []


def test_declaration_edges_do_not_carry_data() -> None:
    """function -> parameter / -> local records a declaration, not a transfer."""
    for flow_kind in ("parameter", "binding", "local_decl", "let_binding"):
        paths = _run(
            [_node("fn", "getenv"), _node("var", "system")],
            [_edge("fn", "var", EdgeRelation.DATAFLOW, flow_kind=flow_kind)],
        )
        assert paths == [], flow_kind


def test_argument_binding_carries_data_into_a_parameter() -> None:
    """This is how a value actually reaches a callee."""
    paths = _run(
        [_node("arg", "getenv"), _node("param", "system")],
        [_edge("arg", "param", EdgeRelation.DATAFLOW, flow_kind="argument_binding")],
    )
    assert len(paths) == 1


def test_non_parameter_dataflow_keeps_its_direction() -> None:
    paths = _run(
        [_node("a", "getenv"), _node("b", "system")],
        [_edge("b", "a", EdgeRelation.DATAFLOW, flow_kind="assignment")],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# End to end: C
# ---------------------------------------------------------------------------


def test_c_input_buffer_reaches_command_sink() -> None:
    """read() taints the destination buffer, which then reaches system()."""
    paths = _scan(
        {
            "src/n.c": "struct ctx { int fd; char recv_buf[256]; };\n"
            "void handle(struct ctx *c) {\n"
            "    read(c->fd, c->recv_buf, 256);\n"
            "    system(c->recv_buf);\n"
            "}\n"
        }
    )
    assert any("system" in text and "recv_buf" in text for text in _explanations(paths)), _explanations(paths)


def test_c_taint_flows_through_a_string_copy() -> None:
    """The copy destination must be reachable from the getenv-derived source.

    Asserted as "external input reaches system()" rather than as one exact route:
    several equal-scoring routes exist here, and the enclosing function sits on a
    two-edge cycle (function -> local declaration, local -> function for a taint
    source), so which route is rendered is not a stable property.
    """
    paths = _scan(
        {
            "src/g.c": "int init(void) {\n"
            '    char *env_name = getenv("NAME");\n'
            "    char dst[64];\n"
            "    strcpy(dst, env_name);\n"
            "    system(dst);\n"
            "    return 0;\n"
            "}\n"
        }
    )
    reaching_system = [p for p in paths if "system" in p["explanation"]]
    assert reaching_system, _explanations(paths)
    assert any("env_name" in p["explanation"] for p in reaching_system), _explanations(paths)


def test_analysis_of_one_graph_is_reproducible() -> None:
    """Same graph in, same findings out.

    Ties used to be broken by set iteration order and by ``<`` on frozensets in
    the priority queue, so equally scored routes came out in a different order
    between runs -- which breaks baselines and suppression fingerprints.
    """
    nodes = [
        _node("src", "getenv"),
        _node("mid_a", "copy_a"),
        _node("mid_b", "copy_b"),
        _node("sink", "system"),
    ]
    edges = [
        _edge("src", "mid_a", EdgeRelation.DATAFLOW),
        _edge("src", "mid_b", EdgeRelation.DATAFLOW),
        _edge("mid_a", "sink", EdgeRelation.DATAFLOW),
        _edge("mid_b", "sink", EdgeRelation.DATAFLOW),
    ]

    runs = [[p.explanation for p in _run(nodes, edges)] for _ in range(5)]
    assert all(result == runs[0] for result in runs), runs


def test_c_macro_expanding_to_a_sink_is_treated_as_that_sink() -> None:
    """UNSAFE_FMT's own name carries no evidence that it reaches sprintf."""
    paths = _scan(
        {
            "src/m.c": "#define UNSAFE_FMT(buf, fmt) sprintf((buf), (fmt))\n"
            "void handle(int fd) {\n"
            "    char log_buf[512];\n"
            "    char data[256];\n"
            "    read(fd, data, 256);\n"
            "    UNSAFE_FMT(log_buf, data);\n"
            "}\n"
        }
    )
    assert any("UNSAFE_FMT" in text for text in _explanations(paths)), _explanations(paths)


def test_c_macro_expanding_to_a_bounded_call_is_not_a_sink() -> None:
    """Negative control: strncpy is bounded, so SAFE_COPY must not be a sink."""
    paths = _scan(
        {
            "src/m.c": "#define SAFE_COPY(d, s, n) strncpy((d), (s), (n))\n"
            "void handle(int fd) {\n"
            "    char a[64];\n"
            "    char b[64];\n"
            "    read(fd, b, 64);\n"
            "    SAFE_COPY(a, b, 63);\n"
            "}\n"
        }
    )
    assert not any("SAFE_COPY" in text for text in _explanations(paths)), _explanations(paths)


def test_c_input_buffers_do_not_leak_between_functions() -> None:
    """Two callers of read() must not appear to taint each other's buffers."""
    paths = _scan(
        {
            "src/m.c": "void first(int fd) {\n"
            "    char alpha[64];\n"
            "    read(fd, alpha, 64);\n"
            "}\n"
            "void second(int fd) {\n"
            "    char beta[64];\n"
            "    read(fd, beta, 64);\n"
            "    system(beta);\n"
            "}\n"
        }
    )
    reaching = [p for p in paths if "system" in p["explanation"]]
    assert reaching, _explanations(paths)
    assert not any("alpha" in p["explanation"] for p in reaching), _explanations(paths)


def test_c_constant_argument_is_not_reported() -> None:
    """Negative control: nothing external reaches the sink."""
    paths = _scan(
        {
            "src/s.c": "int safe(void) {\n"
            "    char buf[64];\n"
            '    strncpy(buf, "constant", 63);\n'
            "    system(buf);\n"
            "    return 0;\n"
            "}\n"
        }
    )
    assert paths == [], _explanations(paths)


# ---------------------------------------------------------------------------
# End to end: Rust
# ---------------------------------------------------------------------------


RUST_MANIFEST = '[package]\nname = "demo"\nversion = "0.1.0"\n'


def test_rust_env_var_reaches_command_sink_through_a_binding() -> None:
    """Requires `use` resolution: the sink pattern is std::process::Command."""
    paths = _scan(
        {
            "Cargo.toml": RUST_MANIFEST,
            "src/lib.rs": "use std::env;\n"
            "use std::process::Command;\n"
            "pub fn handler() {\n"
            '    let cmd = env::var("USER_CMD").unwrap_or_default();\n'
            "    let out = Command::new(&cmd).output();\n"
            "}\n",
        }
    )
    assert any("cmd" in text and "Command::new" in text for text in _explanations(paths)), _explanations(paths)


def test_rust_constant_argument_is_not_reported() -> None:
    """Negative control: the command name is a literal."""
    paths = _scan(
        {
            "Cargo.toml": RUST_MANIFEST,
            "src/lib.rs": "use std::process::Command;\n"
            "pub fn safe_path() {\n"
            '    let fixed = "ls".to_string();\n'
            "    let out = Command::new(&fixed).output();\n"
            "}\n",
        }
    )
    assert paths == [], _explanations(paths)


# ---------------------------------------------------------------------------
# End to end: Python must not regress
# ---------------------------------------------------------------------------


def test_python_request_to_os_system_still_detected() -> None:
    paths = _scan(
        {
            "app.py": "from flask import request\n"
            "import os\n\n"
            "@app.route('/run')\n"
            "def run_cmd():\n"
            "    user_input = request.args.get('cmd')\n"
            "    os.system(user_input)\n"
        }
    )
    assert any("os.system" in text for text in _explanations(paths)), _explanations(paths)


def test_python_constant_command_is_not_reported() -> None:
    paths = _scan(
        {
            "safe.py": "import os\n\n"
            "def run_fixed():\n"
            "    cmd = 'ls -la'\n"
            "    os.system(cmd)\n"
        }
    )
    assert paths == [], _explanations(paths)
