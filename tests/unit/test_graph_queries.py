"""Deterministic graph query tests."""

from __future__ import annotations

from rootai_semantic_parser.evaluation import EvaluationCase, evaluate_graph_queries
from rootai_semantic_parser.graph_queries import GraphQueryEngine, render_query_text


def _graph() -> dict:
    return {
        "nodes": [
            {"id": "a", "label": "handler", "type": "Function", "file": "app.py", "lineno": 1},
            {"id": "b", "label": "request.args", "type": "DataNode", "file": "app.py", "lineno": 2},
            {"id": "c", "label": "eval", "type": "Function", "file": "app.py", "lineno": 3},
        ],
        "edges": [
            {"source": "a", "target": "b", "relation": "dataflow"},
            {"source": "b", "target": "c", "relation": "dataflow"},
        ],
    }


def test_query_engine_finds_shortest_path() -> None:
    """Find a deterministic shortest path by label."""
    result = GraphQueryEngine(_graph()).execute("path source=handler target=eval relations=dataflow")
    assert result["found"] is True
    assert [node["label"] for node in result["nodes"]] == ["handler", "request.args", "eval"]
    assert render_query_text(result) == "handler -[dataflow]-> request.args -[dataflow]-> eval"


def test_evaluation_reports_path_correctness() -> None:
    """Evaluate a gold graph path case."""
    report = evaluate_graph_queries(
        _graph(),
        [
            EvaluationCase(
                name="handler_to_eval",
                query="path source=handler target=eval relations=dataflow",
                expected_labels=["handler", "request.args", "eval"],
            )
        ],
    )
    assert report.total == 1
    assert report.passed == 1
    assert report.path_correctness == 1.0
