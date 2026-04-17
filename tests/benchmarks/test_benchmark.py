"""Benchmark smoke test."""

from __future__ import annotations

from pathlib import Path

from rootai_semantic_parser.benchmark import benchmark_parse


def test_benchmark_parse_smoke(tmp_path: Path) -> None:
    """Benchmark a tiny synthetic repo without failing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler(request):\n    return request.args\n", encoding="utf-8")
    result = benchmark_parse(str(repo))
    assert result.node_count > 0
    assert result.seconds >= 0
