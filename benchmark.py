"""Benchmark helpers for parser speed checks."""

from __future__ import annotations

import time
from dataclasses import dataclass

from core.runtime import MultiFileParser
from models import SecurityConfig


@dataclass
class BenchmarkResult:
    """Result of a benchmark parse run."""

    root: str
    seconds: float
    node_count: int
    edge_count: int


def benchmark_parse(root: str) -> BenchmarkResult:
    """Benchmark parsing for a target repository root."""
    start = time.perf_counter()
    parser = MultiFileParser(root, security_config=SecurityConfig.default_bugbounty())
    parser.parse_all()
    graph = parser.get_graph()
    elapsed = time.perf_counter() - start
    return BenchmarkResult(
        root=root,
        seconds=elapsed,
        node_count=len(graph.get("nodes", [])),
        edge_count=len(graph.get("edges", [])),
    )
