"""Evaluation harness for deterministic semantic graph queries."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from graph_queries import GraphQueryEngine, GraphQueryError


@dataclass
class EvaluationCase:
    """A gold query case for graph/path correctness evaluation."""

    name: str
    query: str
    expected_labels: List[str] = field(default_factory=list)
    expected_found: bool = True


@dataclass
class EvaluationCaseResult:
    """Result for a single evaluation case."""

    name: str
    passed: bool
    seconds: float
    query: str
    error: str = ""
    expected_labels: List[str] = field(default_factory=list)
    actual_labels: List[str] = field(default_factory=list)


@dataclass
class EvaluationReport:
    """Aggregate deterministic-query evaluation report."""

    total: int
    passed: int
    failed: int
    seconds: float
    path_correctness: float
    hallucination_rate: float
    cases: List[EvaluationCaseResult]

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON."""
        return json.dumps(asdict(self), indent=indent)


def load_evaluation_cases(path: str) -> List[EvaluationCase]:
    """Load evaluation cases from JSON."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    items = raw.get("cases", raw if isinstance(raw, list) else [])
    return [
        EvaluationCase(
            name=str(item.get("name", f"case_{index}")),
            query=str(item["query"]),
            expected_labels=[str(label) for label in item.get("expected_labels", [])],
            expected_found=bool(item.get("expected_found", True)),
        )
        for index, item in enumerate(items)
    ]


def evaluate_graph_queries(graph: Dict[str, Any], cases: List[EvaluationCase]) -> EvaluationReport:
    """Evaluate deterministic graph queries against gold labels."""
    engine = GraphQueryEngine(graph)
    started = time.perf_counter()
    results: List[EvaluationCaseResult] = []
    for case in cases:
        case_started = time.perf_counter()
        try:
            result = engine.execute(case.query)
            actual_labels = [str(node.get("label", "")) for node in result.get("nodes", [])]
            found = bool(result.get("found", True))
            label_match = not case.expected_labels or actual_labels == case.expected_labels
            passed = found == case.expected_found and label_match
            results.append(
                EvaluationCaseResult(
                    name=case.name,
                    passed=passed,
                    seconds=time.perf_counter() - case_started,
                    query=case.query,
                    expected_labels=case.expected_labels,
                    actual_labels=actual_labels,
                )
            )
        except (GraphQueryError, KeyError, TypeError, ValueError) as exc:
            results.append(
                EvaluationCaseResult(
                    name=case.name,
                    passed=not case.expected_found,
                    seconds=time.perf_counter() - case_started,
                    query=case.query,
                    error=str(exc),
                    expected_labels=case.expected_labels,
                )
            )

    elapsed = time.perf_counter() - started
    passed_count = sum(1 for result in results if result.passed)
    failed_count = len(results) - passed_count
    correctness = passed_count / len(results) if results else 0.0
    hallucination_rate = failed_count / len(results) if results else 0.0
    return EvaluationReport(
        total=len(results),
        passed=passed_count,
        failed=failed_count,
        seconds=elapsed,
        path_correctness=correctness,
        hallucination_rate=hallucination_rate,
        cases=results,
    )
