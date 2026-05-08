# Evaluation Protocol

The project now includes a deterministic query evaluation harness. It measures graph/query behavior directly and leaves any LLM interpretation as a separate layer.

## Baselines To Compare

For research reporting, compare these modes on the same task set:

- raw LLM over source files
- LLM over full AST or parser JSON
- LLM over reduced dependency cone
- deterministic graph query plus LLM interpretation

The deterministic mode should be evaluated without an LLM first. That gives measurable path correctness and runtime before any narrative explanation is added.

## Metrics

- `accuracy`: task-level pass rate against gold cases
- `path_correctness`: exact expected-label path match for graph path cases
- `hallucination_rate`: deterministic query failure or path mismatch rate
- `time_to_answer`: wall-clock seconds per case
- `unresolved_calls`: unresolved static call/import endpoints from graph resolution stats

## Case Format

```json
{
  "cases": [
    {
      "name": "handler_to_eval",
      "query": "path source=handler target=eval relations=dataflow,calls depth=8",
      "expected_labels": ["handler", "request.args", "eval"],
      "expected_found": true
    }
  ]
}
```

Run against a repository:

```bash
semantic-parser /path/to/repo evaluate --cases cases.json
```

Run against a saved graph snapshot:

```bash
semantic-parser . evaluate --snapshot graph-snapshot.json --cases cases.json
```

## Query DSL

Examples:

```bash
semantic-parser /path/to/repo query --expr "path source=handler target=eval relations=dataflow,calls depth=8"
semantic-parser /path/to/repo query --expr "cone start=handler direction=out depth=2 relations=calls,dataflow" --format text
semantic-parser /path/to/repo query --expr "centrality relations=calls,dataflow limit=20" --format text
semantic-parser /path/to/repo query --expr "scc relations=calls min_size=2"
```

Supported commands are `path`, `reachable`, `cone`, `bfs`, `dfs`, `centrality`, and `scc`.
