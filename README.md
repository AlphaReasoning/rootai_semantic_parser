---
title: RootAI Semantic Parser
emoji: 🛡️
colorFrom: blue
colorTo: gray
sdk: docker
app_port: 7860
pinned: true
license: apache-2.0
---

# RootAI Sovereign Command Deck

RootAI is a semantic analysis and taint-reasoning system for real codebases. Instead of stopping at text matching, it turns source code into a semantic graph, traces untrusted data through that graph, and explains why a sink matters with a guided visual interface.

This Hugging Face Space is built as a live command deck:
- easy repository intake from Git URL, ZIP, or local path
- visible automation transcript so the engine never feels hidden
- visual taint-path storytelling from source to sink
- graph context around each selected finding
- export-ready outputs for reports, demos, CI, and follow-up work

## Why This Project Stands Out

RootAI is designed around five ideas that matter in a showcase:

- **Clarity:** each step explains what the system is doing and why
- **Usefulness:** users can point it at a real repository and get actionable output quickly
- **Creativity:** findings are visualized as semantic paths and graph relationships, not just tables
- **Execution:** the flow runs end to end from intake to export
- **Usability:** advanced controls exist, but the default path stays approachable

## Guided Experience

The UI is organized into five steps:

1. **Ingest**  
   Stage a repository from a public Git URL, uploaded ZIP, or local path.

2. **Configure**  
   Choose a preset, tune scan depth, and optionally load custom profiles, rulesets, suppressions, baselines, feedback, CVE feeds, or external graph snapshots.

3. **Execute**  
   Watch the automated CLI-style transcript as RootAI walks the repo, parses files, merges the graph, ranks taint paths, and assembles the final report.

4. **Understand**  
   Inspect findings with a path cinema view, trust-boundary explanation, and a graph map that highlights the selected taint route.

5. **Export**  
   Download JSON, Markdown, HTML, SARIF, annotation payloads, PoC hints, submission drafts, and graph snapshots.

## Product Surface

- **Use Case Mode selector:** Security Analysis, Code Understanding, and AI Audit
- **Preloaded examples:** tiny built-in repos that make the tool’s value obvious immediately
- **Deterministic query surface:** ask the graph directly with `path`, `cone`, `centrality`, and `scc`
- **Insight panel:** concise output that explains why a path matters
- **Trace path view:** explicit source → transformation → sink path display
- **Persistence:** save and reload sessions locally
- **Metrics:** nodes, edges, taint paths, cache hits, and confidence drift
- **Exports:** JSON, Neo4j-style graph Cypher, and PDF security report artifacts
- **API hook:** optional FastAPI endpoints for parse, query, and graph retrieval

## Best Demo Path

If you want the fastest strong demo:

1. Paste a public Git URL into **Ingest**
2. Keep **Demo Mode** selected in **Configure**
3. Run the scan in **Execute**
4. Open **Understand**
5. Select the top finding and replay the path from source to sink

That path shows the repo intake, visible machine workflow, semantic reasoning, and useful output in under a minute.

## Command Deck Capabilities

- **Polyglot parsing:** 18 languages — Python, JavaScript, TypeScript, TSX, Go, Java, C#, PHP, Ruby, Rust, C, C++, Objective-C, Kotlin, Swift, Scala, Lua, R and Bash. Every one is parsed to a real syntax tree (Python via `ast`, the rest via tree-sitter), contributes data-flow edges, and resolves calls into the function bodies they enter, so a source in one function reaching a sink in another is detected. Each language is covered by a detection test *and* a constant-input control in `tests/unit/test_polyglot.py`; grammars evaluated and not shipped are recorded with reasons in `parsers/generic_engine.py:UNSUPPORTED_LANGUAGES`
- **Formal semantic IR:** versioned node taxonomy, edge ontology, and explicit soundness/completeness boundaries
- **Deterministic graph queries:** BFS, DFS, shortest path, reachability cones, SCCs, and degree centrality without LLM path computation
- **Semantic graph construction:** nodes and edges representing structure, imports, relationships, and flow
- **Taint analysis:** multi-hop defensive source-to-sink tracing with severity and impact scoring
- **Operator controls:** profiles, quick mode, cache control, reachability heuristics, auth heuristics, exclusions
- **Power inputs:** custom config, custom finding profile, ruleset extension, suppressions, baseline, feedback DB, CVE feed, external graph snapshots
- **Operator exports:** raw JSON, Markdown, HTML, SARIF, CI annotations, PoC helper payloads, submission drafts
- **Snapshot lab:** download and diff graph snapshots between runs

## Research Framing

RootAI is best described as a **deterministic structural prior for LLM code reasoning**. The graph engine computes structure, paths, cones, centrality, SCCs, import links, and taint propagation deterministically; an LLM can interpret those results, but it should not be responsible for discovering the path.

Safe security positioning:

- automated privilege-boundary detection
- dependency blast-radius modeling
- high-centrality risk surfacing
- defensive taint and trust-boundary review

Non-claims:

- not formal verification
- not guaranteed exploitability proof
- not bypass or exploit-generation tooling

## Local Run

### Runtime Install

```bash
python3 -m pip install .
```

This installs system or virtualenv console commands:

```bash
semantic-parser --help
rootai-semantic-parser --help
rootai --help
```

### Development Install

```bash
python3 -m pip install -r requirements-dev.txt
```

### Launch The UI

```bash
python3 -m streamlit run app.py --server.port 7860 --server.address 0.0.0.0
```

## CLI Usage

### Help

```bash
semantic-parser --help
python3 -m rootai_semantic_parser --help
```

### Example Scan

```bash
semantic-parser --profile human-only --min-score 6.5 /path/to/repo scan --format bounty-json
```

### Example Bug Bounty Scan

```bash
semantic-parser --profile bugbounty --min-score 4.5 /path/to/repo scan --format bounty-json
```

### Example Custom Profile

```bash
semantic-parser --profile-file ./custom-profile.json /path/to/repo bounty-report
```

### Formal IR Spec

```bash
semantic-parser ir-spec
```

### Deterministic Graph Query

```bash
semantic-parser /path/to/repo query --expr "path source=handler target=eval relations=dataflow,calls depth=8" --format text
```

### Evaluation Suite

```bash
semantic-parser /path/to/repo evaluate --cases cases.json
```

## Docker

### Build

```bash
docker build -t rootai-semantic-parser .
```

### Run

```bash
docker run --rm -p 7860:7860 rootai-semantic-parser
```

## Hugging Face Deployment

This Space is designed to be uploaded directly from:

`/home/alphareasoning/rootai_semantic_parser`

Use the same direct workflow:

```bash
cd /home/alphareasoning/rootai_semantic_parser
hf upload alpha-reasoning/rootai-semantic-parser . . --repo-type space \
  --exclude ".venv/*" \
  --exclude "**/__pycache__/*" \
  --exclude "*.pyc" \
  --exclude ".pytest_cache/*" \
  --exclude ".mypy_cache/*" \
  --exclude ".ruff_cache/*" \
  --exclude ".streamlit/secrets.toml" \
  --exclude ".env" \
  --exclude ".env.*" \
  --exclude "*.log"
```

The Space runs through the included `Dockerfile`, which launches Streamlit on port `7860`.

## Export Guide

- `scan-report.json`: raw machine-readable result bundle
- `bounty-report.md`: human-readable writeup
- `bounty-report.html`: shareable interactive report
- `rootai.sarif`: CI/static-analysis integrations
- `poc-hints.json`: payload and reproduction guidance
- `graph-snapshot.json`: before/after graph comparison input

## Project Status

Challenge-ready UI, parser integration, deployment-safe ignore protection, and focused verification are in place.

**alpha-reasoning lab | RootAI semantic parser | 2026-04-24**
