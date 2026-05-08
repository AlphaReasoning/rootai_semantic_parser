# Platform Roadmap

This repository now includes:

- precise inter-procedural taint propagation across calls and returns
- formal IR contract with node taxonomy, edge ontology, and explicit non-claims
- deterministic graph query engine for paths, cones, SCCs, and centrality
- static Python import resolution and attribute-aware data-flow nodes
- context-aware sanitizer tracking
- framework-aware heuristics for FastAPI, Spring, Gin, and basic C#
- suppression of test/dead-code paths via scoring
- incremental parsing via cache plus changed-file analysis between commits
- CI outputs, SARIF, defensive submission exports, and validation helpers

Hosted/cloud mode, team sharing, and the plugin marketplace are represented as local scaffolds in this repo:

- `cloud-mode` emits the bundle/manifest the hosted service would consume
- suppression files and feedback databases are team-shareable JSON artifacts
- `plugins/marketplace.json` is the local marketplace index seed
