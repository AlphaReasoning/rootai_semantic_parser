# RootAI: Boundary-Reasoning Architecture

## The thesis

Injection is not "attacker data reached a dangerous function". It is **attacker
data changing the parse tree of another language**. Whether it can depends
entirely on where in that language's grammar the value lands.

A taint tracker cannot tell these four apart. They need four different fixes:

```
"SELECT * FROM t WHERE id = "   + x        comparison operand   parameterise
"SELECT * FROM t WHERE n = '"   + x + "'"  inside a literal     escape quotes
"SELECT * FROM t ORDER BY "     + x        an identifier        allowlist ONLY
"SELECT * FROM t WHERE id = ?", [x]        no hole at all       not injectable
```

The third is the one that ships. Escaping does nothing there, parameter binding
cannot even express that position, and teams who parameterised their `WHERE`
clause believe they are done. The fourth is provably safe and should never cost
a human a second of attention.

The same reasoning generalises past SQL. A value inside `<script>` is
JavaScript, so `html.escape` is the wrong encoding. A value in `href` can be
`javascript:`, which escaping permits. A value in shell command-name position
chooses which program runs, and `shlex.quote` does not help.

This is what "understands how one language interacts with another" means
concretely, and it is buildable today: tree-sitter ships the consumer grammars.

## What this is not

- Not a proof of exploitability. It reports positions and required defences.
- Not a replacement for judgement. It is the deterministic prior an LLM
  confirms against, which is the project's stated philosophy.
- Not a claim to find every bug. It will find a *class* of bug that taint
  tracking structurally cannot, and prove some flows safe that taint tracking
  reports.

## Layers

### L0 — Polyglot IR *(exists)*
18 languages to real syntax trees, symbol resolution, cross-file taint. Keep.
Add `LanguageBoundary` as a first-class node type.

### L1 — Boundary map
Every point a value crosses into another interpreter, typed by *which grammar
consumes it*:

| boundary | examples |
|---|---|
| embedded language | SQL, shell, HTML, XPath, LDAP, regex, template, format string |
| process | `exec`, `spawn`, `system` |
| serialization | pickle, YAML, `unserialize`, JSON→object |
| FFI | JNI, cgo, ctypes, N-API |
| config → runtime | env var reaching a command |

Today these are entries in one flat `sinks` set with no notion of what parses
the value. That set becomes a mapping to consumers.

### L2 — String reconstruction and hole context *(in progress)*
1. Walk back from the boundary through the host AST, rebuilding the string it
   constructs: literal parts, plus a hole token per runtime value. Constant
   folding (`analyzers/constants.py`) resolves parts that only *look* dynamic.
2. Parse that template with the consumer's grammar.
3. Classify each hole by its grammatical position.
4. Derive the required defence from the position.
5. Compare against the defence actually applied.

`analyzers/boundaries.py` implements 2–5 for SQL, shell and HTML. Step 1 is the
remaining work and is the harder half.

**Outcomes**: `SAFE` (defended, or no hole at all), `MISMATCH` (a defence was
applied and is the wrong kind — the finding class nothing else reports),
`UNDEFENDED`, `UNKNOWN` (position or defence unrecognised; degrade to taint).

### L3 — Differential analysis
Where a value is *validated* by one parser and *consumed* by another, the two
disagree. This is the "discrepancies and gaps" class:

- `urlparse` says the host is `example.com`; `curl` fetches `evil.com`
- a regex validates before a decode step the sink performs again
- a path check runs before normalisation the filesystem applies after

Starts as a curated `(validator, consumer)` table with known divergences, not a
solver. Partly open research; scoped deliberately small.

### L4 — Evidence bundle
The radar-to-AI handoff. Per candidate: reconstructed template, hole positions,
defences applied and their capabilities, the full path, the route/entry point,
and the *specific question* the model should answer. Replaces "RCE score 95".

### L5 — Tool stack
`scan` → `explain` → `confirm` (LLM triage loop) → `poc` → `fix`, with the
feedback DB learning from verified/rejected outcomes.

## Plan

Each step ends with tests and a measurable check. Ordering is by dependency,
and every step leaves the tool working.

### Step 1 — Boundary primitives ✅
`analyzers/boundaries.py`: consumer registry, hole classification, defence
capability vocabulary, verdicts. SQL/shell/HTML.
*Check*: 13 hand-built cases across three consumers classify correctly,
including four `MISMATCH` cases that taint analysis calls defended.

### Step 2 — Template reconstruction
Rebuild the consumed string from the host AST. Concatenation, interpolation,
f-strings, template literals, `.format`, `%`, `StringBuilder`, and constant
folding for parts that are effectively literal. Emit the template plus a hole
per runtime value onto the sink node.
*Check*: templates recovered for the same flows in all 18 host languages;
round-trip tests asserting hole count and literal parts.

### Step 3 — Sink-to-consumer mapping
Replace the flat sink set with typed boundaries. Each sink declares its
consumer grammar and which argument index is consumed.
*Check*: every sink in the bugbounty profile either maps to a consumer or is
explicitly recorded as unmapped, with no silent gaps.

### Step 4 — Wire verdicts into findings
Boundary verdict becomes part of the taint path: `SAFE` suppresses or
downgrades, `MISMATCH` promotes above ordinary undefended flows, evidence rides
along on the finding.
*Check*: OWASP Benchmark precision must not regress (regression floor, not a
target); DVWA `impossible.php` and the Flask/Requests noise floor hold.

### Step 5 — Corpus for what this actually does
Benchmark cannot measure boundary reasoning; it has no `ORDER BY` injection, no
script-context XSS, no wrong-escaper cases. Build a labelled corpus of
context-mismatch cases, hand-written and drawn from real CVEs.
*Check*: first honest recall/precision numbers for the capability that
differentiates the tool.

### Step 6 — Evidence bundle output
`semantic-parser explain <finding>` emitting the LLM-ready bundle; JSON schema
fixed so downstream tooling can depend on it.
*Check*: bundle contains template, positions, defences, path, route, question.

### Step 7 — More consumers
XPath, LDAP, regex (hand-written mini-parser; no tree-sitter grammar), template
engines, format strings, YAML/pickle deserialization.
*Check*: each consumer ships with mismatch cases in both directions.

### Step 8 — Confirmation loop (L5)
`confirm` subcommand driving an LLM over evidence bundles, writing outcomes to
the feedback DB, and tuning scores from verified/rejected history.
*Check*: end-to-end on a real target, with the feedback measurably changing
ranking.

### Step 9 — Differential analysis (L3)
Curated validator/consumer divergence table, starting with URL parsing and
path normalisation.
*Check*: detects the known SSRF filter-bypass shapes.

## Position on the existing work

The OWASP Benchmark scorer stays as a **regression floor, not a target**. It
measures single-language, single-file, one-sink-per-case injection — real, but
not what this tool is for. Tuning against it optimises the wrong thing; letting
it silently regress would mean the new architecture broke basic taint. It gets
run, not chased.

## Honest risks

- **Step 2 is the hard one.** Reconstructing strings across 18 languages,
  through helper functions and StringBuilder chains, will have gaps. Every gap
  degrades to `UNKNOWN` and ordinary taint reasoning, so it costs precision
  rather than findings — but the capability is only as good as this step.
- **Consumer grammars are approximations.** tree-sitter's SQL grammar is not
  any specific dialect. Position classification is robust to that; anything
  dialect-specific is not.
- **L3 is partly research.** Scoped as a curated table on purpose. If it stays
  a table, it is still useful; treating it as a solved problem would not be.
- **The corpus in Step 5 is work nobody else has done**, which is both why the
  capability is differentiated and why it cannot be validated off the shelf.
