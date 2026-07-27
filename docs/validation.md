# Validation Against Real Targets

The unit suite proves individual behaviours. The benchmark
(`tests/benchmarks/test_detection_benchmark.py`) proves them on miniature
applications this project wrote itself — which means it cannot show how the
scanner behaves on code written by other people.

`tools/validate_corpus.py` closes that gap by scanning real open-source
projects with known outcomes. It needs network access to clone, so it is not
part of the default test run:

```bash
python tools/validate_corpus.py --workdir /tmp/rootai-corpus
```

## Corpus design

Two kinds of target, because precision and recall fail independently.

**Deliberately vulnerable** applications measure recall. DVWA is the most
useful entry: it ships every module at four difficulty tiers, and
`impossible.php` is the *fixed* implementation. A finding there is
unambiguously a false positive, which gives a precision signal that does not
depend on anyone's judgement.

**Mature libraries** measure the false-positive rate on ordinary code. Flask
and Requests are heavily reviewed and have no known injection defects, so
whatever the scanner reports there is the noise floor a human would have to
wade through.

## Baseline

Measured on the commit that introduced this document.

| target | kind | findings | time | note |
|---|---|---:|---:|---|
| NodeGoat (`app/`) | vulnerable | 2 | 1.2s | documented SSJS injection and SSRF, both found |
| DVWA | vulnerable | 18 | 4.9s | 15 SQL injection, 3 RCE; **0 in `impossible.php`** |
| Flask (`src/`) | clean | 7 | 0.9s | see below |
| Requests (`src/`) | clean | 1 | 0.9s | its own URL fetch |

DVWA findings land in the low (6), medium (4) and high (3) tiers and none in
the fixed implementation, which is the strongest precision evidence available
without hand-auditing every result.

## What the clean-target findings actually are

They are **real data flows that are not vulnerabilities in context**. Flask's
`Config.from_pyfile` genuinely runs `exec(compile(config_file.read(), ...))`;
that is the feature. Requests genuinely fetches a URL it was handed.

This category is irreducible without understanding intent, and it is why the
tool is a triage aid rather than a submission source. Seven findings across a
mature framework is a few seconds of human review, which is the bar that
matters. Note these counts are pre-filter; a `semantic-parser scan` with the
bugbounty profile reports fewer.

## Sanitizers and validation guards

A flow that was already defended is reported at reduced severity with the
evidence attached, rather than identically to an undefended one.

**Sanitizers** are recognised in two kinds. *Escapers* (`shlex.quote`,
`escapeshellarg`, `html.escape`) defend the sink class they exist for, matched
by category. *Type coercions* (`int`, `parseInt`, `Integer.parseInt`) defend
every category, because a value parsed into a number cannot carry a payload for
any sink at all.

**Guards** are conditionals that test a value and abandon the path when it
fails, so downstream code only sees input that passed. `if (!ALLOWED.includes(c))
return;` constrains what `c` can be; `if (c.length > 100) return;` does not, and
is deliberately not treated as validation. The distinction is the line between
modelling guards and quietly dropping findings, and both directions are tested.

Findings carry `validation_guards` so an operator can see *why* a path was
downgraded rather than only that it was.

## HTTP route modelling

Entry points are read from route registrations rather than guessed from
function names. Call-based registration (`app.get(path, handler)`,
`router.post`, `http.HandleFunc`, Gin) and annotation- or decorator-based
declaration (Spring `@GetMapping`, ASP.NET `[HttpGet]`, Flask `@app.route`,
FastAPI `@app.get`) are all recognised, including handlers registered in one
file and declared in another.

This matters twice. It corrects the ranking — the name heuristic scored an
unrouted helper *above* a routed admin endpoint, because the helper's labels
happened to contain a word on the heuristic list. And it recovers the URL:
findings carry `routes`, so NodeGoat reports

    RCE   score 105  POST /contributions   contributions.js:32
    SSRF  score  85  GET /research         research.js:16

rather than naming a function. A URL is something an operator can go and test.

## Measured recall and precision: OWASP Benchmark

Everything above measures regressions, not accuracy. DVWA and NodeGoat document
vulnerability *classes*, not lines, so "18 findings" cannot be divided by
anything. OWASP BenchmarkJava can: it ships `expectedresults-1.2.csv` with a
real/not-real verdict and a CWE for each of 2,740 generated servlets, one test
case per file.

```bash
python tools/score_owasp_benchmark.py --benchmark /path/to/BenchmarkJava
```

Scored across the 1,572 cases in the six classes this scanner models as taint
flows. Weak randomness, hashing, cipher strength and cookie flags are excluded:
they are decided by a single API choice, a taint engine has nothing to say about
them, and including them would move the headline without measuring anything.

| category | cases | recall | FP rate | precision | score |
|---|---:|---:|---:|---:|---:|
| cmdi | 251 | 57.1% | 53.6% | 51.8% | +3.5% |
| sqli | 504 | 62.9% | 65.5% | 52.9% | −2.6% |
| xss | 455 | 63.4% | 72.2% | 50.8% | −8.8% |
| pathtraver | 268 | 75.2% | 79.3% | 48.3% | −4.1% |
| ldapi | 59 | 77.8% | 81.2% | 44.7% | −3.5% |
| xpathi | 35 | 80.0% | 90.0% | 40.0% | −10.0% |
| **all** | **1572** | **65.0%** | **69.2%** | **50.5%** | **−4.2%** |

"Score" is OWASP's own metric, recall minus false-positive rate. It is the only
column here that cannot be gamed by flagging everything, and **0% is what random
guessing achieves**. At −4.2% this scanner does not currently beat guessing on
this benchmark.

That number is the point of running it. Three defects it exposed have been
fixed, and one has not.

**Fixed — sinks were not language-scoped.** One flat sink list was applied to
every language, so PHP's `include` fired on Java's
`RequestDispatcher.include` and C's `system` fired on `System.out.println`.
Both appear in servlet boilerplate, so a large share of the suite was flagged
from code that carries no data. Before scoping, XSS scored 20.8% recall — every
one of which was this boilerplate landing in a file that happened to be a true
case. Genuine XSS recall was zero.

**Fixed — string literals were matched against source patterns.**
`println("Error processing request.")` contains the segment `request`, making
the literal a taint source. That line is in the catch block of nearly every
servlet written. Literal contents are now excluded, while interpolations inside
them (`"$QUERY_STRING"`, `f"ls {c}"`) are still read, since those are code.

**Fixed — whole sink families were missing.** Servlet response writers, LDAP
`DirContext.search`, XPath `evaluate`, and most of the `java.io` file
constructors were absent, which is why three categories scored 0% recall.

**Not fixed — no constant propagation.** Of the false positives remaining,
**58 of 95 in a sampled run are cases whose control flow is statically
determined by a constant**, and the rest are mostly the same shape reached
through a helper. Benchmark builds its safe cases by routing a genuinely
tainted value through a construct that provably discards it:

```java
bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;   // always the constant
char switchTarget = "ABC".charAt(1);                               // always 'B'
switch (switchTarget) { case 'A': bar = param; break;
                        case 'B': bar = "bob";  break; }            // always the constant
map.put("keyB", param); bar = (String) map.get("keyA");             // reads the other key
```

Every one is real dataflow by graph reachability and dead by evaluation. A
reachability engine cannot separate them, and no amount of sink tuning will:
the fix is constant propagation with branch elimination, which is the single
highest-value engine change available. Until it exists, expect the false
positive rate on this benchmark to stay near 70%.

### How much of this generalises

Benchmark is synthetic and adversarial by design — real code does not usually
guard a sink with an always-true ternary. The false-positive rate here is
therefore a **worst case**, not the rate on real targets; the corpus above still
reports 7 findings across all of Flask and 1 across Requests. The recall figure
generalises better, because the source-to-sink shapes are ordinary.

Read the two together: recall of 65% is the honest reach of the engine, and the
noise floor on real code is much lower than 69%.

## Known limits this exercise exposed

- **Recall is a floor, not a measurement.** These targets have documented
  vulnerability *classes*, not exhaustive line-level labels, so "18 findings on
  DVWA" does not mean 18 of N. Treat the numbers as regression detection.
- **Generated files are skipped**, not analysed. A 4.5MB minified bundle with
  600,000-character lines took longer to parse than an entire project.
  `looks_generated()` skips those and the scan reports how many, so the gap is
  visible rather than silent.
- **Routing coverage is per framework.** The registration styles listed above
  are modelled; anything else falls back to the name heuristic, which is weak.
  Middleware chains and dynamically built route tables are not followed.
