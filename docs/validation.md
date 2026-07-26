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
| Flask (`src/`) | clean | 6 | 0.9s | see below |
| Requests (`src/`) | clean | 1 | 0.9s | its own URL fetch |

DVWA findings land in the low (6), medium (4) and high (3) tiers and none in
the fixed implementation, which is the strongest precision evidence available
without hand-auditing every result.

## What the clean-target findings actually are

They are **real data flows that are not vulnerabilities in context**. Flask's
`Config.from_pyfile` genuinely runs `exec(compile(config_file.read(), ...))`;
that is the feature. Requests genuinely fetches a URL it was handed.

This category is irreducible without understanding intent, and it is why the
tool is a triage aid rather than a submission source. Six findings across a
mature framework is a few seconds of human review, which is the bar that
matters. Note these counts are pre-filter; a `semantic-parser scan` with the
bugbounty profile reports fewer.

## Known limits this exercise exposed

- **Recall is a floor, not a measurement.** These targets have documented
  vulnerability *classes*, not exhaustive line-level labels, so "18 findings on
  DVWA" does not mean 18 of N. Treat the numbers as regression detection.
- **Generated files are skipped**, not analysed. A 4.5MB minified bundle with
  600,000-character lines took longer to parse than an entire project.
  `looks_generated()` skips those and the scan reports how many, so the gap is
  visible rather than silent.
- **No framework routing.** Entry points are inferred from names, so a
  vulnerability reachable only through a framework's routing table may be
  missed.
