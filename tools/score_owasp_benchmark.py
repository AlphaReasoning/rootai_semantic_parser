#!/usr/bin/env python3
"""Score the scanner against OWASP BenchmarkJava's published ground truth.

Every other target this project validates against has documented vulnerability
*classes*, not line-level labels, so "18 findings on DVWA" is regression
detection rather than measurement. BenchmarkJava is different: it ships
``expectedresults-1.2.csv``, giving a real/not-real verdict and a CWE for each
of 2,740 generated test cases. That is what a recall number requires.

Each test case is one self-contained servlet in one file, so a finding maps to
a case by file name. A case counts as flagged if the scan reports any taint
path in its file.

Categories the scanner does not attempt -- weak randomness, hashing, crypto
strength, cookie flags -- are excluded by default and reported separately.
Scoring a taint engine on `Math.random()` measures nothing about the engine and
inflates or deflates the headline number depending on which way you round.

    python tools/score_owasp_benchmark.py --benchmark /path/to/BenchmarkJava

Add ``--all-categories`` to score the out-of-scope classes too, ``--category
sqli`` to narrow, and ``--limit N`` to sample while iterating.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import AnalysisOptions, SecurityConfig, TaintConfig  # noqa: E402
from core.runtime import MultiFileParser  # noqa: E402

BENCHMARK_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"

#: Vulnerability classes this scanner models as taint source-to-sink flows.
#: These are the ones a recall figure is meaningful for.
IN_SCOPE = {
    "cmdi": "Command injection",
    "sqli": "SQL injection",
    "xss": "Cross-site scripting",
    "pathtraver": "Path traversal",
    "ldapi": "LDAP injection",
    "xpathi": "XPath injection",
}

#: Classes decided by a single API choice rather than by data flow. A taint
#: engine has nothing to say about them; they are scored only under
#: --all-categories, and always reported apart from the headline.
OUT_OF_SCOPE = {
    "weakrand": "Weak randomness (API choice, not data flow)",
    "hash": "Weak hash (API choice, not data flow)",
    "crypto": "Weak cipher (API choice, not data flow)",
    "securecookie": "Missing cookie flag (absence of a call)",
    "trustbound": "Trust-boundary violation (session write, not a sink)",
}


@dataclass
class Case:
    name: str
    category: str
    is_real: bool
    cwe: int
    flagged: bool = False
    findings: List[str] = field(default_factory=list)


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def recall(self) -> Optional[float]:
        """Of the genuinely vulnerable cases, the share that was flagged."""
        real = self.tp + self.fn
        return self.tp / real if real else None

    @property
    def fpr(self) -> Optional[float]:
        """Of the safe cases, the share flagged anyway."""
        safe = self.fp + self.tn
        return self.fp / safe if safe else None

    @property
    def precision(self) -> Optional[float]:
        flagged = self.tp + self.fp
        return self.tp / flagged if flagged else None

    @property
    def youden(self) -> Optional[float]:
        """OWASP's own headline score: recall - false positive rate.

        0.0 is what random guessing achieves at any threshold, which makes it
        the only number here that cannot be gamed by flagging everything.
        """
        if self.recall is None or self.fpr is None:
            return None
        return self.recall - self.fpr


def load_expected(benchmark: Path) -> Dict[str, Case]:
    csv_path = benchmark / "expectedresults-1.2.csv"
    if not csv_path.exists():
        raise SystemExit(f"ground truth not found: {csv_path}")
    cases: Dict[str, Case] = {}
    with csv_path.open(encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].lstrip().startswith("#"):
                continue
            name, category, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            cases[name] = Case(name, category, real.lower() == "true", int(cwe))
    return cases


def ensure_benchmark(benchmark: Optional[str], workdir: Path) -> Path:
    if benchmark:
        path = Path(benchmark).expanduser().resolve()
        if not path.exists():
            raise SystemExit(f"--benchmark path does not exist: {path}")
        return path
    target = workdir / "BenchmarkJava"
    if not target.exists():
        print(f"cloning {BENCHMARK_URL} -> {target}", flush=True)
        workdir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", BENCHMARK_URL, str(target)],
            check=True,
            capture_output=True,
        )
    return target


def select_cases(
    cases: Dict[str, Case], categories: Optional[Sequence[str]], all_categories: bool, limit: Optional[int]
) -> List[Case]:
    if categories:
        wanted: Set[str] = set(categories)
    elif all_categories:
        wanted = set(IN_SCOPE) | set(OUT_OF_SCOPE)
    else:
        wanted = set(IN_SCOPE)
    selected = [c for c in cases.values() if c.category in wanted]
    selected.sort(key=lambda c: c.name)
    if limit:
        # Stride rather than truncate, so a sample keeps the category mix.
        step = max(1, len(selected) // limit)
        selected = selected[::step][:limit]
    return selected


def stage(testcode: Path, selected: Iterable[Case], destination: Path) -> int:
    """Copy the selected cases into a flat directory the scanner can walk.

    Scanning the repository in place would also pull in the harness, helpers
    and crawler, whose findings belong to no test case and would be discarded
    anyway.
    """
    destination.mkdir(parents=True, exist_ok=True)
    staged = 0
    for case in selected:
        source = testcode / f"{case.name}.java"
        if source.exists():
            shutil.copy2(source, destination / source.name)
            staged += 1
    return staged


def scan(directory: Path, profile: str, min_score: float) -> List[Dict]:
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile=profile, min_score=min_score),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile(profile)).taint_paths


def attribute(paths: List[Dict], cases: Dict[str, Case]) -> None:
    """Mark each case whose file produced at least one finding."""
    for path in paths:
        names = {Path(str(f)).stem for f in _files_in(path)}
        for name in names:
            case = cases.get(name)
            if case is not None:
                case.flagged = True
                if len(case.findings) < 3:
                    case.findings.append(
                        f"{path.get('impact', '?')} score={path.get('score', 0):.0f}"
                    )


def _files_in(path: Dict) -> Set[str]:
    """Files a finding touches, from its ``file.java:lineno`` locations.

    Both ends are recorded because a flow may cross files; a case is credited
    if either end lands in it.
    """
    files: Set[str] = set()
    for key in ("source_location", "sink_location"):
        value = path.get(key)
        if value:
            files.add(str(value).rsplit(":", 1)[0])
    return files


def tally(selected: Sequence[Case]) -> Dict[str, Tally]:
    per_category: Dict[str, Tally] = defaultdict(Tally)
    for case in selected:
        bucket = per_category[case.category]
        if case.is_real and case.flagged:
            bucket.tp += 1
        elif case.is_real:
            bucket.fn += 1
        elif case.flagged:
            bucket.fp += 1
        else:
            bucket.tn += 1
    return per_category


def combine(buckets: Iterable[Tally]) -> Tally:
    total = Tally()
    for bucket in buckets:
        total.tp += bucket.tp
        total.fp += bucket.fp
        total.fn += bucket.fn
        total.tn += bucket.tn
    return total


def _pct(value: Optional[float]) -> str:
    return "  n/a" if value is None else f"{value * 100:5.1f}%"


def report(per_category: Dict[str, Tally], elapsed: float, staged: int) -> None:
    in_scope = {k: v for k, v in per_category.items() if k in IN_SCOPE}
    out_scope = {k: v for k, v in per_category.items() if k not in IN_SCOPE}

    def table(title: str, buckets: Dict[str, Tally], labels: Dict[str, str]) -> None:
        if not buckets:
            return
        print(f"\n{title}")
        print(f"{'category':<14}{'cases':>6}{'TP':>5}{'FN':>5}{'FP':>5}{'TN':>5}"
              f"{'recall':>9}{'FP rate':>9}{'prec':>8}{'score':>8}")
        print("-" * 79)
        for name in sorted(buckets):
            b = buckets[name]
            total = b.tp + b.fn + b.fp + b.tn
            print(
                f"{name:<14}{total:>6}{b.tp:>5}{b.fn:>5}{b.fp:>5}{b.tn:>5}"
                f"{_pct(b.recall):>9}{_pct(b.fpr):>9}{_pct(b.precision):>8}{_pct(b.youden):>8}"
            )
        overall = combine(buckets.values())
        total = overall.tp + overall.fn + overall.fp + overall.tn
        print("-" * 79)
        print(
            f"{'ALL':<14}{total:>6}{overall.tp:>5}{overall.fn:>5}{overall.fp:>5}{overall.tn:>5}"
            f"{_pct(overall.recall):>9}{_pct(overall.fpr):>9}"
            f"{_pct(overall.precision):>8}{_pct(overall.youden):>8}"
        )
        _ = labels

    print(f"\nScanned {staged} test cases in {elapsed:.1f}s")
    table("In scope -- classes modelled as taint flows", in_scope, IN_SCOPE)
    table("Out of scope -- not modelled; shown for completeness", out_scope, OUT_OF_SCOPE)

    overall = combine(in_scope.values())
    print(
        "\nHeadline (in scope): recall "
        f"{_pct(overall.recall).strip()}, false positive rate {_pct(overall.fpr).strip()}, "
        f"Youden score {_pct(overall.youden).strip()}."
    )
    print("Youden score is recall minus false-positive rate; 0% is what guessing achieves.")


def write_json(destination: Path, selected: Sequence[Case], per_category: Dict[str, Tally]) -> None:
    payload = {
        "cases": [
            {
                "name": c.name,
                "category": c.category,
                "expected_vulnerable": c.is_real,
                "cwe": c.cwe,
                "flagged": c.flagged,
                "findings": c.findings,
                "outcome": (
                    "TP" if c.is_real and c.flagged
                    else "FN" if c.is_real
                    else "FP" if c.flagged
                    else "TN"
                ),
            }
            for c in selected
        ],
        "per_category": {
            name: {
                "tp": b.tp, "fn": b.fn, "fp": b.fp, "tn": b.tn,
                "recall": b.recall, "fpr": b.fpr,
                "precision": b.precision, "youden": b.youden,
                "in_scope": name in IN_SCOPE,
            }
            for name, b in sorted(per_category.items())
        },
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nPer-case results written to {destination}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", help="path to an existing BenchmarkJava checkout")
    parser.add_argument("--workdir", default="/tmp/rootai-benchmark", help="where to clone if needed")
    parser.add_argument("--category", action="append", help="score only this category (repeatable)")
    parser.add_argument("--all-categories", action="store_true", help="include classes the scanner does not model")
    parser.add_argument("--limit", type=int, help="sample this many cases, keeping the category mix")
    parser.add_argument("--profile", default="bugbounty")
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="report threshold; 0 measures the engine rather than the filter")
    parser.add_argument("--json", help="write per-case outcomes here")
    args = parser.parse_args()

    workdir = Path(args.workdir).expanduser()
    benchmark = ensure_benchmark(args.benchmark, workdir)
    testcode = benchmark / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    if not testcode.is_dir():
        raise SystemExit(f"test cases not found under {testcode}")

    cases = load_expected(benchmark)
    selected = select_cases(cases, args.category, args.all_categories, args.limit)
    if not selected:
        raise SystemExit("no cases selected")

    staging = Path(tempfile.mkdtemp(prefix="rootai-benchmark-"))
    try:
        staged = stage(testcode, selected, staging)
        if not staged:
            raise SystemExit("no test case files were staged")
        print(f"scoring {staged} cases across {len({c.category for c in selected})} categories", flush=True)
        started = time.time()
        paths = scan(staging, args.profile, args.min_score)
        elapsed = time.time() - started
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    by_name = {c.name: c for c in selected}
    attribute(paths, by_name)
    per_category = tally(selected)
    report(per_category, elapsed, staged)
    if args.json:
        write_json(Path(args.json), selected, per_category)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
