#!/usr/bin/env python3
"""Score the boundary analysis against the labelled corpus.

Three questions, because they fail independently:

1. **Position accuracy** -- of the cases that reach a modelled consumer, how
   often is the grammatical position identified correctly? This is the
   foundation; every downstream judgement rests on it.

2. **Verdict accuracy** -- how often does the boundary verdict (MISMATCH /
   UNDEFENDED / SAFE / no-finding) match the label? This is what the ranking
   and the evidence bundle are built on.

3. **Security outcome** -- treating the tool as a detector, its true/false
   positives and negatives against whether each case is actually vulnerable.
   The headline sub-metric is *wrong-defence detection*: of the cases that are
   vulnerable because a defence is present but wrong for the position (the
   class OWASP Benchmark contains none of), how many are caught.

Known-gap cases (currently Python) are scored in a separate block so the
headline is not inflated by hiding them.

    python tools/score_boundary_corpus.py
"""

from __future__ import annotations

import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import AnalysisOptions, SecurityConfig, TaintConfig  # noqa: E402
from core.runtime import MultiFileParser  # noqa: E402
from tools.boundary_corpus import CASES, NONE, write_corpus  # noqa: E402


@dataclass
class Outcome:
    case_id: str
    expected_verdict: str
    got_verdict: str
    expected_position: Optional[str]
    got_position: Optional[str]
    is_vulnerable: bool
    flagged: bool
    verdict_ok: bool
    position_ok: bool
    note: str = ""


def _scan(directory: Path) -> List[Dict]:
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


def _finding_for(paths: List[Dict], filename: str) -> Optional[Dict]:
    """The highest-scoring finding whose sink is in ``filename``."""
    stem = Path(filename).name
    hits = [
        p for p in paths
        if stem in str((p if isinstance(p, dict) else p.__dict__).get("sink_location", ""))
    ]
    if not hits:
        return None
    hits.sort(
        key=lambda p: (p if isinstance(p, dict) else p.__dict__).get("score", 0.0),
        reverse=True,
    )
    return hits[0] if isinstance(hits[0], dict) else hits[0].__dict__


def evaluate() -> List[Outcome]:
    directory = Path(tempfile.mkdtemp(prefix="rootai-boundary-"))
    write_corpus(directory)
    paths = _scan(directory)

    outcomes: List[Outcome] = []
    for case in CASES:
        finding = _finding_for(paths, case.filename)
        boundary = (finding or {}).get("boundary") if finding else None
        flagged = finding is not None

        if boundary:
            got_verdict = boundary.get("outcome", "UNKNOWN")
            got_position = boundary.get("position")
        elif flagged:
            # A finding exists but the sink has no modelled consumer.
            got_verdict = "NO-BOUNDARY"
            got_position = None
        else:
            got_verdict = NONE
            got_position = None

        # A case expecting NONE is satisfied by either no finding or a finding
        # with no boundary claim -- both mean "the layer asserted nothing here".
        if case.expect_verdict == NONE:
            verdict_ok = got_verdict in (NONE, "NO-BOUNDARY")
        else:
            verdict_ok = got_verdict == case.expect_verdict

        position_ok = (case.expect_position is None) or (got_position == case.expect_position)

        outcomes.append(
            Outcome(
                case_id=case.id,
                expected_verdict=case.expect_verdict,
                got_verdict=got_verdict,
                expected_position=case.expect_position,
                got_position=got_position,
                is_vulnerable=case.is_vulnerable,
                flagged=flagged,
                verdict_ok=verdict_ok,
                position_ok=position_ok,
                note="known-gap" if case.known_gap else "",
            )
        )
    return outcomes


def _detector_stats(outcomes: List[Outcome]) -> Dict[str, int]:
    """Treat the tool as a vulnerability detector.

    "Flagged as a real problem" = a boundary verdict of MISMATCH or UNDEFENDED
    (SAFE and no-finding are the tool declining to raise it).
    """
    tp = fp = fn = tn = 0
    for o in outcomes:
        # "Raised" means the tool flagged this as needing attention: a boundary
        # MISMATCH or UNDEFENDED, or -- for a sink with no grammar boundary --
        # an ordinary taint finding. A boundary SAFE or no finding at all is the
        # tool declining to raise it.
        raised = o.got_verdict in ("MISMATCH", "UNDEFENDED") or (
            o.got_verdict == "NO-BOUNDARY" and o.flagged
        )
        if o.is_vulnerable and raised:
            tp += 1
        elif o.is_vulnerable and not raised:
            fn += 1
        elif not o.is_vulnerable and raised:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _pct(n: int, d: int) -> str:
    return "  n/a" if d == 0 else f"{100 * n / d:5.1f}%"


def report(outcomes: List[Outcome]) -> bool:
    main = [o for o in outcomes if not o.note]
    gaps = [o for o in outcomes if o.note == "known-gap"]

    print(f"\nBoundary corpus: {len(main)} cases in scope, {len(gaps)} known-gap\n")
    print(f"{'case':<38}{'position':<12}{'verdict':<12}{'ok'}")
    print("-" * 68)
    for o in main:
        marks = ("P" if o.position_ok else "p") + ("V" if o.verdict_ok else "v")
        print(f"{o.case_id:<38}{(o.got_position or '-')[:11]:<12}{o.got_verdict:<12}{marks}")

    position_cases = [o for o in main if o.expected_position is not None]
    position_ok = sum(1 for o in position_cases if o.position_ok)
    verdict_ok = sum(1 for o in main if o.verdict_ok)
    stats = _detector_stats(main)

    print("\n--- accuracy ---")
    print(f"position   {_pct(position_ok, len(position_cases))}  ({position_ok}/{len(position_cases)})")
    print(f"verdict    {_pct(verdict_ok, len(main))}  ({verdict_ok}/{len(main)})")

    print("\n--- as a detector ---")
    print(f"TP {stats['tp']}  FP {stats['fp']}  FN {stats['fn']}  TN {stats['tn']}")
    recall = _pct(stats["tp"], stats["tp"] + stats["fn"])
    precision = _pct(stats["tp"], stats["tp"] + stats["fp"])
    print(f"recall {recall}   precision {precision}")

    mismatch = [o for o in main if o.expected_verdict == "MISMATCH"]
    mismatch_caught = sum(1 for o in mismatch if o.got_verdict == "MISMATCH")
    print("\n--- the differentiator: wrong-defence (MISMATCH) detection ---")
    print(f"caught {mismatch_caught}/{len(mismatch)}  "
          f"({_pct(mismatch_caught, len(mismatch)).strip()})")
    print("These are the cases a name-based tool calls defended. OWASP Benchmark")
    print("contains none of them.")

    if gaps:
        gap_ok = sum(1 for o in gaps if o.verdict_ok)
        print(f"\n--- known gaps (not in the headline) ---")
        for o in gaps:
            print(f"  {o.case_id:<36} verdict {o.got_verdict} (expected {o.expected_verdict})")
        print(f"  {gap_ok}/{len(gaps)} handled")

    failures = [o for o in main if not (o.position_ok and o.verdict_ok)]
    if failures:
        print("\n--- misclassifications ---")
        for o in failures:
            print(f"  {o.case_id}: position {o.got_position} (want {o.expected_position}), "
                  f"verdict {o.got_verdict} (want {o.expected_verdict})")
    return not failures


if __name__ == "__main__":
    ok = report(evaluate())
    raise SystemExit(0 if ok else 1)
