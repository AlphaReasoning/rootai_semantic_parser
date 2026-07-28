"""The boundary corpus as a living regression check.

`tools/score_boundary_corpus.py` produces the headline numbers; this pins them
so a change that quietly breaks position analysis or defence-adequacy fails the
build instead of the next measurement. The thresholds are deliberately exact
on the small in-scope set -- every case has a known-by-construction label, so
anything less than perfect on them is a real regression, not noise.

Known-gap cases (StringBuilder append-chains, Python f-strings) are excluded
from these assertions on purpose; they are tracked in the corpus and reported
separately so the gap stays visible rather than asserted away.
"""

from __future__ import annotations

import pytest

from tools.score_boundary_corpus import evaluate


@pytest.fixture(scope="module")
def outcomes():
    return [o for o in evaluate() if o.note != "known-gap"]


def test_every_in_scope_position_is_correct(outcomes) -> None:
    wrong = [o.case_id for o in outcomes if not o.position_ok]
    assert not wrong, f"position misclassified: {wrong}"


def test_every_in_scope_verdict_is_correct(outcomes) -> None:
    wrong = [
        f"{o.case_id}: got {o.got_verdict}, want {o.expected_verdict}"
        for o in outcomes
        if not o.verdict_ok
    ]
    assert not wrong, wrong


def test_no_false_positives_on_defended_code(outcomes) -> None:
    """A SAFE case reported as a live issue is the precision failure that
    erodes trust fastest."""
    false_positives = [
        o.case_id
        for o in outcomes
        if not o.is_vulnerable and o.got_verdict in ("MISMATCH", "UNDEFENDED")
    ]
    assert not false_positives, f"flagged safe code: {false_positives}"


def test_every_wrong_defence_is_caught(outcomes) -> None:
    """The differentiator: cases a name-based tool calls defended."""
    missed = [
        o.case_id
        for o in outcomes
        if o.expected_verdict == "MISMATCH" and o.got_verdict != "MISMATCH"
    ]
    assert not missed, f"missed wrong-defence cases: {missed}"


def test_every_real_vulnerability_is_raised(outcomes) -> None:
    missed = [
        o.case_id
        for o in outcomes
        if o.is_vulnerable
        and not (
            o.got_verdict in ("MISMATCH", "UNDEFENDED")
            or (o.got_verdict == "NO-BOUNDARY" and o.flagged)
        )
    ]
    assert not missed, f"missed real vulnerabilities: {missed}"
