"""The confirmation loop: an LLM judges candidates, but the tests never call one.

The judge is pluggable precisely so the loop is testable offline and usable
without an API key. These tests exercise the deterministic HeuristicJudge (the
default), the loop's feedback wiring through a fake judge, and the ClaudeJudge's
failure handling — which must degrade to a verdict, never crash, and never make
a network call in a test.
"""

from __future__ import annotations

from typing import Dict

import pytest

from rootai_semantic_parser.analyzers.confirm import (
    CONFIRMED,
    REJECTED,
    UNCERTAIN,
    ClaudeJudge,
    HeuristicJudge,
    Judgment,
    run_confirmation,
)


def _bundle(**overrides) -> Dict:
    base = {
        "finding_id": "f1",
        "reachability": {"routes": ["POST /admin"], "entrypoints": []},
        "boundary": {"outcome": "UNDEFENDED", "structural": False, "template_complete": True},
        "probe": "send a payload",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# HeuristicJudge — deterministic verdicts from the evidence
# ---------------------------------------------------------------------------


def test_wrong_defence_and_reachable_is_confirmed() -> None:
    verdict = HeuristicJudge().judge(
        _bundle(boundary={"outcome": "MISMATCH", "structural": True, "detail": "x", "template_complete": True})
    )
    assert verdict.verdict == CONFIRMED
    assert verdict.confidence >= 0.8


def test_wrong_defence_but_unreachable_is_uncertain() -> None:
    """A MISMATCH the static pass can't prove reachable is not yet a finding."""
    verdict = HeuristicJudge().judge(
        _bundle(
            reachability={"routes": [], "entrypoints": []},
            boundary={"outcome": "MISMATCH", "structural": True, "detail": "x", "template_complete": True},
        )
    )
    assert verdict.verdict == UNCERTAIN


def test_provably_safe_boundary_is_rejected() -> None:
    verdict = HeuristicJudge().judge(
        _bundle(boundary={"outcome": "SAFE", "trustworthy_safe": True, "detail": "escaped", "template_complete": True})
    )
    assert verdict.verdict == REJECTED


def test_incomplete_reconstruction_is_uncertain_not_safe() -> None:
    """An incomplete template must never be trusted to clear a finding."""
    verdict = HeuristicJudge().judge(
        _bundle(boundary={"outcome": "SAFE", "trustworthy_safe": False, "template_complete": False})
    )
    assert verdict.verdict == UNCERTAIN


def test_undefended_structural_reachable_is_confirmed() -> None:
    verdict = HeuristicJudge().judge(
        _bundle(boundary={"outcome": "UNDEFENDED", "structural": True, "detail": "order by", "template_complete": True})
    )
    assert verdict.verdict == CONFIRMED


def test_undefended_but_unreachable_is_uncertain() -> None:
    verdict = HeuristicJudge().judge(
        _bundle(
            reachability={"routes": [], "entrypoints": []},
            boundary={"outcome": "UNDEFENDED", "structural": False, "template_complete": True},
        )
    )
    assert verdict.verdict == UNCERTAIN


def test_no_boundary_but_reachable_still_gets_a_verdict() -> None:
    verdict = HeuristicJudge().judge(_bundle(boundary=None))
    assert verdict.verdict == CONFIRMED


# ---------------------------------------------------------------------------
# The loop and its feedback wiring
# ---------------------------------------------------------------------------


class _FakeJudge:
    """A judge that records what it saw, standing in for Claude in a test."""

    name = "fake"

    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        self.seen = []

    def judge(self, bundle: Dict) -> Judgment:
        self.seen.append(bundle["finding_id"])
        return Judgment(bundle["finding_id"], self.verdict, 0.9, "fake", "none", self.name)


def test_loop_judges_every_bundle_and_summarises() -> None:
    report = run_confirmation([_bundle(finding_id="a"), _bundle(finding_id="b")], _FakeJudge(CONFIRMED))
    payload = report.to_dict()
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["confirmed"] == 2


def test_loop_records_each_verdict_as_feedback() -> None:
    """Confirmed/rejected outcomes must reach the feedback DB for score tuning."""
    recorded = []

    def writer(fingerprint, verdict, notes):
        recorded.append((fingerprint, verdict))

    run_confirmation([_bundle(finding_id="a")], _FakeJudge(REJECTED), feedback_writer=writer)
    assert recorded == [("a", "false_positive")]


def test_verdicts_map_to_feedback_vocabulary() -> None:
    mapping = {}

    def writer(fingerprint, verdict, notes):
        mapping[fingerprint] = verdict

    for verdict, fid in ((CONFIRMED, "c"), (REJECTED, "r"), (UNCERTAIN, "u")):
        run_confirmation([_bundle(finding_id=fid)], _FakeJudge(verdict), feedback_writer=writer)
    assert mapping == {"c": "true_positive", "r": "false_positive", "u": "needs_review"}


# ---------------------------------------------------------------------------
# ClaudeJudge — degrades, never crashes, never calls the network in a test
# ---------------------------------------------------------------------------


def test_claude_judge_degrades_when_sdk_or_credentials_missing() -> None:
    """No API key and no `anthropic` install must yield an uncertain verdict,
    not an exception — the loop keeps going and the candidate survives."""
    judge = ClaudeJudge()
    judge._get_client = lambda: (_ for _ in ()).throw(RuntimeError("no credentials"))
    verdict = judge.judge(_bundle())
    assert verdict.verdict == UNCERTAIN
    assert "unavailable" in verdict.reasoning.lower()


def test_claude_judge_treats_a_refusal_as_uncertain() -> None:
    """A safety-classifier refusal is not a verdict on the finding; the
    candidate is handed to a human rather than dropped."""

    class _RefusingClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                return type("R", (), {"stop_reason": "refusal", "content": []})()

    judge = ClaudeJudge()
    judge._client = _RefusingClient()
    verdict = judge.judge(_bundle())
    assert verdict.verdict == UNCERTAIN
    assert "declined" in verdict.reasoning.lower()


def test_claude_judge_parses_a_structured_verdict() -> None:
    class _Block:
        type = "text"
        text = '{"verdict": "confirmed", "confidence": 0.9, "reasoning": "r", "recommended_next_step": "n"}'

    class _OkClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                return type("R", (), {"stop_reason": "end_turn", "content": [_Block()]})()

    judge = ClaudeJudge()
    judge._client = _OkClient()
    verdict = judge.judge(_bundle())
    assert verdict.verdict == CONFIRMED
    assert verdict.confidence == pytest.approx(0.9)
    assert verdict.judged_by == "claude"


def test_claude_judge_handles_an_unparseable_response() -> None:
    class _Block:
        type = "text"
        text = "not json at all"

    class _BadClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                return type("R", (), {"stop_reason": "end_turn", "content": [_Block()]})()

    judge = ClaudeJudge()
    judge._client = _BadClient()
    verdict = judge.judge(_bundle())
    assert verdict.verdict == UNCERTAIN
