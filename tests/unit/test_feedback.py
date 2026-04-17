"""Feedback loop tests."""

from __future__ import annotations

from rootai_semantic_parser.feedback import FeedbackEntry, adaptive_score_delta, feedback_stats


def test_feedback_stats_counts_verdicts() -> None:
    """Summarize stored feedback correctly."""
    stats = feedback_stats([FeedbackEntry(fingerprint="a", verdict="true_positive", impact="RCE")])
    assert stats["count"] == 1
    assert stats["verdicts"]["true_positive"] == 1


def test_adaptive_score_delta_rewards_matching_true_positive() -> None:
    """Boost similar findings after a true-positive verdict."""
    delta = adaptive_score_delta(
        {"impact": "RCE", "sink_location": "x.py:1"},
        [FeedbackEntry(fingerprint="a", verdict="true_positive", impact="RCE", sink="x.py")],
    )
    assert delta > 0
