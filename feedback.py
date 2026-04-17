"""Feedback ingestion, adaptive scoring, and tuning helpers."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from reports import build_bounty_report


@dataclass
class FeedbackEntry:
    """Recorded analyst feedback for a finding."""

    fingerprint: str
    verdict: str
    impact: str = ""
    sink: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)


def load_feedback_db(path: str) -> List[FeedbackEntry]:
    """Load feedback entries from disk."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        return []
    raw = json.loads(content)
    return [FeedbackEntry(**item) for item in raw]


def save_feedback_db(path: str, entries: List[FeedbackEntry]) -> None:
    """Write feedback entries to disk."""
    Path(path).write_text(json.dumps([entry.__dict__ for entry in entries], indent=2), encoding="utf-8")


def record_feedback(path: str, entry: FeedbackEntry) -> None:
    """Append a feedback entry to disk."""
    entries = load_feedback_db(path)
    entries.append(entry)
    save_feedback_db(path, entries)


def feedback_stats(entries: List[FeedbackEntry]) -> Dict[str, Any]:
    """Summarize feedback signals."""
    verdicts: Dict[str, int] = {}
    impacts: Dict[str, int] = {}
    for entry in entries:
        verdicts[entry.verdict] = verdicts.get(entry.verdict, 0) + 1
        if entry.impact:
            impacts[entry.impact] = impacts.get(entry.impact, 0) + 1
    return {"count": len(entries), "verdicts": verdicts, "impacts": impacts}


def adaptive_score_delta(finding: Dict[str, Any], entries: List[FeedbackEntry]) -> float:
    """Compute a score delta from historical feedback."""
    delta = 0.0
    impact = str(finding.get("impact", ""))
    sink = str(finding.get("sink_location", ""))
    for entry in entries:
        verdict_weight = 8.0 if entry.verdict == "true_positive" else -12.0 if entry.verdict == "false_positive" else 0.0
        if impact and entry.impact == impact:
            delta += verdict_weight * 0.5
        if sink and entry.sink and entry.sink in sink:
            delta += verdict_weight * 0.5
    return delta


def apply_feedback_scores(bounty, entries: List[FeedbackEntry]):
    """Adapt finding scores from feedback history."""
    for finding in bounty.findings:
        finding["score"] = max(0.0, float(finding.get("score", 0.0)) + adaptive_score_delta(finding, entries))
    bounty.findings.sort(key=lambda item: float(item.get("score", 0.0)), reverse=True)
    return bounty


def tune_rules(entries: List[FeedbackEntry]) -> Dict[str, Any]:
    """Produce coarse rule-tuning recommendations from feedback."""
    recommendations: Dict[str, Any] = {"boost_impacts": [], "suppress_sinks": []}
    impact_counts: Dict[str, int] = {}
    sink_counts: Dict[str, int] = {}
    for entry in entries:
        if entry.verdict == "true_positive" and entry.impact:
            impact_counts[entry.impact] = impact_counts.get(entry.impact, 0) + 1
        if entry.verdict == "false_positive" and entry.sink:
            sink_counts[entry.sink] = sink_counts.get(entry.sink, 0) + 1
    recommendations["boost_impacts"] = [impact for impact, count in impact_counts.items() if count >= 2]
    recommendations["suppress_sinks"] = [sink for sink, count in sink_counts.items() if count >= 2]
    return recommendations
