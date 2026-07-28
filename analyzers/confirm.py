"""The confirmation loop: turn candidates into judged findings.

This tool is the white-box leg of a stack — it produces *candidates*. The
confirmation step decides which of those candidates are worth a human's time,
and it is the point where an LLM belongs: not to discover the dataflow (the
graph engine did that, deterministically) but to interpret the evidence bundle
and judge whether the candidate is a real, reachable vulnerability. That split
is the project's whole philosophy — the model reasons about a path it is handed,
it never finds one.

A judge takes an :class:`~analyzers.evidence.EvidenceBundle` and returns a
:class:`Judgment`. Two implementations ship:

* :class:`HeuristicJudge` — deterministic, offline, no dependencies. It reasons
  from the boundary verdict and reachability the same way a triager would on a
  first pass. It is the default, so the loop runs with no API key and the tests
  stay hermetic.
* :class:`ClaudeJudge` — sends the bundle to Claude for a real assessment. Opt
  in explicitly; it costs money and requires the ``anthropic`` SDK plus
  credentials. It handles the ``refusal`` stop reason gracefully, because a
  vulnerability-analysis prompt is exactly the kind of content a safety
  classifier may decline — a refusal becomes an ``uncertain`` verdict, never a
  crash.

Outcomes feed the feedback DB, so a confirmed/rejected history can tune scoring
over time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol

CONFIRMED = "confirmed"
REJECTED = "rejected"
UNCERTAIN = "uncertain"

#: Judge verdict -> feedback DB verdict, so the confirmation loop's decisions
#: become the adaptive-scoring signal the feedback tools already consume.
_FEEDBACK_VERDICT = {
    CONFIRMED: "true_positive",
    REJECTED: "false_positive",
    UNCERTAIN: "needs_review",
}


@dataclass
class Judgment:
    """One judge's assessment of one candidate."""

    finding_id: str
    verdict: str
    confidence: float
    reasoning: str
    recommended_next_step: str
    #: Which judge produced this, so a mixed run is auditable.
    judged_by: str = "heuristic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "reasoning": self.reasoning,
            "recommended_next_step": self.recommended_next_step,
            "judged_by": self.judged_by,
        }


class Judge(Protocol):
    """Assess one evidence bundle. Implementations must never raise."""

    name: str

    def judge(self, bundle: Dict[str, Any]) -> Judgment: ...


# ---------------------------------------------------------------------------
# Deterministic judge -- the offline default
# ---------------------------------------------------------------------------


class HeuristicJudge:
    """Judge from the evidence alone, with no model call.

    Encodes the reasoning a triager applies on a first pass, so the loop is
    useful — and the tests are hermetic — without an API key. It is deliberately
    conservative: anything it cannot decide from the structure becomes
    ``uncertain`` and is handed on for runtime confirmation rather than being
    called either way.
    """

    name = "heuristic"

    def judge(self, bundle: Dict[str, Any]) -> Judgment:
        boundary = bundle.get("boundary") or {}
        reach = bundle.get("reachability") or {}
        finding_id = str(bundle.get("finding_id", "?"))
        outcome = boundary.get("outcome")
        reachable = bool(reach.get("routes") or reach.get("entrypoints"))

        if boundary.get("template_complete") is False:
            return Judgment(
                finding_id, UNCERTAIN, 0.4,
                "The consumed string could not be fully reconstructed, so the "
                "position is a best effort. Confirm the reconstruction by hand "
                "before trusting a verdict.",
                bundle.get("probe") or "trace the sink argument manually",
                self.name,
            )

        if outcome == "SAFE" and boundary.get("trustworthy_safe", True):
            return Judgment(
                finding_id, REJECTED, 0.8,
                f"The boundary is provably defended: {boundary.get('detail')}. "
                "No reachable payload survives to the sink.",
                "no action; retained only as evidence the flow was checked",
                self.name,
            )

        if outcome == "MISMATCH":
            confidence = 0.85 if reachable else 0.6
            return Judgment(
                finding_id, CONFIRMED if reachable else UNCERTAIN, confidence,
                "A defence is present but is the wrong kind for this position "
                f"({boundary.get('detail')}). "
                + (
                    "The sink is reachable from a route, so this is a live finding."
                    if reachable
                    else "Reachability is unconfirmed; verify the route exists at runtime."
                ),
                bundle.get("probe") or "run the position-specific probe",
                self.name,
            )

        if outcome == "UNDEFENDED" and boundary.get("structural"):
            confidence = 0.8 if reachable else 0.55
            return Judgment(
                finding_id, CONFIRMED if reachable else UNCERTAIN, confidence,
                f"A structural position with no applicable defence: "
                f"{boundary.get('detail')}. Escaping cannot help here.",
                bundle.get("probe") or "run the position-specific probe",
                self.name,
            )

        # Undefended non-structural, or no boundary at all: a real flow, but its
        # exploitability turns on reachability the static pass can't settle.
        if reachable:
            return Judgment(
                finding_id, CONFIRMED, 0.6,
                "Attacker-controlled input reaches the sink undefended, from a "
                "known route.",
                bundle.get("probe") or "send a payload to the route and observe",
                self.name,
            )
        return Judgment(
            finding_id, UNCERTAIN, 0.4,
            "Attacker-controlled input reaches the sink, but no route or entry "
            "point was found, so it may be internal-only or dead code.",
            "confirm the sink is reachable from an external entry point",
            self.name,
        )


# ---------------------------------------------------------------------------
# Claude judge -- the real assessment, opt-in
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are assisting a defensive security review: the user is triaging "
    "static-analysis findings on their own source code before shipping, and in "
    "authorised bug-bounty work. A deterministic graph engine has already "
    "traced each candidate from an attacker-controlled source to a dangerous "
    "sink and reconstructed exactly where the value lands in the consumed "
    "language. Your job is not to find the flaw -- it is handed to you -- but "
    "to judge whether it is a real, reachable vulnerability worth a human's "
    "time, using only the evidence provided.\n\n"
    "Return CONFIRMED only when the evidence shows a genuinely exploitable "
    "flow; REJECTED when the position is provably defended or the flow cannot "
    "carry a payload; UNCERTAIN when reachability or the reconstruction is not "
    "settled by the evidence. Be calibrated: a wrong-defence (MISMATCH) at a "
    "structural position is high-signal, but reachability that the static pass "
    "could not confirm genuinely warrants UNCERTAIN. Keep reasoning to a few "
    "sentences an operator can act on."
)

_JUDGMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": [CONFIRMED, REJECTED, UNCERTAIN]},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
        "recommended_next_step": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning", "recommended_next_step"],
    "additionalProperties": False,
}


class ClaudeJudge:
    """Assess a bundle with Claude. Opt-in: costs money, needs credentials.

    Uses structured outputs so the response is a validated verdict rather than
    prose to parse, and never lets an API or content problem take the loop down:
    a refusal, an auth failure, or a malformed response all degrade to an
    ``uncertain`` judgment carrying the reason.
    """

    name = "claude"

    def __init__(self, model: str = "claude-opus-5", max_tokens: int = 8192) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            import anthropic  # imported lazily so the SDK is not a hard dependency

            self._client = anthropic.Anthropic()
        return self._client

    def judge(self, bundle: Dict[str, Any]) -> Judgment:
        finding_id = str(bundle.get("finding_id", "?"))
        try:
            client = self._get_client()
        except Exception as exc:  # missing SDK or unresolved credentials
            return self._degraded(finding_id, f"Claude judge unavailable: {exc}")

        prompt = (
            "Assess this static-analysis candidate. The evidence bundle is the "
            "complete output of the white-box pass; judge only from it.\n\n"
            + json.dumps(bundle, indent=2)
        )
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=_SYSTEM_PROMPT,
                output_config={"format": {"type": "json_schema", "schema": _JUDGMENT_SCHEMA}},
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:
            return self._degraded(finding_id, f"Claude request failed: {exc}")

        if getattr(response, "stop_reason", None) == "refusal":
            # A vulnerability-analysis prompt can trip a safety classifier. That
            # is not a verdict on the finding, so surface it as uncertain and
            # leave the candidate for a human rather than dropping it.
            return self._degraded(
                finding_id,
                "The model declined to assess this candidate (safety classifier). "
                "Review it manually.",
            )

        text = next(
            (block.text for block in response.content if getattr(block, "type", None) == "text"),
            "",
        )
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return self._degraded(finding_id, "The model returned an unparseable response.")

        confidence = data.get("confidence", 0.0)
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.0
        verdict = data.get("verdict", UNCERTAIN)
        if verdict not in (CONFIRMED, REJECTED, UNCERTAIN):
            verdict = UNCERTAIN
        return Judgment(
            finding_id,
            verdict,
            confidence,
            str(data.get("reasoning", "")),
            str(data.get("recommended_next_step", "")),
            self.name,
        )

    def _degraded(self, finding_id: str, reason: str) -> Judgment:
        return Judgment(finding_id, UNCERTAIN, 0.0, reason,
                        "assess this candidate manually", self.name)


# ---------------------------------------------------------------------------
# Running the loop
# ---------------------------------------------------------------------------


@dataclass
class ConfirmationReport:
    judgments: List[Judgment] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        by_verdict: Dict[str, int] = {}
        for judgment in self.judgments:
            by_verdict[judgment.verdict] = by_verdict.get(judgment.verdict, 0) + 1
        return {
            "summary": {
                "total": len(self.judgments),
                "by_verdict": by_verdict,
                "confirmed": by_verdict.get(CONFIRMED, 0),
                "rejected": by_verdict.get(REJECTED, 0),
                "uncertain": by_verdict.get(UNCERTAIN, 0),
            },
            "judgments": [judgment.to_dict() for judgment in self.judgments],
        }


def run_confirmation(
    bundles: List[Dict[str, Any]],
    judge: Judge,
    feedback_writer: Optional[Callable[[str, str, str], None]] = None,
) -> ConfirmationReport:
    """Judge every bundle, optionally recording each outcome as feedback.

    ``feedback_writer`` receives ``(fingerprint, feedback_verdict, notes)`` per
    judgment, so a confirmed/rejected history accumulates for score tuning
    without this module needing to know how the feedback DB is stored.
    """
    report = ConfirmationReport()
    for bundle in bundles:
        judgment = judge.judge(bundle)
        report.judgments.append(judgment)
        if feedback_writer is not None:
            feedback_writer(
                judgment.finding_id,
                _FEEDBACK_VERDICT.get(judgment.verdict, "needs_review"),
                f"[{judgment.judged_by}] {judgment.reasoning}",
            )
    return report
