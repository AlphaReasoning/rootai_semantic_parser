"""Evidence bundles: the static-analysis-to-confirmation handoff.

This tool is the white-box leg of a larger stack. It reads source and produces
candidates; a dynamic prober or an LLM confirms them. The value of that split
collapses if the handoff is a severity score and a line number, because the
confirming step then has to re-derive everything the static pass already knew.

An evidence bundle is the opposite: everything the static pass established,
structured for a consumer rather than a reader. Where the value enters, where it
lands, what parser consumes it, which grammatical position it occupies, the
defence that position requires, the defence actually present, the route it is
reachable from, and -- crucially -- the *specific question* the next step should
answer and the *concrete probe* that answers it.

A finding that carries its own confirmation recipe is what makes the stack more
than a pile of separate tools. "The hole is a single-quoted SQL literal reached
via POST /admin/exec param `q`; break out with an unbalanced quote" is
actionable. "SQL injection, score 75" is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceBundle:
    """Everything the white-box pass knows about one candidate."""

    finding_id: str
    impact: str
    confidence: float
    score: float

    #: Where the value enters and where it is consumed.
    source: Dict[str, Any]
    sink: Dict[str, Any]
    #: The data path, label by label, source to sink.
    flow: List[str]

    #: External reachability, if known: the routes and entry points.
    reachability: Dict[str, Any]
    #: Grammar-boundary verdict, when a consuming language was identified.
    boundary: Optional[Dict[str, Any]]
    #: Defences seen on the path and whether they fit the position.
    defences: Dict[str, Any]

    #: The single question the confirming step should resolve.
    question: str
    #: The concrete test that resolves it, for a dynamic prober.
    probe: Optional[str]
    #: Why a human should or should not trust this without confirmation.
    caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "impact": self.impact,
            "confidence": round(self.confidence, 3),
            "score": round(self.score, 1),
            "source": self.source,
            "sink": self.sink,
            "flow": self.flow,
            "reachability": self.reachability,
            "boundary": self.boundary,
            "defences": self.defences,
            "question": self.question,
            "probe": self.probe,
            "caveats": self.caveats,
        }


def _finding_id(finding: Dict[str, Any]) -> str:
    sink = str(finding.get("sink_location") or finding.get("sink_id") or "?")
    source = str(finding.get("source_label") or finding.get("source_id") or "?")
    return f"{sink}::{source}"


def _question_for(finding: Dict[str, Any], boundary: Optional[Dict[str, Any]]) -> str:
    """The one thing the confirming step should decide.

    Sharpened by the boundary verdict when there is one: a MISMATCH already
    knows the applied defence is the wrong kind, so the open question is only
    whether the position is reachable with a live payload, not whether it is
    vulnerable in principle.
    """
    impact = finding.get("impact", "the sink")
    routes = finding.get("routes") or []
    where = f" via {routes[0]}" if routes else ""

    if boundary:
        outcome = boundary.get("outcome")
        position = boundary.get("position")
        if outcome == "MISMATCH":
            return (
                f"The value reaches {position}{where}, defended by "
                f"{boundary.get('applied')} -- which is the wrong kind of defence for "
                f"that position. Confirm the payload survives to the sink and that "
                f"the route is reachable."
            )
        if outcome == "UNDEFENDED" and boundary.get("structural"):
            return (
                f"The value reaches {position}{where} with no applicable defence, and "
                f"no escaping can defend that position. Confirm reachability and that "
                f"an allowlist is genuinely absent at runtime."
            )
        if outcome == "SAFE":
            return (
                f"The boundary appears defended ({boundary.get('detail')}). Confirm the "
                f"reconstruction was complete and no alternate path reaches the same sink."
            )
    return (
        f"Does attacker-controlled input actually reach this {impact} sink{where} "
        f"unsanitised at runtime?"
    )


def _caveats(finding: Dict[str, Any], boundary: Optional[Dict[str, Any]]) -> List[str]:
    caveats: List[str] = []
    if not finding.get("reachable", True) and not (finding.get("routes") or finding.get("entrypoints")):
        caveats.append(
            "No route or entry point was found reaching this sink, so it may be "
            "internal-only or dead code. Reachability is unconfirmed."
        )
    if boundary and not boundary.get("template_complete", True):
        caveats.append(
            "The consumed string could not be fully reconstructed (a helper or "
            "dynamic fragment was in the way), so the position is a best effort and "
            "a SAFE verdict here is not trustworthy."
        )
    if finding.get("test_only"):
        caveats.append("This sink is in test code.")
    if finding.get("library_code"):
        caveats.append("This sink is in vendored or library code.")
    if boundary is None:
        caveats.append(
            "No consuming grammar was identified for this sink, so only ordinary "
            "taint reasoning applies -- position and required defence are unknown."
        )
    return caveats


def build_evidence_bundle(finding: Dict[str, Any]) -> EvidenceBundle:
    """Assemble the confirmation-ready bundle for one finding."""
    boundary = finding.get("boundary")
    defences = {
        "applied": (boundary or {}).get("applied", []),
        "verdict": (boundary or {}).get("outcome"),
        "required_one_of": (boundary or {}).get("required_one_of", []),
        "sanitization_status": finding.get("sanitization_status"),
        "validation_guards": finding.get("validation_guards", []),
    }
    return EvidenceBundle(
        finding_id=_finding_id(finding),
        impact=finding.get("impact", "generic"),
        confidence=float(finding.get("confidence", 0.0)),
        score=float(finding.get("score", 0.0)),
        source={
            "label": finding.get("source_label", ""),
            "location": finding.get("source_location", ""),
        },
        sink={
            "label": finding.get("sink_label", ""),
            "location": finding.get("sink_location", ""),
            "consumer": (boundary or {}).get("consumer"),
            "template": (boundary or {}).get("template"),
        },
        flow=finding.get("path_labels") or [],
        reachability={
            "reachable": finding.get("reachable", None),
            "routes": finding.get("routes", []),
            "entrypoints": finding.get("entrypoints", []),
            "auth_guarded": finding.get("auth_guarded", False),
        },
        boundary=boundary,
        defences=defences,
        question=_question_for(finding, boundary),
        probe=(boundary or {}).get("probe") or _fallback_probe(finding),
        caveats=_caveats(finding, boundary),
    )


def _fallback_probe(finding: Dict[str, Any]) -> Optional[str]:
    hints = finding.get("payload_hints") or []
    return f"try: {hints[0]}" if hints else None


def build_evidence_report(findings: List[Dict[str, Any]], limit: int = 50) -> Dict[str, Any]:
    """A bundle per finding, plus a triage summary over the set."""
    bundles = [build_evidence_bundle(finding) for finding in findings[:limit]]
    by_verdict: Dict[str, int] = {}
    for bundle in bundles:
        outcome = (bundle.boundary or {}).get("outcome", "no-boundary")
        by_verdict[outcome] = by_verdict.get(outcome, 0) + 1
    return {
        "summary": {
            "total": len(bundles),
            "by_boundary_verdict": by_verdict,
            "wrong_defence": by_verdict.get("MISMATCH", 0),
            "structurally_undefended": sum(
                1
                for bundle in bundles
                if (bundle.boundary or {}).get("outcome") == "UNDEFENDED"
                and (bundle.boundary or {}).get("structural")
            ),
        },
        "bundles": [bundle.to_dict() for bundle in bundles],
    }
