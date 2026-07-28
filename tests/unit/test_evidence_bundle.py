"""The evidence bundle is the handoff, so it is tested as a contract.

This tool is the white-box leg of a stack; a dynamic prober or an LLM confirms
what it finds. The bundle is what crosses that boundary, so what matters is not
that it is pretty but that it carries everything the next step needs without
re-deriving it: where the value lands, the defence required, the route, the
question to answer, and the probe that answers it.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List

from rootai_semantic_parser.analyzers.evidence import (
    build_evidence_bundle,
    build_evidence_report,
)
from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig


def _findings(filename: str, source: str) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    report = parser.scan(taint_config=TaintConfig.profile("bugbounty"))
    node_idx = {n["id"]: n for n in report.graph.get("nodes", [])}
    out = []
    for path in report.taint_paths:
        finding = dict(path) if isinstance(path, dict) else dict(path.__dict__)
        finding["path_labels"] = [
            node_idx.get(nid, {}).get("label", nid) for nid in finding.get("path", [])
        ]
        out.append(finding)
    return out


WRONG_ESCAPER = (
    "a.php",
    "<?php\n$c = mysqli_real_escape_string($db, $_GET['sort']);\n"
    '$sql = "SELECT id FROM products ORDER BY " . $c;\nmysqli_query($db, $sql);\n',
)


def test_bundle_carries_position_defence_and_probe() -> None:
    """The three things the confirming step cannot re-derive on its own."""
    bundle = build_evidence_bundle(_findings(*WRONG_ESCAPER)[0]).to_dict()
    assert bundle["boundary"]["position"] == "sql:identifier"
    assert bundle["defences"]["required_one_of"] == ["allowlist", "numeric-cast"]
    assert bundle["defences"]["applied"] == ["quote-escape"]
    assert bundle["probe"]


def test_the_question_names_the_wrong_defence() -> None:
    """A MISMATCH bundle should ask the sharpened question, not the generic one.

    The static pass already knows the defence is the wrong kind, so the open
    question is reachability, not vulnerability-in-principle.
    """
    bundle = build_evidence_bundle(_findings(*WRONG_ESCAPER)[0]).to_dict()
    question = bundle["question"].lower()
    assert "wrong kind" in question
    assert "reachable" in question


def test_the_flow_is_preserved_end_to_end() -> None:
    bundle = build_evidence_bundle(_findings(*WRONG_ESCAPER)[0]).to_dict()
    assert bundle["flow"][0].startswith("$db")
    assert bundle["flow"][-1] == "mysqli_query"


def test_a_sink_with_no_consumer_says_so_in_its_caveats() -> None:
    """Honest degradation: the bundle must not imply position analysis it lacks."""
    findings = _findings(
        "a.py",
        "import pickle\ndef v(request):\n    pickle.loads(request.args.get('o'))\n",
    )
    bundle = build_evidence_bundle(findings[0]).to_dict()
    assert bundle["boundary"] is None
    assert any("no consuming grammar" in caveat.lower() for caveat in bundle["caveats"])


def test_an_incomplete_reconstruction_is_flagged_as_untrustworthy() -> None:
    findings = _findings(
        "A.java",
        "public class A { public void f(HttpServletRequest r) throws Exception {\n"
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT a FROM t WHERE a = " + helper() + " AND b = " + p;\n'
        "  st.executeQuery(sql); } }\n",
    )
    bundle = build_evidence_bundle(findings[0]).to_dict()
    assert any("could not be fully reconstructed" in caveat.lower() for caveat in bundle["caveats"])


def test_report_summarises_by_verdict() -> None:
    """Triage needs the shape of the set, not just a list."""
    report = build_evidence_report(_findings(*WRONG_ESCAPER))
    assert report["summary"]["total"] >= 1
    assert report["summary"]["wrong_defence"] >= 1
    assert report["summary"]["by_boundary_verdict"].get("MISMATCH", 0) >= 1
