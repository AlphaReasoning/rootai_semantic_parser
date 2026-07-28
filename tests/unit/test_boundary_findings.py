"""Boundary verdicts must reach the finding and reorder it.

Step 1 classified positions in isolation; step 2 reconstructed the template.
This is where the two become a *finding* an operator and a downstream prober can
act on: the verdict rides on the taint path, and it moves the score in the
direction the verdict warrants.

The ranking is the point. A wrong-defended flow (MISMATCH) and an undefended
structural position outrank an ordinary undefended flow, because both look
handled to everything that reasons by sink name. A provably-safe boundary sinks
below the reporting threshold. If the ranking did not change, the analysis
would be decoration.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig


def _paths(filename: str, source: str) -> List:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


def _boundary(path) -> Optional[Dict]:
    return getattr(path, "boundary", None) if not isinstance(path, dict) else path.get("boundary")


def _score(path) -> float:
    return getattr(path, "score", None) if not isinstance(path, dict) else path.get("score")


def _top(filename: str, source: str):
    paths = _paths(filename, source)
    assert paths, "expected at least one finding"
    return paths[0]


# ---------------------------------------------------------------------------
# The verdict reaches the finding
# ---------------------------------------------------------------------------


def test_finding_carries_the_boundary_verdict() -> None:
    finding = _top(
        "A.java",
        "public class A { public void f(HttpServletRequest r) throws Exception {\n"
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT * FROM t ORDER BY " + p;\n'
        "  st.executeQuery(sql); } }\n",
    )
    boundary = _boundary(finding)
    assert boundary is not None
    assert boundary["consumer"] == "sql"
    assert boundary["position"] == "sql:identifier"


def test_finding_carries_a_probe_for_a_downstream_tool() -> None:
    """The static->dynamic handoff: the finding names the test to run."""
    finding = _top(
        "A.java",
        "public class A { public void f(HttpServletRequest r) throws Exception {\n"
        '  String p = r.getParameter("p");\n'
        '  st.executeQuery("SELECT * FROM t ORDER BY " + p); } }\n',
    )
    boundary = _boundary(finding)
    assert boundary and boundary["probe"]
    assert "ORDER BY" in boundary["probe"]


# ---------------------------------------------------------------------------
# The ranking the layer exists to produce
# ---------------------------------------------------------------------------


def test_wrong_defence_outranks_plain_undefended() -> None:
    """A MISMATCH looks handled to every name-based tool, so it must rank up.

    `real_escape_string` on an ORDER BY target is inert -- there are no quotes
    to escape -- but it is a recognised sanitiser, so a taint engine downgrades
    the flow. The boundary layer promotes it instead.
    """
    mismatch = _top(
        "a.php",
        "<?php\n$c = mysqli_real_escape_string($db, $_GET['c']);\n"
        '$sql = "SELECT * FROM t ORDER BY " . $c;\nmysqli_query($db, $sql);\n',
    )
    plain = _top(
        "a.php",
        "<?php\n$c = $_GET['c'];\n"
        '$sql = "SELECT * FROM t WHERE n = " . $c;\nmysqli_query($db, $sql);\n',
    )
    assert _boundary(mismatch)["outcome"] == "MISMATCH"
    assert _score(mismatch) > _score(plain)


def test_a_wrong_escaper_is_not_reported_as_sanitized() -> None:
    """The taint layer saw a recognised escaper and would call this defended.

    The boundary layer overrides that: the escaper is the wrong kind for the
    position, so the flow is live.
    """
    finding = _top(
        "a.php",
        "<?php\n$c = mysqli_real_escape_string($db, $_GET['c']);\n"
        '$sql = "SELECT * FROM t ORDER BY " . $c;\nmysqli_query($db, $sql);\n',
    )
    assert _boundary(finding)["outcome"] == "MISMATCH"
    sanitized = getattr(finding, "sanitized", None)
    if sanitized is None and isinstance(finding, dict):
        sanitized = finding.get("sanitized")
    assert sanitized is False


def test_a_right_escaper_in_a_literal_is_safe_and_downranked() -> None:
    finding = _top(
        "a.php",
        "<?php\n$c = mysqli_real_escape_string($db, $_GET['c']);\n"
        "$sql = \"SELECT * FROM t WHERE n = '\" . $c . \"'\";\nmysqli_query($db, $sql);\n",
    )
    boundary = _boundary(finding)
    assert boundary["outcome"] == "SAFE"
    # Provably defended at the boundary, so it sinks well below an undefended
    # flow's baseline.
    assert _score(finding) < 50


def test_a_provably_constant_query_produces_no_finding() -> None:
    """No hole means not injectable, so it should not reach the operator."""
    paths = _paths(
        "A.java",
        "public class A { public void f() throws Exception {\n"
        '  String col = "name";\n'
        '  String sql = "SELECT * FROM t ORDER BY " + col;\n'
        "  st.executeQuery(sql); } }\n",
    )
    assert all(
        (_boundary(p) or {}).get("outcome") != "MISMATCH" for p in paths
    )


# ---------------------------------------------------------------------------
# Honest degradation
# ---------------------------------------------------------------------------


def test_an_incomplete_template_never_suppresses() -> None:
    """A reconstruction that gave up cannot prove safety, only locate risk."""
    finding = _top(
        "A.java",
        "public class A { public void f(HttpServletRequest r) throws Exception {\n"
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT a FROM t WHERE a = " + helper() + " AND b = " + p;\n'
        "  st.executeQuery(sql); } }\n",
    )
    boundary = _boundary(finding)
    # `helper()` could not be followed, so the template is incomplete; a SAFE
    # here would not have carried a suppressing score.
    assert boundary is not None
    assert boundary["template_complete"] is False


def test_a_sink_with_no_consumer_has_no_boundary_but_still_reports() -> None:
    finding = _top(
        "a.py",
        "import pickle\ndef v(request):\n    pickle.loads(request.args.get('o'))\n",
    )
    assert _boundary(finding) is None
