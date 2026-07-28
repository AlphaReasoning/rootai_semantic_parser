"""Rebuilding the string a sink actually hands to the consuming parser.

Position analysis is worthless without this. A sink is almost never given a
literal -- it is given a variable that was built two lines earlier -- so unless
the string is reconstructed from the host AST, the consuming grammar only ever
sees a bare identifier and every position is unknown.

These tests assert the reconstruction across host languages and across the
shapes real code uses: concatenation, variable indirection, interpolation, and
values that only look dynamic until they are constant-folded.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig


def _boundaries(filename: str, source: str) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    return [
        (node.get("metadata") or {})["boundary"]
        for node in parser.get_graph()["nodes"]
        if (node.get("metadata") or {}).get("boundary")
    ]


def _one(filename: str, source: str) -> Dict:
    found = _boundaries(filename, source)
    assert found, "no language boundary was recorded at the sink"
    return found[0]


def _positions(boundary: Dict) -> List[str]:
    return [hole["position"] for hole in boundary["holes"]]


# ---------------------------------------------------------------------------
# The same bug, four host languages
# ---------------------------------------------------------------------------

ORDER_BY_INJECTION = {
    "java": (
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT * FROM t ORDER BY " + p;\n'
        '  st.executeQuery(sql); } }\n',
    ),
    "javascript_concat": (
        "a.js",
        'app.get("/x", (req, res) => { db.query("SELECT * FROM t ORDER BY " + req.query.c); });\n',
    ),
    "javascript_template_literal": (
        "a.js",
        'app.get("/x", (req, res) => { db.query(`SELECT * FROM t ORDER BY ${req.query.c}`); });\n',
    ),
    "php": (
        "a.php",
        '<?php\n$c = $_GET["c"];\n$sql = "SELECT * FROM t ORDER BY " . $c;\nmysqli_query($db, $sql);\n',
    ),
}


@pytest.mark.parametrize("case", sorted(ORDER_BY_INJECTION))
def test_order_by_hole_is_an_identifier_position(case: str) -> None:
    """The position no escaper can defend, recovered in every host language."""
    filename, source = ORDER_BY_INJECTION[case]
    boundary = _one(filename, source)
    assert boundary["consumer"] == "sql"
    assert "sql:identifier" in _positions(boundary), f"{case}: got {_positions(boundary)}"
    assert boundary["structural"] is True


def test_a_quoted_literal_is_distinguished_from_an_identifier() -> None:
    """Same sink, same taint path, different required defence."""
    boundary = _one(
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT * FROM t WHERE n = \'" + p + "\'";\n'
        '  st.executeQuery(sql); } }\n',
    )
    assert _positions(boundary) == ["sql:quoted-literal"]
    assert boundary["structural"] is False


# ---------------------------------------------------------------------------
# Reaching the sink through a variable
# ---------------------------------------------------------------------------


def test_the_template_survives_variable_indirection() -> None:
    """Sinks are handed variables, not literals. Following the binding is the
    whole reason position analysis is possible on real code."""
    boundary = _one(
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  String p = r.getParameter("p");\n'
        '  String sql = "SELECT * FROM t ORDER BY " + p;\n'
        '  st.executeQuery(sql); } }\n',
    )
    assert boundary["template"].startswith("SELECT * FROM t ORDER BY ")
    assert boundary["complete"] is True


def test_interpolation_keeps_the_surrounding_syntax() -> None:
    """Dropping the whitespace around a hole changes the parse.

    `ORDER BY ${col}` rendered as `ORDER BYROOTAIHOLE0` is one identifier, and
    the position silently becomes unclassifiable.
    """
    boundary = _one(
        "a.js",
        'app.get("/x", (req, res) => { db.query(`SELECT * FROM t ORDER BY ${req.query.c}`); });\n',
    )
    assert "ORDER BY ROOTAIHOLE0" in boundary["template"]


# ---------------------------------------------------------------------------
# Low-risk code that composes into something provably safe
# ---------------------------------------------------------------------------


def test_a_folded_constant_leaves_no_hole_at_all() -> None:
    """`col = "name"` is not attacker-controlled however it is spelled.

    A template with no holes is a proof of safety, not an absence of evidence,
    and is what stops this layer from simply flagging every query.
    """
    boundary = _one(
        "A.java",
        'public class A { public void f() throws Exception {\n'
        '  String col = "name";\n'
        '  String sql = "SELECT * FROM t ORDER BY " + col;\n'
        '  st.executeQuery(sql); } }\n',
    )
    assert boundary["holes"] == []
    assert boundary["no_holes"] is True


def test_a_parameterised_query_records_no_hole() -> None:
    boundary = _one(
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  java.sql.PreparedStatement s = c.prepareStatement("SELECT * FROM t WHERE id = ?");\n'
        '  s.execute(); } }\n',
    )
    assert boundary["no_holes"] is True


# ---------------------------------------------------------------------------
# Consumers other than SQL
# ---------------------------------------------------------------------------


def test_shell_argument_position_is_recovered() -> None:
    boundary = _one(
        "a.js",
        "const cp = require('child_process');\n"
        'app.get("/x", (req, res) => { cp.execSync("ping -c 1 " + req.query.h); });\n',
    )
    assert boundary["consumer"] == "shell"
    assert _positions(boundary) == ["shell:unquoted-argument"]


def test_a_value_inside_a_script_block_is_javascript_not_html() -> None:
    """The finding a taint engine calls defended when html.escape is present."""
    boundary = _one(
        "A.java",
        "public class A { public void f(HttpServletRequest r, HttpServletResponse s) throws Exception {\n"
        '  String p = r.getParameter("p");\n'
        '  s.getWriter().println("<script>var a=\'" + p + "\';</script>"); } }\n',
    )
    assert boundary["consumer"] == "html"
    assert _positions(boundary) == ["html:script-body"]
    assert boundary["structural"] is True


# ---------------------------------------------------------------------------
# Degrading honestly
# ---------------------------------------------------------------------------


def test_a_helper_call_is_a_hole_in_a_known_position() -> None:
    """Not knowing what a helper returns does not stop the position being known.

    `"... WHERE n = " + buildIt(r)` puts *something* at an unquoted operand,
    which is the fact worth reporting; what the helper returns only decides
    whether it is attacker-controlled, and that is taint analysis's job.
    """
    boundary = _one(
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  String sql = "SELECT * FROM t WHERE n = " + buildIt(r);\n'
        '  st.executeQuery(sql); } }\n',
    )
    assert _positions(boundary) == ["sql:unquoted-value"]


def test_a_query_built_entirely_elsewhere_claims_nothing() -> None:
    """No syntax was recovered, so any position would be an artifact.

    The probe token alone parses as an identifier, and reporting that would be
    a confident claim derived from nothing but the placeholder.
    """
    assert not _boundaries(
        "A.java",
        'public class A { public void f(HttpServletRequest r) throws Exception {\n'
        '  st.executeQuery(buildQuery(r)); } }\n',
    )


def test_a_sink_with_no_modelled_consumer_records_no_boundary() -> None:
    """Deserialization is not a grammar this models; nothing is claimed."""
    assert not _boundaries(
        "a.py",
        "import pickle\ndef v(request):\n    pickle.loads(request.args.get('o'))\n",
    )


# ---------------------------------------------------------------------------
# Interpolation must not be mistaken for fixed text
# ---------------------------------------------------------------------------

INTERPOLATED_LITERAL = {
    "php": (
        "a.php",
        '<?php\n$c = $_GET["c"];\n$sql = "SELECT * FROM t WHERE n = \'$c\'";\n'
        "mysqli_query($db, $sql);\n",
    ),
    "javascript": (
        "a.js",
        'app.get("/x", (req, res) => {\n'
        "  db.query(`SELECT * FROM t WHERE n = '${req.query.c}'`);\n});\n",
    ),
}


@pytest.mark.parametrize("case", sorted(INTERPOLATED_LITERAL))
def test_an_interpolated_value_keeps_the_embedded_quotes(case: str) -> None:
    """Regression: the quote belonged to SQL, not to the host string.

    Reconstruction strips the host language's delimiters. The chunk before an
    interpolation in `"... WHERE n = '$c'"` *ends* in a quote that is part of
    the query, and removing it moved the hole from a quoted literal to a bare
    operand -- inverting which defence is required.
    """
    filename, source = INTERPOLATED_LITERAL[case]
    boundary = _one(filename, source)
    assert _positions(boundary) == ["sql:quoted-literal"], boundary["template"]


def test_unbraced_interpolation_is_not_a_constant() -> None:
    """Regression, and the most dangerous class of bug in this layer.

    PHP's `"ORDER BY $c"` has no braces, so a constant folder looking only for
    `${...}` read the whole string as fixed text. That produces a template with
    no holes, which this layer reports as *proof of safety* -- a false negative
    manufactured out of a false constant.
    """
    boundary = _one(
        "a.php",
        '<?php\n$c = $_GET["c"];\n$sql = "SELECT * FROM t ORDER BY $c";\nmysqli_query($db, $sql);\n',
    )
    assert boundary["no_holes"] is False
    assert _positions(boundary) == ["sql:identifier"]


def test_single_quoted_php_really_is_constant() -> None:
    """The other direction: single quotes interpolate in none of these languages."""
    boundary = _one(
        "a.php",
        "<?php\n$sql = 'SELECT * FROM t ORDER BY name';\nmysqli_query($db, $sql);\n",
    )
    assert boundary["no_holes"] is True


def test_python_fstring_boundary_is_reconstructed() -> None:
    """The ast engine now reconstructs templates, so Python -- the primary
    pre-ship language here -- has boundary analysis like the rest."""
    boundary = _one(
        "a.py",
        "def v(request):\n"
        "    c = request.args.get('c')\n"
        "    cur.execute(f\"SELECT * FROM t WHERE n = '{c}'\")\n",
    )
    assert _positions(boundary) == ["sql:quoted-literal"]


def test_python_percent_and_format_reconstruct() -> None:
    for source in (
        "def v(request):\n    n = request.args.get('n')\n"
        "    cur.execute('SELECT * FROM t ORDER BY %s' % n)\n",
        "def v(request):\n    n = request.args.get('n')\n"
        "    cur.execute('SELECT * FROM t ORDER BY {}'.format(n))\n",
    ):
        boundary = _one("a.py", source)
        assert _positions(boundary) == ["sql:identifier"], boundary["template"]
