"""A corpus labelled for grammatical-boundary analysis.

OWASP Benchmark cannot measure what this tool's boundary layer does. Every one
of its injection cases puts the value in the same place -- a quoted literal or a
bare operand -- so it never exercises the distinction the layer exists for: that
the *same* tainted value reaching the *same* sink is a different bug, needing a
different defence, depending on its grammatical position, and that a defence can
be present and still be the wrong kind.

So this corpus is authored for that capability. Each case is a minimal but
realistic snippet whose ground truth is known by construction: the consuming
language, the grammatical position the value lands in, whether a defence is
present and whether it fits, and therefore whether the code is actually
vulnerable.

Honesty about provenance. These are **synthetic reproductions of known bug
classes**, not samples found in the wild. The classes are real and
well-documented (ORDER BY injection, wrong-context output encoding, shell
command-name substitution); the specific code is written here. No case claims a
CVE number it cannot substantiate. What the corpus measures is whether the tool
classifies position and defence-adequacy correctly, which is a property of the
analysis, not of any particular victim application.

The labels are the point of review, so they live beside the source they
describe rather than in a separate file that can drift.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Verdict vocabulary, matching analyzers/boundaries.py.
MISMATCH = "MISMATCH"        # a defence is present and wrong for the position
UNDEFENDED = "UNDEFENDED"    # no applicable defence
SAFE = "SAFE"                # defended, or provably no hole
NONE = "NONE"               # no taint finding should exist at all


@dataclass
class Case:
    id: str
    filename: str
    source: str
    #: The consuming language, or None when the sink parses no embedded language.
    consumer: Optional[str]
    #: Expected grammatical position, e.g. "sql:identifier"; None if no boundary.
    expect_position: Optional[str]
    #: Expected boundary verdict; NONE when no finding should be produced.
    expect_verdict: str
    #: The real-world truth: is this code actually exploitable?
    is_vulnerable: bool
    #: One line a reviewer can check the label against.
    rationale: str
    #: "synthetic" plus the bug class it reproduces.
    provenance: str
    #: Cases the current engine is known not to handle yet, scored separately so
    #: the headline is not inflated by hiding them.
    known_gap: bool = False


def _c(**kwargs) -> Case:
    return Case(**kwargs)


CASES: List[Case] = [
    # -----------------------------------------------------------------------
    # SQL -- quoted literal: escaping is the right defence here
    # -----------------------------------------------------------------------
    _c(
        id="sql_literal_undefended_php",
        filename="sql_literal_undefended.php",
        source=(
            "<?php\n$name = $_GET['name'];\n"
            "$sql = \"SELECT * FROM users WHERE name = '\" . $name . \"'\";\n"
            "mysqli_query($db, $sql);\n"
        ),
        consumer="sql",
        expect_position="sql:quoted-literal",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="value in a quoted literal with no escaping; classic quote-break SQLi",
        provenance="synthetic: string-literal SQL injection",
    ),
    _c(
        id="sql_literal_escaped_php",
        filename="sql_literal_escaped.php",
        source=(
            "<?php\n$name = mysqli_real_escape_string($db, $_GET['name']);\n"
            "$sql = \"SELECT * FROM users WHERE name = '\" . $name . \"'\";\n"
            "mysqli_query($db, $sql);\n"
        ),
        consumer="sql",
        expect_position="sql:quoted-literal",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="quote-escaping is exactly the right defence for a quoted literal",
        provenance="synthetic: correctly-escaped literal (negative control)",
    ),
    _c(
        id="sql_literal_undefended_java",
        filename="SqlLiteralUndefended.java",
        source=(
            "public class SqlLiteralUndefended {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String name = r.getParameter(\"name\");\n"
            "    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";\n"
            "    stmt.executeQuery(sql);\n  }\n}\n"
        ),
        consumer="sql",
        expect_position="sql:quoted-literal",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="same class in Java; value in a quoted literal, no escaping",
        provenance="synthetic: string-literal SQL injection",
    ),
    # -----------------------------------------------------------------------
    # SQL -- identifier position: escaping is INERT, this is the differentiator
    # -----------------------------------------------------------------------
    _c(
        id="sql_orderby_undefended_js",
        filename="sql_orderby_undefended.js",
        source=(
            "app.get('/products', (req, res) => {\n"
            "  db.query('SELECT * FROM products ORDER BY ' + req.query.sort);\n"
            "});\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="ORDER BY target is an identifier position; no allowlist present",
        provenance="synthetic: ORDER BY injection (a widespread real class)",
    ),
    _c(
        id="sql_orderby_wrong_escaper_php",
        filename="sql_orderby_wrong_escaper.php",
        source=(
            "<?php\n$sort = mysqli_real_escape_string($db, $_GET['sort']);\n"
            "$sql = \"SELECT * FROM products ORDER BY \" . $sort;\n"
            "mysqli_query($db, $sql);\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=MISMATCH,
        is_vulnerable=True,
        rationale="escaping is applied but does nothing in an identifier position; the ships-to-prod bug",
        provenance="synthetic: ORDER BY injection defended by the wrong tool",
    ),
    _c(
        id="sql_orderby_wrong_escaper_java",
        filename="SqlOrderByWrongEscaper.java",
        source=(
            "public class SqlOrderByWrongEscaper {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String sort = escapeSql(r.getParameter(\"sort\"));\n"
            "    String sql = \"SELECT * FROM products ORDER BY \" + sort;\n"
            "    stmt.executeQuery(sql);\n  }\n}\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        # escapeSql is not a recognised capability, so the tool cannot know it
        # is the wrong tool -- it should report UNDEFENDED, not MISMATCH. Being
        # honest about that boundary of knowledge is the correct behaviour.
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="unknown escaper on an identifier position; tool cannot confirm it fits, still flags",
        provenance="synthetic: ORDER BY injection, unrecognised defence",
    ),
    _c(
        id="sql_orderby_numeric_cast_java",
        filename="SqlOrderByNumericCast.java",
        source=(
            "public class SqlOrderByNumericCast {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    int col = Integer.parseInt(r.getParameter(\"col\"));\n"
            "    String sql = \"SELECT * FROM products ORDER BY \" + col;\n"
            "    stmt.executeQuery(sql);\n  }\n}\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="a value parsed to int cannot carry a payload for any position",
        provenance="synthetic: numeric coercion (negative control)",
    ),
    # -----------------------------------------------------------------------
    # SQL -- unquoted numeric operand
    # -----------------------------------------------------------------------
    _c(
        id="sql_unquoted_operand_php",
        filename="sql_unquoted_operand.php",
        source=(
            "<?php\n$id = $_GET['id'];\n"
            "$sql = \"SELECT * FROM users WHERE id = \" . $id;\n"
            "mysqli_query($db, $sql);\n"
        ),
        consumer="sql",
        expect_position="sql:unquoted-value",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="bare comparison operand; escaping quotes would not help, only parameterise/cast",
        provenance="synthetic: numeric-context SQL injection",
    ),
    # -----------------------------------------------------------------------
    # SQL -- provably constant: not injectable at all
    # -----------------------------------------------------------------------
    _c(
        id="sql_constant_column_java",
        filename="SqlConstantColumn.java",
        source=(
            "public class SqlConstantColumn {\n"
            "  public void run() throws Exception {\n"
            "    String col = \"name\";\n"
            "    String sql = \"SELECT * FROM products ORDER BY \" + col;\n"
            "    stmt.executeQuery(sql);\n  }\n}\n"
        ),
        consumer="sql",
        expect_position=None,
        expect_verdict=NONE,
        is_vulnerable=False,
        rationale="the column folds to a constant, so there is no hole to attack",
        provenance="synthetic: constant folds to no hole (negative control)",
    ),
    # -----------------------------------------------------------------------
    # Shell -- argument vs command name
    # -----------------------------------------------------------------------
    _c(
        id="shell_arg_undefended_js",
        filename="shell_arg_undefended.js",
        source=(
            "const cp = require('child_process');\n"
            "app.get('/ping', (req, res) => {\n"
            "  cp.execSync('ping -c 1 ' + req.query.host);\n"
            "});\n"
        ),
        consumer="shell",
        expect_position="shell:unquoted-argument",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="unquoted shell argument; ';', '|', '$()' all break out",
        provenance="synthetic: OS command injection",
    ),
    _c(
        id="shell_arg_quoted_php",
        filename="shell_arg_quoted.php",
        source=(
            "<?php\n$host = escapeshellarg($_GET['host']);\n"
            "system('ping -c 1 ' . $host);\n"
        ),
        consumer="shell",
        expect_position="shell:unquoted-argument",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="escapeshellarg is the right defence for an argument position",
        provenance="synthetic: correctly-escaped shell arg (negative control)",
    ),
    _c(
        id="shell_command_name_wrong_defence_php",
        filename="shell_command_name_wrong_defence.php",
        source=(
            "<?php\n$cmd = escapeshellarg($_GET['cmd']);\n"
            "system($cmd . ' --version');\n"
        ),
        consumer="shell",
        expect_position="shell:command-name",
        expect_verdict=MISMATCH,
        is_vulnerable=True,
        rationale="quoting the command name still lets the value choose which program runs",
        provenance="synthetic: command-name substitution defended by arg quoting",
    ),
    # -----------------------------------------------------------------------
    # HTML -- output encoding is context-specific
    # -----------------------------------------------------------------------
    _c(
        id="html_text_undefended_js",
        filename="html_text_undefended.js",
        source=(
            "app.get('/hello', (req, res) => {\n"
            "  res.send('<div>' + req.query.name + '</div>');\n"
            "});\n"
        ),
        consumer="html",
        expect_position="html:text",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="value in element text with no encoding; reflected XSS",
        provenance="synthetic: reflected XSS in text context",
    ),
    _c(
        id="html_text_escaped_js",
        filename="html_text_escaped.js",
        source=(
            "app.get('/hello', (req, res) => {\n"
            "  const safe = escapeHtml(req.query.name);\n"
            "  res.send('<div>' + safe + '</div>');\n"
            "});\n"
        ),
        consumer="html",
        expect_position="html:text",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="HTML escaping is exactly right for text context",
        provenance="synthetic: correctly-encoded text (negative control)",
    ),
    _c(
        id="html_script_wrong_encoding_js",
        filename="html_script_wrong_encoding.js",
        source=(
            "app.get('/cfg', (req, res) => {\n"
            "  const safe = escapeHtml(req.query.v);\n"
            "  res.send(\"<script>var cfg='\" + safe + \"';</script>\");\n"
            "});\n"
        ),
        consumer="html",
        expect_position="html:script-body",
        expect_verdict=MISMATCH,
        is_vulnerable=True,
        rationale="inside <script> the value is JavaScript; HTML escaping is the wrong encoding",
        provenance="synthetic: XSS in script context defended by HTML encoding",
    ),
    _c(
        id="html_url_attr_wrong_encoding_js",
        filename="html_url_attr_wrong_encoding.js",
        source=(
            "app.get('/link', (req, res) => {\n"
            "  const safe = escapeHtml(req.query.url);\n"
            "  res.send(\"<a href='\" + safe + \"'>go</a>\");\n"
            "});\n"
        ),
        consumer="html",
        expect_position="html:url-attribute",
        expect_verdict=MISMATCH,
        is_vulnerable=True,
        rationale="HTML escaping does not stop a javascript: URL in an href",
        provenance="synthetic: javascript:-scheme XSS defended by HTML encoding",
    ),
    # -----------------------------------------------------------------------
    # Non-boundary sinks: the tool should not claim position analysis it lacks
    # -----------------------------------------------------------------------
    _c(
        id="deserialization_no_boundary_php",
        filename="deserialization_no_boundary.php",
        source=(
            "<?php\n$obj = unserialize($_GET['o']);\n"
        ),
        consumer=None,
        expect_position=None,
        expect_verdict=NONE,  # a finding may exist, but no boundary verdict
        is_vulnerable=True,
        rationale="deserialization is not a grammar boundary; the tool should record no boundary",
        provenance="synthetic: object-injection sink outside the boundary model",
    ),
    # -----------------------------------------------------------------------
    # Harder cases: multiple holes, correct-defence variety, realistic shapes.
    # These exist to give the corpus teeth -- a suite with no failures measures
    # nothing.
    # -----------------------------------------------------------------------
    _c(
        id="sql_multihole_worst_wins_java",
        filename="SqlMultiHole.java",
        source=(
            "public class SqlMultiHole {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String n = r.getParameter(\"n\");\n"
            "    String sort = r.getParameter(\"sort\");\n"
            "    String sql = \"SELECT * FROM t WHERE n = '\" + n + \"' ORDER BY \" + sort;\n"
            "    stmt.executeQuery(sql);\n  }\n}\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="two holes -- a quoted literal and an identifier; the structural one is the worst and should win",
        provenance="synthetic: multi-hole query, worst position reported",
    ),
    _c(
        id="sql_prepared_placeholder_java",
        filename="SqlPrepared.java",
        source=(
            "public class SqlPrepared {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String n = r.getParameter(\"n\");\n"
            "    PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE n = ?\");\n"
            "    ps.setString(1, n);\n    ps.executeQuery();\n  }\n}\n"
        ),
        consumer="sql",
        expect_position=None,
        expect_verdict=NONE,
        is_vulnerable=False,
        rationale="a ? placeholder is not a hole the value can escape; parameterised",
        provenance="synthetic: prepared statement (negative control)",
    ),
    _c(
        id="html_attr_value_undefended_js",
        filename="html_attr_value_undefended.js",
        source=(
            "app.get('/p', (req, res) => {\n"
            "  res.send(\"<div class='\" + req.query.c + \"'>x</div>\");\n"
            "});\n"
        ),
        consumer="html",
        expect_position="html:attribute-value",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="quoted attribute value with no encoding; break out with a quote and angle bracket",
        provenance="synthetic: XSS in attribute-value context",
    ),
    _c(
        id="sql_decode_then_escape_php",
        filename="sql_decode_then_escape.php",
        source=(
            "<?php\n$raw = urldecode($_GET['name']);\n"
            "$name = mysqli_real_escape_string($db, $raw);\n"
            "$sql = \"SELECT * FROM users WHERE name = '\" . $name . \"'\";\n"
            "mysqli_query($db, $sql);\n"
        ),
        consumer="sql",
        expect_position="sql:quoted-literal",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="escaping is applied last and fits the literal position; the decode before it does not reintroduce quotes",
        provenance="synthetic: decode-then-escape, correct ordering",
    ),
    _c(
        id="sql_stringbuilder_java",
        filename="SqlStringBuilder.java",
        source=(
            "public class SqlStringBuilder {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String sort = r.getParameter(\"sort\");\n"
            "    StringBuilder sb = new StringBuilder();\n"
            "    sb.append(\"SELECT * FROM t ORDER BY \");\n"
            "    sb.append(sort);\n"
            "    stmt.executeQuery(sb.toString());\n  }\n}\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="StringBuilder-assembled query; the value is still an ORDER BY identifier",
        provenance="synthetic: StringBuilder query assembly",
    ),
    _c(
        id="sql_allowlist_guard_js",
        filename="sql_allowlist_guard.js",
        source=(
            "app.get('/p', (req, res) => {\n"
            "  const sort = req.query.sort;\n"
            "  if (!['name', 'price'].includes(sort)) return res.status(400).end();\n"
            "  db.query('SELECT * FROM products ORDER BY ' + sort);\n"
            "});\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="an allowlist guard constrains the value to two column names; the right defence for an identifier position",
        provenance="synthetic: allowlist guard at identifier position",
    ),
    # -----------------------------------------------------------------------
    # XPath -- hand-written classifier (no tree-sitter grammar)
    # -----------------------------------------------------------------------
    _c(
        id="xpath_string_literal_undefended_java",
        filename="XPathStringUndefended.java",
        source=(
            "public class XPathStringUndefended {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String id = r.getParameter(\"id\");\n"
            "    String expr = \"/Employees/Employee[@emplid='\" + id + \"']\";\n"
            "    String result = xp.evaluate(expr, xmlDocument);\n  }\n}\n"
        ),
        consumer="xpath",
        expect_position="xpath:string-literal",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="value in an XPath string literal with no encoding; break out with a quote",
        provenance="synthetic: XPath injection in a string literal",
    ),
    _c(
        id="xpath_string_literal_encoded_java",
        filename="XPathStringEncoded.java",
        source=(
            "public class XPathStringEncoded {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String id = ESAPI.encoder().encodeForXPath(r.getParameter(\"id\"));\n"
            "    String expr = \"/Employees/Employee[@emplid='\" + id + \"']\";\n"
            "    String result = xp.evaluate(expr, xmlDocument);\n  }\n}\n"
        ),
        consumer="xpath",
        expect_position="xpath:string-literal",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="encodeForXPath fits a string-literal position",
        provenance="synthetic: correctly-encoded XPath literal (negative control)",
    ),
    # -----------------------------------------------------------------------
    # LDAP -- hand-written classifier
    # -----------------------------------------------------------------------
    _c(
        id="ldap_filter_value_undefended_java",
        filename="LdapFilterUndefended.java",
        source=(
            "public class LdapFilterUndefended {\n"
            "  public void run(HttpServletRequest r) throws Exception {\n"
            "    String name = r.getParameter(\"name\");\n"
            "    String filter = \"(uid=\" + name + \")\";\n"
            "    idc.search(base, filter, filters, sc);\n  }\n}\n"
        ),
        consumer="ldap",
        expect_position="ldap:filter-value",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="value in an LDAP filter with no escaping; `*)(uid=*` breaks out",
        provenance="synthetic: LDAP injection in a filter value",
    ),
    _c(
        id="ldap_filter_value_encoded_php",
        filename="ldap_filter_encoded.php",
        source=(
            "<?php\n$user = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);\n"
            "$filter = \"(uid=\" . $user . \")\";\n"
            "ldap_search($conn, $base, $filter);\n"
        ),
        consumer="ldap",
        expect_position="ldap:filter-value",
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="ldap_escape with LDAP_ESCAPE_FILTER fits a filter-value position",
        provenance="synthetic: correctly-escaped LDAP filter (negative control)",
    ),
    # -----------------------------------------------------------------------
    # Python host language, via the ast engine's own reconstruction
    # -----------------------------------------------------------------------
    _c(
        id="python_fstring_literal",
        filename="python_fstring.py",
        source=(
            "def view(request):\n"
            "    name = request.args.get('name')\n"
            "    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        ),
        consumer="sql",
        expect_position="sql:quoted-literal",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="f-string interpolation into a quoted literal; ast engine reconstructs it",
        provenance="synthetic: Python f-string SQL injection",
    ),
    _c(
        id="python_fstring_orderby",
        filename="python_fstring_orderby.py",
        source=(
            "def view(request):\n"
            "    sort = request.args.get('sort')\n"
            "    cur.execute(f\"SELECT * FROM products ORDER BY {sort}\")\n"
        ),
        consumer="sql",
        expect_position="sql:identifier",
        expect_verdict=UNDEFENDED,
        is_vulnerable=True,
        rationale="f-string into an ORDER BY identifier; escaping cannot help",
        provenance="synthetic: Python ORDER BY injection",
    ),
    _c(
        id="python_parameterised_safe",
        filename="python_parameterised.py",
        source=(
            "def view(request):\n"
            "    n = request.args.get('n')\n"
            "    cur.execute('SELECT * FROM t WHERE n = ?', (n,))\n"
        ),
        consumer="sql",
        expect_position=None,
        expect_verdict=SAFE,
        is_vulnerable=False,
        rationale="a ? placeholder with the value passed separately is parameterised",
        provenance="synthetic: Python parameterised query (negative control)",
    ),
]


def write_corpus(destination: Path) -> Dict[str, Case]:
    """Write every case's source to ``destination`` and return them by id."""
    destination.mkdir(parents=True, exist_ok=True)
    for case in CASES:
        (destination / case.filename).write_text(case.source, encoding="utf-8")
    return {case.id: case for case in CASES}


def labels() -> List[Dict]:
    return [asdict(case) for case in CASES]


if __name__ == "__main__":
    # Emit the labels for review.
    print(json.dumps(labels(), indent=2))
