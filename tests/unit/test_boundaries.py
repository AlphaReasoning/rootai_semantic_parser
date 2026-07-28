"""Grammatical position decides the defence, not the sink's name.

A taint tracker reports `query(sql)` identically however `sql` was built. The
whole point of boundary analysis is that it is not identical: a value inside a
quoted literal needs quote escaping, the same value in an ORDER BY target needs
an allowlist because escaping is meaningless there and parameter binding cannot
express the position at all, and a parameterised query has no hole to attack.

Both directions are tested throughout. A classifier that only ever says
"dangerous" has not earned any of the precision it claims.
"""

from __future__ import annotations

from typing import List

import pytest

from rootai_semantic_parser.analyzers.boundaries import (
    MISMATCH,
    SAFE,
    UNDEFENDED,
    UNKNOWN,
    analyse,
    capabilities_of,
    hole_token,
    judge,
)

H = hole_token(0)


def _verdict(template: str, consumer: str, sanitizers: List[str]):
    analysis = analyse(template, consumer)
    assert analysis is not None, f"no analysis for {consumer}: {template}"
    return judge(analysis, sanitizers)


# ---------------------------------------------------------------------------
# SQL: the same value, four positions, four answers
# ---------------------------------------------------------------------------

SQL_POSITIONS = {
    "comparison operand": (f"SELECT * FROM t WHERE id = {H}", "sql:unquoted-value"),
    "quoted literal": (f"SELECT * FROM t WHERE n = '{H}'", "sql:quoted-literal"),
    "order target": (f"SELECT * FROM t ORDER BY {H}", "sql:identifier"),
    "table name": (f"SELECT * FROM {H} WHERE id = 1", "sql:identifier"),
    "projected column": (f"SELECT {H} FROM t", "sql:identifier"),
    "insert literal": (f"INSERT INTO t VALUES ('{H}')", "sql:quoted-literal"),
}


@pytest.mark.parametrize("case", sorted(SQL_POSITIONS))
def test_sql_position_is_identified(case: str) -> None:
    template, expected = SQL_POSITIONS[case]
    verdict = _verdict(template, "sql", [])
    assert verdict.hole is not None, f"{case}: no hole located"
    assert verdict.hole.position.name == expected, f"{case}: got {verdict.hole.position.name}"


def test_a_parameterised_query_has_no_hole_at_all() -> None:
    """Not an absence of evidence -- a proof. No value reaches the parser."""
    verdict = _verdict("SELECT * FROM t WHERE id = ?", "sql", [])
    assert verdict.outcome == SAFE
    assert verdict.hole is None


def test_quote_escaping_defends_a_literal() -> None:
    assert _verdict(f"SELECT * FROM t WHERE n = '{H}'", "sql", ["real_escape_string"]).outcome == SAFE


def test_quote_escaping_does_not_defend_an_identifier() -> None:
    """The finding class that motivates this whole module.

    Escaping quotes in `ORDER BY <value>` accomplishes nothing: there are no
    quotes. A taint engine sees a recognised sanitiser and calls the flow
    defended, and so does a reviewer skimming the diff.
    """
    verdict = _verdict(f"SELECT * FROM t ORDER BY {H}", "sql", ["real_escape_string"])
    assert verdict.outcome == MISMATCH
    assert verdict.hole is not None and verdict.hole.position.structural


def test_numeric_coercion_defends_every_position() -> None:
    """A value parsed into a number cannot carry a payload for any grammar."""
    for template in (
        f"SELECT * FROM t ORDER BY {H}",
        f"SELECT * FROM t WHERE id = {H}",
        f"SELECT * FROM t WHERE n = '{H}'",
    ):
        assert _verdict(template, "sql", ["Integer.parseInt"]).outcome == SAFE


def test_an_undefended_literal_is_still_reported() -> None:
    verdict = _verdict(f"SELECT * FROM t WHERE n = '{H}'", "sql", [])
    assert verdict.outcome == UNDEFENDED


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------

SHELL_POSITIONS = {
    "unquoted argument": (f"ping -c 1 {H}", "shell:unquoted-argument"),
    "double quoted": (f'ping -c 1 "{H}"', "shell:double-quoted"),
    "single quoted": (f"ping -c 1 '{H}'", "shell:single-quoted"),
    "command name": (f"{H} -c 1", "shell:command-name"),
}


@pytest.mark.parametrize("case", sorted(SHELL_POSITIONS))
def test_shell_position_is_identified(case: str) -> None:
    template, expected = SHELL_POSITIONS[case]
    verdict = _verdict(template, "shell", [])
    assert verdict.hole is not None and verdict.hole.position.name == expected


def test_shell_quoting_defends_an_argument() -> None:
    assert _verdict(f"ping -c 1 {H}", "shell", ["shlex.quote"]).outcome == SAFE


def test_shell_quoting_does_not_defend_the_command_name() -> None:
    """Quoting `rm` still runs `rm`. The value chooses the program."""
    verdict = _verdict(f"{H} -c 1", "shell", ["shlex.quote"])
    assert verdict.outcome == MISMATCH
    assert verdict.hole is not None and verdict.hole.position.structural


# ---------------------------------------------------------------------------
# HTML: escaping is context-specific and the context is usually wrong
# ---------------------------------------------------------------------------

HTML_POSITIONS = {
    "element text": (f"<div>{H}</div>", "html:text"),
    "attribute value": (f"<div class='{H}'>x</div>", "html:attribute-value"),
    "url attribute": (f"<a href='{H}'>x</a>", "html:url-attribute"),
    "script body": (f"<script>var a = '{H}';</script>", "html:script-body"),
    "style body": (f"<style>a {{ color: {H} }}</style>", "html:style-body"),
    "attribute name": (f"<div {H}='x'>y</div>", "html:attribute-name"),
}


@pytest.mark.parametrize("case", sorted(HTML_POSITIONS))
def test_html_position_is_identified(case: str) -> None:
    template, expected = HTML_POSITIONS[case]
    verdict = _verdict(template, "html", [])
    assert verdict.hole is not None and verdict.hole.position.name == expected


def test_html_escaping_defends_text_and_attributes() -> None:
    assert _verdict(f"<div>{H}</div>", "html", ["html.escape"]).outcome == SAFE
    assert _verdict(f"<div class='{H}'>x</div>", "html", ["htmlspecialchars"]).outcome == SAFE


HTML_MISMATCHES = {
    "script body is JavaScript, not HTML": f"<script>var a = '{H}';</script>",
    "url attribute permits the javascript: scheme": f"<a href='{H}'>x</a>",
    "attribute name can introduce an event handler": f"<div {H}='x'>y</div>",
}


@pytest.mark.parametrize("case", sorted(HTML_MISMATCHES))
def test_html_escaping_is_the_wrong_defence_here(case: str) -> None:
    verdict = _verdict(HTML_MISMATCHES[case], "html", ["html.escape"])
    assert verdict.outcome == MISMATCH, f"{case}: got {verdict.outcome} ({verdict.detail})"


def test_javascript_escaping_defends_a_script_body() -> None:
    assert _verdict(f"<script>var a = '{H}';</script>", "html", ["encodeForJavaScript"]).outcome == SAFE


# ---------------------------------------------------------------------------
# Degrading rather than guessing
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# XPath and LDAP: hand-written classifiers, no tree-sitter grammar
# ---------------------------------------------------------------------------

XPATH_POSITIONS = {
    "string literal": (f"/Employees/Employee[@id='{H}']", "xpath:string-literal"),
    "predicate expression": (f"/users/user[{H}]", "xpath:expression"),
    "node name": (f"//{H}/text()", "xpath:node-name"),
}


@pytest.mark.parametrize("case", sorted(XPATH_POSITIONS))
def test_xpath_position_is_identified(case: str) -> None:
    template, expected = XPATH_POSITIONS[case]
    verdict = _verdict(template, "xpath", [])
    assert verdict.hole is not None and verdict.hole.position.name == expected


def test_xpath_encoder_defends_a_string_literal() -> None:
    assert _verdict(f"/user[@id='{H}']", "xpath", ["encodeForXPath"]).outcome == SAFE


def test_xpath_encoder_does_not_defend_a_node_name() -> None:
    """A node-name position is structural; escaping the value cannot constrain
    which nodes it selects."""
    verdict = _verdict(f"//{H}/text()", "xpath", ["encodeForXPath"])
    assert verdict.outcome == MISMATCH
    assert verdict.hole is not None and verdict.hole.position.structural


LDAP_POSITIONS = {
    "filter value": (f"(uid={H})", "ldap:filter-value"),
    "value in and-group": (f"(&(uid={H})(objectClass=person))", "ldap:filter-value"),
    "attribute name": (f"({H}=admin)", "ldap:filter-structure"),
}


@pytest.mark.parametrize("case", sorted(LDAP_POSITIONS))
def test_ldap_position_is_identified(case: str) -> None:
    template, expected = LDAP_POSITIONS[case]
    verdict = _verdict(template, "ldap", [])
    assert verdict.hole is not None and verdict.hole.position.name == expected


def test_ldap_encoder_defends_a_filter_value() -> None:
    assert _verdict(f"(uid={H})", "ldap", ["encodeForLDAP"]).outcome == SAFE


def test_ldap_encoder_does_not_defend_the_filter_structure() -> None:
    """Escaping a value does nothing when the value is the attribute name."""
    verdict = _verdict(f"({H}=admin)", "ldap", ["encodeForLDAP"])
    assert verdict.outcome == MISMATCH
    assert verdict.hole is not None and verdict.hole.position.structural


def test_an_unknown_consumer_yields_no_analysis() -> None:
    """Callers fall back to ordinary taint reasoning; nothing is suppressed."""
    assert analyse(f"foo {H}", "brainfuck") is None


def test_an_unrecognised_defence_is_unknown_not_absent() -> None:
    """Claiming a helper does nothing is as wrong as claiming it works."""
    verdict = _verdict(f"SELECT * FROM t WHERE n = '{H}'", "sql", ["companySpecificScrubber"])
    assert verdict.outcome == UNKNOWN


def test_capabilities_are_recognised_through_qualified_names() -> None:
    known, unknown = capabilities_of(["mysqli_real_escape_string", "com.acme.Weird"])
    assert "quote-escape" in known
    assert unknown == ("com.acme.weird",)


def test_multiple_holes_report_the_worst_position() -> None:
    """A query with one safe and one structural hole is not a safe query."""
    template = f"SELECT * FROM t WHERE n = '{hole_token(0)}' ORDER BY {hole_token(1)}"
    verdict = _verdict(template, "sql", ["real_escape_string"])
    assert verdict.outcome == MISMATCH
    assert verdict.hole is not None and verdict.hole.position.name == "sql:identifier"
