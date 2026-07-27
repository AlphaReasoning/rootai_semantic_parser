"""Sinks and sources mean different things in different languages.

The taint vocabulary is one flat set applied to every language, which works
while the names are distinctive (``pickle.loads``, ``execSync``) and fails the
moment they are ordinary words. Scoring against OWASP Benchmark made the cost
visible: PHP's ``include`` sink fired on Java's ``RequestDispatcher.include``,
which appears in the boilerplate of nearly every servlet, and the C ``system``
sink fired on ``System.out.println``.

Both directions are tested. A rule that suppresses a real sink to buy quiet is
worse than the noise it removes.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig


def _scan(filename: str, source: str) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


# ---------------------------------------------------------------------------
# Suppressed where the name is innocent
# ---------------------------------------------------------------------------

INNOCENT = {
    "java_request_dispatcher_include": (
        "A.java",
        "public class A {\n"
        "  public void doGet(HttpServletRequest request, HttpServletResponse response)\n"
        "      throws Exception {\n"
        "    javax.servlet.RequestDispatcher rd = request.getRequestDispatcher(\"/x.html\");\n"
        "    rd.include(request, response);\n"
        "  }\n"
        "}\n",
    ),
    "java_system_out_println": (
        "A.java",
        "public class A {\n"
        "  public void doGet(HttpServletRequest req) {\n"
        "    String c = req.getParameter(\"c\");\n"
        "    System.out.println(c);\n"
        "  }\n"
        "}\n",
    ),
    "java_string_format": (
        "A.java",
        "public class A {\n"
        "  public void doGet(HttpServletRequest req) {\n"
        "    String c = req.getParameter(\"c\");\n"
        "    String s = String.format(\"%s\", c);\n"
        "  }\n"
        "}\n",
    ),
}


@pytest.mark.parametrize("case", sorted(INNOCENT))
def test_sink_does_not_fire_outside_its_language(case: str) -> None:
    filename, source = INNOCENT[case]
    assert not _scan(filename, source), f"{case}: reported a sink that does not exist in this language"


# ---------------------------------------------------------------------------
# Still detected where the name is the real thing
# ---------------------------------------------------------------------------

GENUINE = {
    "php_include": ("a.php", "<?php\n$p = $_GET['p'];\ninclude($p);\n"),
    "c_system": (
        "a.c",
        "#include <stdlib.h>\nvoid run(void){ char buf[64]; gets(buf); system(buf); }\n",
    ),
    "objc_system": (
        "a.m",
        'void run(char* c){ system(c); }\nvoid handler(){ char* cmd = getenv("C"); run(cmd); }\n',
    ),
    "r_system": (
        "a.R",
        'run <- function(c) { system(c) }\nhandler <- function() { cmd <- Sys.getenv("C"); run(cmd) }\n',
    ),
    "java_runtime_exec": (
        "A.java",
        "public class A {\n"
        "  public void doGet(HttpServletRequest req) throws Exception {\n"
        "    Runtime.getRuntime().exec(req.getParameter(\"c\"));\n"
        "  }\n"
        "}\n",
    ),
}


@pytest.mark.parametrize("case", sorted(GENUINE))
def test_sink_still_fires_in_its_own_language(case: str) -> None:
    filename, source = GENUINE[case]
    assert _scan(filename, source), f"{case}: suppressed a real sink"


# ---------------------------------------------------------------------------
# Literals are prose, except where they are not
# ---------------------------------------------------------------------------


def test_a_string_containing_a_source_name_is_not_a_source() -> None:
    """`println("Error processing request.")` contains the segment `request`.

    Matching source patterns against the inside of a string made that line --
    which sits in the catch block of nearly every servlet ever written -- an
    attacker-controlled value. It was the single largest false-positive cause
    measured against OWASP Benchmark.
    """
    assert not _scan(
        "A.java",
        "public class A {\n"
        "  public void doGet(HttpServletResponse response) throws Exception {\n"
        "    response.getWriter().println(\"Error processing request.\");\n"
        "  }\n"
        "}\n",
    )


def test_an_interpolated_variable_inside_a_string_is_still_read() -> None:
    """The other direction: a literal can contain live code.

    `cmd="$QUERY_STRING"` and `f"ls {path}"` read a value. Discarding whole
    literals to fix the case above would have silently dropped these.
    """
    assert _scan("a.sh", 'run() { eval "$1"; }\nhandler() { cmd="$QUERY_STRING"; run "$cmd"; }\n')


def test_python_fstring_interpolation_is_read() -> None:
    assert _scan(
        "a.py",
        "import os\ndef view(request):\n    c = request.args.get('c')\n    os.system(f'ls {c}')\n",
    )
