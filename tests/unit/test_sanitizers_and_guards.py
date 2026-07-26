"""Sanitizers and validation guards: evidence that a flow was already defended.

Code that does the right thing was previously reported exactly like code that
does not, which is the largest single noise source on real projects. Two
mechanisms matter:

* **Sanitizers** transform the value -- escaping it, or parsing it into a type
  that cannot carry a payload.
* **Guards** test the value and abandon the path when it fails, so anything
  downstream only sees input that passed the check.

Each case is paired with an unguarded control that must still report at full
severity. A test that only proved suppression would be satisfied by a scanner
that reports nothing.
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


def _sanitized(paths: List[Dict]) -> bool:
    return bool(paths) and all(p.get("sanitization_status") == "sanitized_detected" for p in paths)


def _worst_score(paths: List[Dict]) -> float:
    return max((p["score"] for p in paths), default=0.0)


# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------

SANITIZER_CASES = {
    "python_shlex_quote": (
        "a.py",
        "import os, shlex\ndef h(request):\n    c = request.args.get('c')\n"
        "    s = shlex.quote(c)\n    os.system(s)\n",
        "import os\ndef h(request):\n    c = request.args.get('c')\n    os.system(c)\n",
    ),
    "python_int_coercion": (
        "a.py",
        "import os\ndef h(request):\n    c = request.args.get('c')\n"
        "    n = int(c)\n    os.system('sleep %d' % n)\n",
        "import os\ndef h(request):\n    c = request.args.get('c')\n    os.system(c)\n",
    ),
    "javascript_shellescape": (
        "a.js",
        "const cp = require('child_process');\n"
        "function h(req){ const c = req.query.c; const s = shellescape(c); cp.execSync(s); }\n",
        "const cp = require('child_process');\n"
        "function h(req){ const c = req.query.c; cp.execSync(c); }\n",
    ),
    "php_escapeshellarg": (
        "a.php",
        "<?php\nfunction h(){ $c = $_GET['c']; $s = escapeshellarg($c); system($s); }\n",
        "<?php\nfunction h(){ $c = $_GET['c']; system($c); }\n",
    ),
}


@pytest.mark.parametrize("case", sorted(SANITIZER_CASES))
def test_sanitized_path_is_marked_and_downgraded(case: str) -> None:
    filename, sanitized_source, unsanitized_source = SANITIZER_CASES[case]
    sanitized = _scan(filename, sanitized_source)
    unsanitized = _scan(filename, unsanitized_source)

    assert unsanitized, f"{case}: control must still be reported"
    assert _sanitized(sanitized), f"{case}: sanitizer not detected"
    assert _worst_score(sanitized) < _worst_score(unsanitized), case


def test_sanitizer_call_is_not_bypassed_by_the_assignment_edge() -> None:
    """Regression: an identifier that is only a call argument got a direct edge.

    `s = shlex.quote(c)` linked c straight to s alongside the flow through the
    call, so taint routed around every transforming call and no sanitizer ever
    fired.
    """
    paths = _scan(
        "a.py",
        "import os, shlex\ndef h(request):\n    c = request.args.get('c')\n"
        "    s = shlex.quote(c)\n    os.system(s)\n",
    )
    assert _sanitized(paths)


def test_type_coercion_defends_every_sink_category() -> None:
    """A value parsed into a number cannot carry a payload for any sink.

    Previously int() was recorded as defending only code and SQL, so a command
    sink downstream was still reported at full severity.
    """
    paths = _scan(
        "a.py",
        "import os\ndef h(request):\n    c = request.args.get('c')\n"
        "    n = int(c)\n    os.system('sleep %d' % n)\n",
    )
    assert _sanitized(paths)


def test_escaper_category_lines_up_with_its_sink() -> None:
    """html.escape must defend the XSS sink it exists for."""
    paths = _scan(
        "a.py",
        "import html\ndef h(request):\n    c = request.args.get('c')\n"
        "    s = html.escape(c)\n    res.write(s)\n",
    )
    assert _sanitized(paths)


def test_sanitized_finding_is_never_critical() -> None:
    paths = _scan(
        "a.py",
        "import os, shlex\ndef h(request):\n    c = request.args.get('c')\n"
        "    s = shlex.quote(c)\n    os.system(s)\n",
    )
    assert paths
    assert all(p["severity"] != "critical" for p in paths)


# ---------------------------------------------------------------------------
# Validation guards
# ---------------------------------------------------------------------------

GUARD_CASES = {
    "javascript_allowlist": (
        "a.js",
        "const cp = require('child_process');\nconst OK = ['a','b'];\n"
        "function h(req){ const c = req.query.c; if(!OK.includes(c)) return; cp.execSync(c); }\n",
        "const cp = require('child_process');\n"
        "function h(req){ const c = req.query.c; cp.execSync(c); }\n",
    ),
    "go_membership": (
        "a.go",
        'package main\nimport "os/exec"\n'
        'func h(r *R){ c := r.FormValue("c"); if !contains(OK, c) { return }; exec.Command(c).Run() }\n',
        'package main\nimport "os/exec"\n'
        'func h(r *R){ c := r.FormValue("c"); exec.Command(c).Run() }\n',
    ),
    "java_equality": (
        "A.java",
        'public class A { public void h(HttpServletRequest req) throws Exception {'
        ' String c = req.getParameter("c"); if(!c.equals("ok")) return;'
        ' Runtime.getRuntime().exec(c); } }\n',
        'public class A { public void h(HttpServletRequest req) throws Exception {'
        ' String c = req.getParameter("c"); Runtime.getRuntime().exec(c); } }\n',
    ),
    "php_in_array": (
        "a.php",
        "<?php\nfunction h(){ $c = $_GET['c']; if(!in_array($c, $OK)) return; system($c); }\n",
        "<?php\nfunction h(){ $c = $_GET['c']; system($c); }\n",
    ),
}


@pytest.mark.parametrize("case", sorted(GUARD_CASES))
def test_constraining_guard_downgrades_the_finding(case: str) -> None:
    filename, guarded_source, unguarded_source = GUARD_CASES[case]
    guarded = _scan(filename, guarded_source)
    unguarded = _scan(filename, unguarded_source)

    assert unguarded, f"{case}: control must still be reported"
    assert _worst_score(guarded) < _worst_score(unguarded), case


def test_a_length_check_is_not_treated_as_validation() -> None:
    """A bound on size says nothing about content, so it must not suppress.

    This is the line between modelling guards and quietly dropping findings.
    """
    weak = _scan(
        "a.js",
        "const cp = require('child_process');\n"
        "function h(req){ const c = req.query.c; if(c.length > 100) return; cp.execSync(c); }\n",
    )
    unguarded = _scan(
        "a.js",
        "const cp = require('child_process');\n"
        "function h(req){ const c = req.query.c; cp.execSync(c); }\n",
    )
    assert weak
    assert _worst_score(weak) == _worst_score(unguarded)


def test_guard_without_an_exit_branch_does_not_count() -> None:
    """A test whose failure path falls through has not constrained anything."""
    paths = _scan(
        "a.js",
        "const cp = require('child_process');\nconst OK = ['a','b'];\n"
        "function h(req){ const c = req.query.c; if(OK.includes(c)) { log(c); } cp.execSync(c); }\n",
    )
    assert paths
    assert all(p.get("sanitization_status") == "none_detected" for p in paths)


def test_guard_evidence_is_surfaced_on_the_finding() -> None:
    """An operator should see why a path was downgraded, not just that it was."""
    paths = _scan(
        "a.js",
        "const cp = require('child_process');\nconst OK = ['a','b'];\n"
        "function h(req){ const c = req.query.c; if(!OK.includes(c)) return; cp.execSync(c); }\n",
    )
    assert paths
    assert any(p.get("validation_guards") for p in paths)
