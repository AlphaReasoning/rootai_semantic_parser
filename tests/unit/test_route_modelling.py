"""HTTP route modelling: which findings are actually reachable from outside.

Entry points used to be guessed from function names, which inverted the ranking
that matters most for triage. A routed admin endpoint scored *lower* than an
unrouted helper, because the helper's labels happened to contain a word on the
heuristic list.

Detecting the route registration itself fixes the ranking and, more usefully,
recovers the URL. A finding that says "POST /admin/exec" is something an
operator can go and test; "this function is tainted" is not.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig


def _graph(filename: str, source: str) -> Dict:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    return parser.get_graph()


def _routes(filename: str, source: str) -> List[str]:
    graph = _graph(filename, source)
    return sorted(
        {
            str((n.get("metadata") or {}).get("route"))
            for n in graph["nodes"]
            if (n.get("metadata") or {}).get("route")
        }
    )


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
# Detection, per framework
# ---------------------------------------------------------------------------

ROUTE_CASES = {
    "express_inline": ("a.js", "app.get('/run', (req, res) => { x(req.query.c); });\n", "GET /run"),
    "express_router_post": (
        "a.js",
        "router.post('/admin/exec', (req, res) => { x(req.body.c); });\n",
        "POST /admin/exec",
    ),
    "express_named_handler": (
        "a.js",
        "function doThing(req, res){ x(req.query.c); }\napp.get('/run', doThing);\n",
        "GET /run",
    ),
    "fastapi_decorator": ("a.py", "@app.get('/items')\ndef items():\n    pass\n", "GET /items"),
    "spring_getmapping": (
        "A.java",
        'public class A { @GetMapping("/run") public void doThing() {} }\n',
        "GET /run",
    ),
    "spring_postmapping": (
        "A.java",
        'public class A { @PostMapping("/admin") public void adm() {} }\n',
        "POST /admin",
    ),
    "csharp_httpget": (
        "A.cs",
        'public class A { [HttpGet("/run")] public void DoThing() {} }\n',
        "GET /run",
    ),
    "gin_get": (
        "a.go",
        'package main\nfunc main(){ r.GET("/ping", ping) }\nfunc ping(c *gin.Context){}\n',
        "GET /ping",
    ),
}


@pytest.mark.parametrize("case", sorted(ROUTE_CASES))
def test_route_is_detected(case: str) -> None:
    filename, source, expected = ROUTE_CASES[case]
    assert expected in _routes(filename, source), f"{case}: got {_routes(filename, source)}"


def test_code_without_a_route_declares_none() -> None:
    """A plain helper must not acquire a route it does not have."""
    assert _routes("a.js", "function helper(req){ x(req.query.c); }\n") == []


# ---------------------------------------------------------------------------
# The ranking this exists to fix
# ---------------------------------------------------------------------------


def test_routed_endpoint_outranks_an_unrouted_helper() -> None:
    """Regression: the name heuristic ranked these the wrong way round.

    An unrouted helper scored 75 while a routed admin RCE scored 20, because the
    helper's labels contained a word on the heuristic list and the real endpoint's
    did not.
    """
    routed = _scan(
        "a.js",
        "const cp = require('child_process');\n"
        "router.post('/admin/exec', (req, res) => { cp.execSync(req.body.cmd); });\n",
    )
    unrouted = _scan(
        "a.js",
        "const cp = require('child_process');\n"
        "function helper(req){ cp.execSync(req.query.cmd); }\n",
    )
    assert routed and unrouted
    assert max(p["score"] for p in routed) > max(p["score"] for p in unrouted)


def test_finding_carries_the_url_to_test() -> None:
    paths = _scan(
        "a.js",
        "const cp = require('child_process');\n"
        "router.post('/admin/exec', (req, res) => { cp.execSync(req.body.cmd); });\n",
    )
    assert paths
    assert any("POST /admin/exec" in (p.get("routes") or []) for p in paths)


def test_routed_finding_is_marked_reachable() -> None:
    paths = _scan(
        "A.java",
        'public class A { @GetMapping("/run") public void d(HttpServletRequest req)'
        ' throws Exception { Runtime.getRuntime().exec(req.getParameter("c")); } }\n',
    )
    assert paths
    assert all(p["reachable"] for p in paths)


def test_route_is_attributed_through_the_enclosing_function() -> None:
    """The route sits on the handler, which is not on the data path itself.

    Declaration edges do not carry taint, so attribution walks the ownership
    relation instead. Flask's `request` is a module-level proxy with no
    declaration edge at all, and is attributed positionally.
    """
    paths = _scan(
        "a.py",
        "import os\n@app.route('/run')\ndef view():\n    os.system(request.args.get('c'))\n",
    )
    assert paths
    assert any(p.get("routes") for p in paths)


# ---------------------------------------------------------------------------
# Handler identity
# ---------------------------------------------------------------------------


def test_anonymous_handler_does_not_borrow_a_name_from_its_body() -> None:
    """Regression: an inline handler took the first identifier it used.

    `(req, res) => { cp.execSync(...) }` became a function named "cp", colliding
    with that variable and hiding the real handler from route attribution.
    """
    graph = _graph(
        "a.js",
        "const cp = require('child_process');\n"
        "router.post('/x', (req, res) => { cp.execSync(req.body.c); });\n",
    )
    functions = [
        n for n in graph["nodes"] if n["type"] == "Function" and not (n.get("metadata") or {}).get("synthetic")
    ]
    assert functions
    assert all(n["label"] != "cp" for n in functions), [n["label"] for n in functions]


def test_inline_handler_is_not_visited_twice() -> None:
    """A second, unrouted copy of the handler would swallow the taint path."""
    graph = _graph("a.js", "app.get('/x', (req, res) => { sink(req.query.c); });\n")
    routed = [n for n in graph["nodes"] if (n.get("metadata") or {}).get("route")]
    assert len(routed) == 1, [n["label"] for n in routed]
