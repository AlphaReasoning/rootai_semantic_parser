"""Cross-file taint: a source in one file reaching a sink declared in another.

This is the shape real applications take -- a route or controller reads input
and hands it to a service, DAO or helper in a different file. Per-file parsing
resolves calls only against declarations in the same file, so without the
cross-file pass the path stops at the file boundary.

Every case is paired with a control that passes a constant through the identical
call graph and must report nothing.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from rootai_semantic_parser.core.runtime import CrossFileCallResolver, MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig

#: language -> (vulnerable file set, control file set using a constant)
CASES: Dict[str, tuple] = {
    "javascript": (
        {
            "svc.js": "const cp = require('child_process');\n"
            "function runCommand(c) { cp.execSync(c); }\n"
            "module.exports = { runCommand };\n",
            "ctl.js": "const svc = require('./svc');\n"
            "function handler(req) { const cmd = req.query.c; svc.runCommand(cmd); }\n",
        },
        {
            "svc.js": "const cp = require('child_process');\n"
            "function runCommand(c) { cp.execSync(c); }\n",
            "ctl.js": "function handler() { const cmd = 'ls'; runCommand(cmd); }\n",
        },
    ),
    "java": (
        {
            "Svc.java": "public class Svc {\n"
            "  public void runCommand(String c) throws Exception { Runtime.getRuntime().exec(c); }\n"
            "}\n",
            "Ctl.java": "public class Ctl {\n"
            '  public void handler(HttpServletRequest req) throws Exception { String cmd = req.getParameter("c"); svc.runCommand(cmd); }\n'
            "}\n",
        },
        {
            "Svc.java": "public class Svc {\n"
            "  public void runCommand(String c) throws Exception { Runtime.getRuntime().exec(c); }\n"
            "}\n",
            "Ctl.java": "public class Ctl {\n"
            '  public void handler() throws Exception { String cmd = "ls"; svc.runCommand(cmd); }\n'
            "}\n",
        },
    ),
    "go": (
        {
            "svc.go": 'package main\nimport "os/exec"\nfunc runCommand(c string) { exec.Command(c).Run() }\n',
            "ctl.go": 'package main\nfunc handler(r *R) { cmd := r.FormValue("c"); runCommand(cmd) }\n',
        },
        {
            "svc.go": 'package main\nimport "os/exec"\nfunc runCommand(c string) { exec.Command(c).Run() }\n',
            "ctl.go": 'package main\nfunc handler() { cmd := "ls"; runCommand(cmd) }\n',
        },
    ),
    "kotlin": (
        {
            "Svc.kt": "fun runCommand(c: String) { Runtime.getRuntime().exec(c) }\n",
            "Ctl.kt": 'fun handler(req: Req) { val cmd = req.getParameter("c"); runCommand(cmd) }\n',
        },
        {
            "Svc.kt": "fun runCommand(c: String) { Runtime.getRuntime().exec(c) }\n",
            "Ctl.kt": 'fun handler() { val cmd = "ls"; runCommand(cmd) }\n',
        },
    ),
    "php": (
        {
            "svc.php": "<?php\nfunction runCommand($c) { system($c); }\n",
            "ctl.php": "<?php\nfunction handler() { $cmd = $_GET['c']; runCommand($cmd); }\n",
        },
        {
            "svc.php": "<?php\nfunction runCommand($c) { system($c); }\n",
            "ctl.php": "<?php\nfunction handler() { $cmd = 'ls'; runCommand($cmd); }\n",
        },
    ),
}

LANGUAGES = sorted(CASES)


def _scan(files: Dict[str, str]) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    for name, body in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


@pytest.mark.parametrize("language", LANGUAGES)
def test_taint_crosses_the_file_boundary(language: str) -> None:
    vulnerable, _ = CASES[language]
    paths = _scan(vulnerable)
    assert paths, f"{language}: source in one file did not reach the sink declared in another"


@pytest.mark.parametrize("language", LANGUAGES)
def test_constant_through_the_same_call_graph_is_not_reported(language: str) -> None:
    _, control = CASES[language]
    paths = _scan(control)
    assert paths == [], f"{language}: {[p['explanation'] for p in paths]}"


# ---------------------------------------------------------------------------
# Resolution policy
# ---------------------------------------------------------------------------


def _graph(files: Dict[str, str]) -> Dict:
    directory = Path(tempfile.mkdtemp())
    for name, body in files.items():
        (directory / name).write_text(body, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    return parser.get_graph()


def test_ambiguous_name_is_left_unresolved() -> None:
    """Two files declaring the same name must not be merged into one another.

    Resolving by name alone would make every caller of a common method reach
    every implementation of it, which is how a name-based resolver turns into a
    false-positive generator.
    """
    graph = _graph(
        {
            "a.js": "const cp = require('child_process');\nfunction handle(c) { cp.execSync(c); }\n",
            "b.js": "function handle(c) { return c; }\n",
            "c.js": "function caller(req) { const cmd = req.query.c; handle(cmd); }\n",
        }
    )
    cross_file = [
        e
        for e in graph["edges"]
        if (e.get("metadata") or {}).get("cross_file") and e["relation"] == "calls"
    ]
    assert cross_file == [], "an ambiguous name must not resolve"


def test_resolver_is_idempotent() -> None:
    """Running the pass twice must not duplicate edges."""
    graph = _graph(
        {
            "svc.js": "const cp = require('child_process');\nfunction runCommand(c) { cp.execSync(c); }\n",
            "ctl.js": "function handler(req) { const cmd = req.query.c; runCommand(cmd); }\n",
        }
    )
    before = len(graph["edges"])
    added = CrossFileCallResolver(graph).run()
    assert added == 0, "a second pass added edges the first should already have"
    assert len(graph["edges"]) == before


def test_cross_file_edges_are_marked_as_such() -> None:
    """Provenance matters: an operator should see which links were inferred."""
    graph = _graph(
        {
            "svc.js": "const cp = require('child_process');\nfunction runCommand(c) { cp.execSync(c); }\n",
            "ctl.js": "function handler(req) { const cmd = req.query.c; runCommand(cmd); }\n",
        }
    )
    inferred = [e for e in graph["edges"] if (e.get("metadata") or {}).get("cross_file")]
    assert inferred
    assert all((e.get("metadata") or {}).get("resolved") or "position" in (e.get("metadata") or {}) for e in inferred)
