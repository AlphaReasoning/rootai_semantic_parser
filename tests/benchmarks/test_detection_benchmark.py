"""Detection benchmark: labelled vulnerabilities with expected outcomes.

Everything else in the suite asserts a single behaviour. This measures the two
numbers that decide whether the tool is useful -- how many real vulnerabilities
it finds, and how often it reports code that is fine -- and fails when either
moves the wrong way.

The corpus is deliberately small and checked in, so it runs in CI without
network access. Each case is a complete miniature application: several files,
realistic structure, and a stated expectation. ``EXPECTED_RECALL`` and
``MAX_FALSE_POSITIVES`` are the contract; raising recall means lowering neither.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig

#: name -> (files, should_be_detected, description)
CORPUS: List[Tuple[str, Dict[str, str], bool, str]] = [
    (
        "js_command_injection_cross_file",
        {
            "routes/handler.js": "const svc = require('../services/shell');\n"
            "function handleRun(req, res) {\n"
            "  const target = req.query.target;\n"
            "  svc.runDiagnostic(target);\n"
            "}\n",
            "services/shell.js": "const cp = require('child_process');\n"
            "function runDiagnostic(host) { cp.execSync('ping ' + host); }\n"
            "module.exports = { runDiagnostic };\n",
        },
        True,
        "req.query reaches execSync through a service in another file",
    ),
    (
        "js_command_injection_constant",
        {
            "routes/handler.js": "const svc = require('../services/shell');\n"
            "function handleRun(req, res) {\n"
            "  const target = 'localhost';\n"
            "  svc.runDiagnostic(target);\n"
            "}\n",
            "services/shell.js": "const cp = require('child_process');\n"
            "function runDiagnostic(host) { cp.execSync('ping ' + host); }\n",
        },
        False,
        "same call graph, constant host",
    ),
    (
        "python_sql_via_helper",
        {
            "app.py": "from db import lookup\n"
            "def view(request):\n"
            "    name = request.args.get('name')\n"
            "    return lookup(name)\n",
            "db.py": "import sqlite3\n"
            "def lookup(name):\n"
            "    cur = sqlite3.connect('x').cursor()\n"
            "    return cur.execute('SELECT * FROM u WHERE n=' + name)\n",
        },
        True,
        "request parameter reaches cursor.execute in another module",
    ),
    (
        "python_sql_constant",
        {
            "app.py": "from db import lookup\n"
            "def view():\n"
            "    name = 'admin'\n"
            "    return lookup(name)\n",
            "db.py": "import sqlite3\n"
            "def lookup(name):\n"
            "    cur = sqlite3.connect('x').cursor()\n"
            "    return cur.execute('SELECT * FROM u WHERE n=' + name)\n",
        },
        False,
        "same call graph, constant name",
    ),
    (
        "c_buffer_overflow",
        {
            "net.c": "int start(void) {\n"
            '    char *name = getenv("SERVER_NAME");\n'
            "    char buf[64];\n"
            "    strcpy(buf, name);\n"
            "    system(buf);\n"
            "    return 0;\n"
            "}\n",
        },
        True,
        "getenv reaches strcpy and system",
    ),
    (
        "c_bounded_copy",
        {
            "net.c": "int start(void) {\n"
            "    char buf[64];\n"
            '    strncpy(buf, "localhost", 63);\n'
            "    system(buf);\n"
            "    return 0;\n"
            "}\n",
        },
        False,
        "bounded copy of a constant",
    ),
    (
        "java_command_injection",
        {
            "Controller.java": "public class Controller {\n"
            "  public void run(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
            '    String host = req.getParameter("host");\n'
            "    Shell.ping(host);\n"
            "  }\n"
            "}\n",
            "Shell.java": "public class Shell {\n"
            "  public static void ping(String host) throws Exception { Runtime.getRuntime().exec(host); }\n"
            "}\n",
        },
        True,
        "servlet parameter reaches Runtime.exec across files",
    ),
    (
        "go_ssrf",
        {
            "handler.go": 'package main\nfunc handle(r *Request) { target := r.FormValue("url"); fetchURL(target) }\n',
            "client.go": 'package main\nimport "net/http"\nfunc fetchURL(u string) { http.Get(u) }\n',
        },
        True,
        "form value reaches http.Get across files",
    ),
    (
        "php_command_injection",
        {
            "index.php": "<?php\nrequire 'lib.php';\nfunction main() { $h = $_GET['host']; ping($h); }\n",
            "lib.php": "<?php\nfunction ping($h) { system('ping ' . $h); }\n",
        },
        True,
        "$_GET reaches system across files",
    ),
    (
        "clean_application",
        {
            "app.py": "import os\n"
            "def handler(request):\n"
            "    name = request.args.get('name')\n"
            "    if name not in ALLOWED:\n"
            "        return 'no'\n"
            "    return render(name)\n"
            "def render(value):\n"
            "    return value.upper()\n"
            "ALLOWED = {'a', 'b'}\n",
            "util.py": "def helper(x):\n    return x.strip()\n",
        },
        False,
        "input is used but never reaches a sink",
    ),
]

#: Contract. Lower these only with a deliberate, stated reason.
EXPECTED_RECALL = 1.0
MAX_FALSE_POSITIVES = 0


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


@pytest.mark.parametrize(
    ("name", "files", "should_detect", "description"),
    CORPUS,
    ids=[case[0] for case in CORPUS],
)
def test_benchmark_case(name: str, files: Dict[str, str], should_detect: bool, description: str) -> None:
    paths = _scan(files)
    if should_detect:
        assert paths, f"{name}: missed -- {description}"
    else:
        assert paths == [], f"{name}: false positive -- {description}: {[p['explanation'] for p in paths]}"


def test_benchmark_recall_and_precision() -> None:
    """Aggregate scorecard, so a regression in either direction is visible."""
    vulnerable = [c for c in CORPUS if c[2]]
    clean = [c for c in CORPUS if not c[2]]

    detected = sum(1 for _, files, _, _ in vulnerable if _scan(files))
    false_positives = sum(1 for _, files, _, _ in clean if _scan(files))

    recall = detected / len(vulnerable)
    assert recall >= EXPECTED_RECALL, (
        f"recall {recall:.0%} ({detected}/{len(vulnerable)}) below the {EXPECTED_RECALL:.0%} contract"
    )
    assert false_positives <= MAX_FALSE_POSITIVES, (
        f"{false_positives} false positive(s) across {len(clean)} clean cases"
    )
