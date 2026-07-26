"""Language coverage: the same vulnerability, expressed in every claimed language.

Each language appears twice -- once with attacker-controlled input reaching a
command sink, once with a constant in the same position. A language only counts
as supported when it passes both: detection alone can be achieved by reporting
everything.

These tests are the evidence behind the "polyglot" claim in the README. Adding a
language to that claim means adding it here first.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig
from rootai_semantic_parser.parsers.registry import iter_parser_classes

#: language -> (filename, vulnerable source, safe source using a constant)
CASES: Dict[str, Tuple[str, str, str]] = {
    "python": (
        "a.py",
        "import os\n"
        "def handler(request):\n"
        "    cmd = request.args.get('c')\n"
        "    os.system(cmd)\n",
        "import os\n"
        "def handler():\n"
        "    cmd = 'ls -la'\n"
        "    os.system(cmd)\n",
    ),
    "javascript": (
        "a.js",
        "const cp = require('child_process');\n"
        "function handler(req) {\n"
        "  const cmd = req.query.c;\n"
        "  cp.execSync(cmd);\n"
        "}\n",
        "const cp = require('child_process');\n"
        "function handler() {\n"
        "  const cmd = 'ls -la';\n"
        "  cp.execSync(cmd);\n"
        "}\n",
    ),
    "typescript": (
        "a.ts",
        "import { execSync } from 'child_process';\n"
        "function handler(req: any) {\n"
        "  const cmd = req.query.c;\n"
        "  execSync(cmd);\n"
        "}\n",
        "import { execSync } from 'child_process';\n"
        "function handler() {\n"
        "  const cmd = 'ls -la';\n"
        "  execSync(cmd);\n"
        "}\n",
    ),
    "go": (
        "a.go",
        'package main\n'
        'import "os/exec"\n'
        "func handler(r *R) {\n"
        '  cmd := r.FormValue("c")\n'
        "  exec.Command(cmd).Run()\n"
        "}\n",
        'package main\n'
        'import "os/exec"\n'
        "func handler() {\n"
        '  cmd := "ls"\n'
        "  exec.Command(cmd).Run()\n"
        "}\n",
    ),
    "java": (
        "A.java",
        "public class A {\n"
        "  public void handler(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
        '    String cmd = req.getParameter("c");\n'
        "    Runtime.getRuntime().exec(cmd);\n"
        "  }\n"
        "}\n",
        "public class A {\n"
        "  public void handler() throws Exception {\n"
        '    String cmd = "ls";\n'
        "    Runtime.getRuntime().exec(cmd);\n"
        "  }\n"
        "}\n",
    ),
    "csharp": (
        "A.cs",
        "public class A {\n"
        "  public void Handler(HttpRequest Request) {\n"
        '    string cmd = Request.Query["c"];\n'
        "    System.Diagnostics.Process.Start(cmd);\n"
        "  }\n"
        "}\n",
        "public class A {\n"
        "  public void Handler() {\n"
        '    string cmd = "ls";\n'
        "    System.Diagnostics.Process.Start(cmd);\n"
        "  }\n"
        "}\n",
    ),
    "php": (
        "a.php",
        "<?php\n"
        "function handler() {\n"
        "  $cmd = $_GET['c'];\n"
        "  system($cmd);\n"
        "}\n",
        "<?php\n"
        "function handler() {\n"
        "  $cmd = 'ls -la';\n"
        "  system($cmd);\n"
        "}\n",
    ),
    "ruby": (
        "a.rb",
        "def handler(params)\n"
        "  cmd = params[:c]\n"
        "  system(cmd)\n"
        "end\n",
        "def handler\n"
        "  cmd = 'ls -la'\n"
        "  system(cmd)\n"
        "end\n",
    ),
    "rust": (
        "src/lib.rs",
        "use std::env;\n"
        "use std::process::Command;\n"
        "pub fn handler() {\n"
        '    let cmd = env::var("C").unwrap_or_default();\n'
        "    let out = Command::new(&cmd).output();\n"
        "}\n",
        "use std::process::Command;\n"
        "pub fn handler() {\n"
        '    let cmd = "ls".to_string();\n'
        "    let out = Command::new(&cmd).output();\n"
        "}\n",
    ),
    "c": (
        "a.c",
        "int handler(void) {\n"
        '    char *cmd = getenv("C");\n'
        "    system(cmd);\n"
        "    return 0;\n"
        "}\n",
        "int handler(void) {\n"
        "    char buf[8];\n"
        '    strncpy(buf, "ls", 7);\n'
        "    system(buf);\n"
        "    return 0;\n"
        "}\n",
    ),
}

LANGUAGES = sorted(CASES)


def _scan(filename: str, source: str) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    target = directory / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    if filename.endswith(".rs"):
        (directory / "Cargo.toml").write_text('[package]\nname = "x"\n', encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


@pytest.mark.parametrize("language", LANGUAGES)
def test_command_injection_is_detected(language: str) -> None:
    filename, vulnerable, _ = CASES[language]
    paths = _scan(filename, vulnerable)
    assert paths, f"{language}: attacker-controlled input reaching a command sink was not detected"


@pytest.mark.parametrize("language", LANGUAGES)
def test_constant_in_the_same_position_is_not_reported(language: str) -> None:
    """Without this, "detected" above could just mean "reports everything"."""
    filename, _, safe = CASES[language]
    paths = _scan(filename, safe)
    assert paths == [], f"{language}: {[p['explanation'] for p in paths]}"


@pytest.mark.parametrize("language", LANGUAGES)
def test_parser_emits_dataflow_edges(language: str) -> None:
    """Name-level structure is not enough; taint needs value-carrying edges.

    The previous regex parsers emitted a module node, a function node and
    nothing else, which is why no library sink was ever reachable.
    """
    filename, vulnerable, _ = CASES[language]
    directory = Path(tempfile.mkdtemp())
    target = directory / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(vulnerable, encoding="utf-8")
    if filename.endswith(".rs"):
        (directory / "Cargo.toml").write_text('[package]\nname = "x"\n', encoding="utf-8")

    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    graph = parser.get_graph()

    dataflow = [e for e in graph["edges"] if e["relation"] == "dataflow"]
    assert dataflow, f"{language}: parser produced no dataflow edges"
    assert len(graph["nodes"]) > 2, f"{language}: only {len(graph['nodes'])} nodes"


@pytest.mark.parametrize("language", LANGUAGES)
def test_language_is_reachable_through_the_registry(language: str) -> None:
    filename, _, _ = CASES[language]
    claimed = [
        cls for cls in iter_parser_classes() if cls.supports(f"whatever/{Path(filename).name}")
    ]
    assert claimed, f"{language}: no registered parser claims {filename}"


def test_every_registered_parser_uses_a_real_grammar() -> None:
    """No parser may fall back to regex scanning.

    Python uses the stdlib ast module; every other parser must be tree-sitter
    backed, which is what distinguishes semantic parsing from name matching.
    """
    from rootai_semantic_parser.parsers.engines import PythonParser, TreeSitterParser

    for parser_cls in iter_parser_classes():
        if parser_cls is PythonParser or parser_cls.__name__ == "PythonParser":
            continue
        if not hasattr(parser_cls, "supports"):
            continue
        assert issubclass(parser_cls, TreeSitterParser), parser_cls.__name__
