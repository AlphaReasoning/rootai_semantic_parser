"""Taint through object fields, containers, and loop bindings.

Assignment used to mean one thing: a bare name on the left. Everything else --
``self.cmd = ...``, ``opts['k'] = ...``, ``args.add(...)``, ``for row in ...``
-- produced no target, so the flow ended there silently.

That is not an edge case. Storing request data on the instance in one method
and using it in another is how MVC controllers are written, in Spring, Rails,
ASP.NET and Django alike; building a list or map from request data and handing
it to a sink is how command arguments are assembled. Each shape below was
measured as a miss before the change.
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
# Fields: written in one method, used in another
# ---------------------------------------------------------------------------

FIELD_CASES = {
    "python_self_attribute": (
        "a.py",
        "import os\n"
        "class Handler:\n"
        "    def receive(self, request):\n"
        "        self.cmd = request.args.get('c')\n"
        "    def run(self):\n"
        "        os.system(self.cmd)\n",
    ),
    "java_declared_field": (
        "A.java",
        "public class A {\n"
        "    String cmd;\n"
        "    public void receive(HttpServletRequest req) { cmd = req.getParameter(\"c\"); }\n"
        "    public void run() throws Exception { Runtime.getRuntime().exec(cmd); }\n"
        "}\n",
    ),
    "javascript_this_property": (
        "a.js",
        "const cp = require('child_process');\n"
        "class H {\n"
        "  receive(req) { this.cmd = req.query.c; }\n"
        "  run() { cp.execSync(this.cmd); }\n"
        "}\n",
    ),
}


@pytest.mark.parametrize("case", sorted(FIELD_CASES))
def test_field_carries_taint_between_methods(case: str) -> None:
    filename, source = FIELD_CASES[case]
    assert _scan(filename, source), f"{case}: field write was not connected to the field read"


def test_a_constant_field_is_not_a_source() -> None:
    """The control. Recognising the write must not taint every field."""
    assert not _scan(
        "a.py",
        "import os\n"
        "class Handler:\n"
        "    def receive(self):\n"
        "        self.cmd = 'ls -la'\n"
        "    def run(self):\n"
        "        os.system(self.cmd)\n",
    )


# ---------------------------------------------------------------------------
# Containers: written into, then read back
# ---------------------------------------------------------------------------

CONTAINER_CASES = {
    "python_subscript_write": (
        "a.py",
        "import os\n"
        "def view(request):\n"
        "    opts = {}\n"
        "    opts['cmd'] = request.args.get('c')\n"
        "    os.system(opts['cmd'])\n",
    ),
    "javascript_array_push": (
        "a.js",
        "const cp = require('child_process');\n"
        "app.post('/x', (req, res) => {\n"
        "  const args = [];\n"
        "  args.push(req.body.c);\n"
        "  cp.execSync(args[0]);\n"
        "});\n",
    ),
    "java_collection_add": (
        "A.java",
        "public class A {\n"
        "  public void run(HttpServletRequest req) throws Exception {\n"
        "    java.util.List<String> args = new java.util.ArrayList<String>();\n"
        "    args.add(req.getParameter(\"c\"));\n"
        "    Runtime.getRuntime().exec(args.get(0));\n"
        "  }\n"
        "}\n",
    ),
}


@pytest.mark.parametrize("case", sorted(CONTAINER_CASES))
def test_container_carries_taint_to_the_sink(case: str) -> None:
    filename, source = CONTAINER_CASES[case]
    assert _scan(filename, source), f"{case}: value written into the container did not reach the sink"


def test_container_taint_is_not_key_sensitive() -> None:
    """Documented over-approximation, asserted so it stays a decision.

    ``opts['bad'] = tainted`` taints ``opts``, so ``opts['good']`` reports too.
    Telling the keys apart needs constant propagation, which this engine does
    not do; over-reporting is the safer direction, but it is a real cost and
    should fail loudly if someone later assumes precision that is not here.
    """
    assert _scan(
        "a.py",
        "import os\n"
        "def view(request):\n"
        "    opts = {}\n"
        "    opts['bad'] = request.args.get('c')\n"
        "    opts['good'] = 'ls'\n"
        "    os.system(opts['good'])\n",
    )


def test_a_constant_container_is_not_a_source() -> None:
    assert not _scan(
        "a.py",
        "import os\n"
        "def view():\n"
        "    opts = {}\n"
        "    opts['cmd'] = 'ls -la'\n"
        "    os.system(opts['cmd'])\n",
    )


# ---------------------------------------------------------------------------
# Loop bindings
# ---------------------------------------------------------------------------


def test_loop_variable_carries_taint_from_the_iterable() -> None:
    """`for x in request...` is an assignment in all but keyword."""
    assert _scan(
        "a.py",
        "import os\n"
        "def view(request):\n"
        "    for item in request.args.getlist('c'):\n"
        "        os.system(item)\n",
    )


def test_loop_over_a_constant_is_not_a_source() -> None:
    assert not _scan(
        "a.py",
        "import os\ndef view():\n    for item in ['ls', 'pwd']:\n        os.system(item)\n",
    )


def test_tuple_unpacking_binds_every_name() -> None:
    assert _scan(
        "a.py",
        "import os\ndef view(request):\n    a, b = request.args.get('c'), 'safe'\n    os.system(a)\n",
    )
