"""Cross-file import resolution tests."""

from __future__ import annotations

from pathlib import Path

from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, EdgeRelation, SecurityConfig


def test_python_import_call_resolves_across_files(tmp_path: Path) -> None:
    """Resolve imported call targets to the declaring file."""
    (tmp_path / "a.py").write_text(
        "from b import sink\n\n"
        "def handler(request):\n"
        "    cmd = request.args.get('cmd')\n"
        "    return sink(cmd)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def sink(value):\n"
        "    return eval(value)\n",
        encoding="utf-8",
    )
    parser = MultiFileParser(
        str(tmp_path),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
        use_cache=False,
    )
    parser.parse_all()
    graph = parser.get_graph()
    sink_ids = {
        node["id"]
        for node in graph["nodes"]
        if node.get("label") == "sink" and str(node.get("file", "")).endswith("b.py")
    }
    assert sink_ids
    assert any(
        edge["relation"] == EdgeRelation.CALLS.value and edge["target"] in sink_ids
        for edge in graph["edges"]
    )
    assert graph["_resolution_stats"]["resolved"] >= 1
