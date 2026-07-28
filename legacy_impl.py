"""Compatibility facade for older imports."""

from __future__ import annotations

import os
import tempfile
import unittest

from analyzers import SSAVersionTracker, SymbolResolver, TaintAnalyzer
from cli import main
from core.runtime import CVEEnricher, GlobalDependencyResolver, GraphMerger, MultiFileParser, ParseCache
from models import (
    AnalysisOptions,
    BountyReport,
    Edge,
    EdgeRelation,
    GraphDiff,
    LogicClass,
    Node,
    NodeType,
    ScanReport,
    SecurityConfig,
    TaintConfig,
    TaintPath,
)
from parsers.engines import (
    LanguageParser,
    PythonParser,
    TreeSitterParser,
    resolve_tree_sitter_language,
    safe_unparse,
)
from parsers.generic_engine import (
    CSharpParser,
    GoParser,
    JavaParser,
    JavaScriptParser,
    PHPParser,
    RubyParser,
)
from reports.renderers import (
    GraphSnapshot,
    apply_baseline_and_suppressions,
    bounty_report_to_annotations,
    bounty_report_to_sarif,
    build_bounty_report,
    export_llm_context,
    render_bounty_output,
)
from reports.markdown import bounty_report_to_markdown_table
from version import __version__


def run_self_tests() -> int:
    """Run embedded smoke tests for the packaged parser."""

    class TestSemanticParser(unittest.TestCase):
        def setUp(self) -> None:
            self.temp_dir = tempfile.TemporaryDirectory()
            self.root = self.temp_dir.name

        def tearDown(self) -> None:
            self.temp_dir.cleanup()

        def test_ssa_versioning(self) -> None:
            tracker = SSAVersionTracker()
            self.assertEqual(tracker.get_versioned_id("data"), "data_v1")
            self.assertEqual(tracker.get_versioned_id("data"), "data_v2")

        def test_graph_diff(self) -> None:
            snap1 = GraphSnapshot({"node1": "hash1"}, {"edge1"})
            snap2 = GraphSnapshot({"node1": "hash1", "node2": "hash2"}, set())
            diff = snap1.diff(snap2)
            self.assertIn("node2", diff.added_nodes)

        def test_security_config(self) -> None:
            is_pii, logic = SecurityConfig.default_web().classify_node("get_user_email")
            self.assertTrue(is_pii)
            self.assertEqual(logic, LogicClass.READ)

        def test_end_to_end_taint_analysis(self) -> None:
            py_file = os.path.join(self.root, "app.py")
            with open(py_file, "w", encoding="utf-8") as handle:
                handle.write("import os\n" "def handle_request(request):\n" "    user_input = request.form.get('cmd')\n" "    os.system(user_input)\n")
            parser = MultiFileParser(self.root, security_config=SecurityConfig.default_web())
            report = parser.scan(taint_config=TaintConfig(sources={"request", "user_input"}, sinks={"os.system"}))
            self.assertGreaterEqual(report.taint_path_count, 1)

        def test_bugbounty_profile_report(self) -> None:
            py_file = os.path.join(self.root, "resolver.py")
            with open(py_file, "w", encoding="utf-8") as handle:
                handle.write("def graphql_resolver(args):\n    cmd = args.input\n    eval(cmd)\n")
            parser = MultiFileParser(self.root, security_config=SecurityConfig.default_bugbounty(), options=AnalysisOptions(profile="bugbounty", quick_mode=True))
            report = parser.scan(taint_config=TaintConfig.profile("bugbounty"))
            bounty = build_bounty_report(report, profile="bugbounty", quick_mode=True)
            self.assertGreaterEqual(len(bounty.findings), 1)

        def test_markdown_report_and_filters(self) -> None:
            py_file = os.path.join(self.root, "app.py")
            with open(py_file, "w", encoding="utf-8") as handle:
                handle.write("def fastapi_handler(request):\n    cmd = request.args\n    eval(cmd)\n")
            parser = MultiFileParser(self.root, security_config=SecurityConfig.default_bugbounty(), options=AnalysisOptions(profile="bugbounty", quick_mode=True, min_score=60.0, only_reachable_unsanitized=True))
            report = parser.scan(taint_config=TaintConfig.profile("bugbounty"))
            bounty = build_bounty_report(report, profile="bugbounty", quick_mode=True)
            markdown = bounty_report_to_markdown_table(bounty)
            self.assertIn("| Score | Confidence | Severity | Potential Impact |", markdown)

        def test_framework_entrypoint_patterns(self) -> None:
            fixtures = {
                "api.py": "@router.get('/users')\ndef list_users(request):\n    return request.args\n",
                "main.go": "package main\nfunc GinHandler(c *gin.Context) {\n helper()\n}\nfunc helper() {}\n",
                "UserController.java": "@RestController\nclass UserController { @GetMapping(\"/users\") public void listUsers() { helper(); } public void helper() {} }\n",
            }
            for name, content in fixtures.items():
                with open(os.path.join(self.root, name), "w", encoding="utf-8") as handle:
                    handle.write(content)
            parser = MultiFileParser(self.root, security_config=SecurityConfig.default_bugbounty())
            parser.parse_all()
            graph = parser.get_graph()
            flagged = {node["label"] for node in graph["nodes"] if node.get("metadata", {}).get("entrypoint")}
            self.assertIn("list_users", flagged)
            self.assertIn("GinHandler", flagged)
            self.assertIn("listUsers", flagged)

    print(f"Running Enterprise Internal Security tests (v{__version__})...")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSemanticParser)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


__all__ = [
    "AnalysisOptions",
    "BountyReport",
    "CSharpParser",
    "CVEEnricher",
    "Edge",
    "EdgeRelation",
    "GlobalDependencyResolver",
    "GraphDiff",
    "GraphMerger",
    "GraphSnapshot",
    "LanguageParser",
    "LogicClass",
    "MultiFileParser",
    "Node",
    "NodeType",
    "ParseCache",
    "PHPParser",
    "PythonParser",
    "RubyParser",
    "ScanReport",
    "SecurityConfig",
    "SSAVersionTracker",
    "SymbolResolver",
    "TaintAnalyzer",
    "TaintConfig",
    "TaintPath",
    "TreeSitterParser",
    "__version__",
    "apply_baseline_and_suppressions",
    "bounty_report_to_annotations",
    "bounty_report_to_markdown_table",
    "bounty_report_to_sarif",
    "build_bounty_report",
    "export_llm_context",
    "main",
    "render_bounty_output",
    "resolve_tree_sitter_language",
    "run_self_tests",
    "safe_unparse",
]
