"""CLI wrapper around the modular parser implementation."""

from __future__ import annotations

import sys

import argparse
import json
import logging
from typing import List, Optional, Set

from config import SUPPORTED_PROFILES, load_finding_profile, load_ruleset
from core.runtime import CVEEnricher, MultiFileParser, changed_files_between_commits
from evaluation import evaluate_graph_queries, load_evaluation_cases
from feedback import FeedbackEntry, apply_feedback_scores, feedback_stats, load_feedback_db, record_feedback, tune_rules
from graph_queries import GraphQueryError, GraphQueryEngine, render_query_text
from models import AnalysisOptions, FindingProfile, SecurityConfig, TaintConfig, formal_ir_spec
from plugins.loader import load_plugin_modules
from reports import (
    GraphSnapshot,
    apply_baseline_and_suppressions,
    build_bounty_report,
    bounty_report_to_submission_markdown,
    bounty_report_to_web_ui,
    export_llm_context,
    generate_poc_hints,
    render_bounty_output,
)
from version import __version__

log = logging.getLogger(__name__)


def _load_suppressions(path: Optional[str]) -> Set[str]:
    """Load suppression fingerprints."""
    if not path:
        return set()
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, list):
        return {str(item) for item in raw}
    return {str(item) for item in raw.get("suppressions", [])}


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="semantic_parser",
        description=f"Semantic Graph Parser v{__version__} Enterprise -- Polyglot Security Platform",
    )
    parser.add_argument("root", nargs="?", help="Source tree root directory")
    parser.add_argument("--config", metavar="FILE", help="SecurityConfig JSON file")
    parser.add_argument("--exclude", metavar="GLOBS", help="Comma-separated glob patterns to exclude")
    parser.add_argument("--profile", choices=list(SUPPORTED_PROFILES), default="default")
    parser.add_argument("--profile-file", help="Custom finding-profile JSON file")
    parser.add_argument("--quick-mode", action="store_true", help="Skip full SSA and use lighter taint/callgraph analysis")
    parser.add_argument("--no-cache", action="store_true", help="Disable on-disk parse cache")
    parser.add_argument("--no-reachability", action="store_true", help="Disable exposed-sink reachability heuristics")
    parser.add_argument("--no-auth-checks", action="store_true", help="Disable auth-guard heuristics")
    parser.add_argument("--min-score", type=float, default=None, help="Filter findings below this score")
    parser.add_argument("--only-unsanitized-reachable", action="store_true", help="Keep only findings that are both reachable and unsanitized")
    parser.add_argument("--plugin", action="append", default=[], help="Import a plugin module that registers extra parsers")
    parser.add_argument("--ruleset", help="Custom ruleset JSON to merge onto the active profile")
    parser.add_argument("--suppressions", help="Suppression fingerprint JSON")
    parser.add_argument("--baseline", help="Baseline bounty-report JSON to suppress known findings")
    parser.add_argument("--feedback-db", help="Feedback database JSON for adaptive scoring")

    sub = parser.add_subparsers(dest="command", required=False)
    scan_parser = sub.add_parser("scan", help="Full scan: parse + resolve + taint + report")
    scan_parser.add_argument("--format", choices=["json", "text", "markdown", "bounty-json", "bounty-html", "bounty-markdown", "sarif", "github-annotations", "gitlab-annotations", "bitbucket-annotations"], default="text")
    scan_parser.add_argument("--cve-feed", metavar="FILE", help="CVE feed JSON for enrichment")
    scan_parser.add_argument("--dependencies", metavar="FILES", help="Comma-separated list of external GraphSnapshot JSONs")
    scan_parser.add_argument("--out", help="Write report to file instead of stdout")

    export_parser = sub.add_parser("export", help="Export LLM context Markdown")
    export_parser.add_argument("--tokens", type=int, default=4000)
    export_parser.add_argument("--out", help="Write to file instead of stdout")

    bounty_parser = sub.add_parser("bounty-report", help="Emit a hunter-focused ranked taint report")
    bounty_parser.add_argument("--html", action="store_true")
    bounty_parser.add_argument("--markdown", action="store_true")
    bounty_parser.add_argument("--sarif", action="store_true")
    bounty_parser.add_argument("--out", help="Write report to file instead of stdout")

    ci_parser = sub.add_parser("ci-scan", help="CI-friendly scan mode with baselines and suppressions")
    ci_parser.add_argument("--format", choices=["sarif", "github-annotations", "gitlab-annotations", "bitbucket-annotations", "bounty-json"], default="sarif")
    ci_parser.add_argument("--out", help="Write report to file instead of stdout")

    changed_parser = sub.add_parser("what-changed", help="Analyze only files changed between two git commits")
    changed_parser.add_argument("commit_a")
    changed_parser.add_argument("commit_b")
    changed_parser.add_argument("--format", choices=["bounty-json", "bounty-markdown", "sarif"], default="bounty-json")
    changed_parser.add_argument("--out", help="Write report to file instead of stdout")

    submit_parser = sub.add_parser("submit-report", help="Export a HackerOne or Bugcrowd submission draft")
    submit_parser.add_argument("--platform", choices=["HackerOne", "Bugcrowd"], default="HackerOne")
    submit_parser.add_argument("--collaborator", default="")
    submit_parser.add_argument("--out", help="Write report to file instead of stdout")

    poc_parser = sub.add_parser("poc", help="Generate curl/Burp/Collaborator helpers for top findings")
    poc_parser.add_argument("--collaborator", default="")
    poc_parser.add_argument("--out", help="Write report to file instead of stdout")

    explain_parser = sub.add_parser(
        "explain",
        help="Emit confirmation-ready evidence bundles for downstream tools/AI",
    )
    explain_parser.add_argument("--out", help="Write report to file instead of stdout")
    explain_parser.add_argument("--limit", type=int, default=50, help="Max findings to bundle")

    web_parser = sub.add_parser("web-ui", help="Render a standalone interactive web UI HTML report")
    web_parser.add_argument("--out", help="Write report to file instead of stdout")

    cloud_parser = sub.add_parser("cloud-mode", help="Produce a cloud-native scan bundle manifest")
    cloud_parser.add_argument("--out", help="Write manifest to file instead of stdout")

    feedback_add = sub.add_parser("feedback-add", help="Record analyst feedback for adaptive scoring")
    feedback_add.add_argument("--fingerprint", required=True)
    feedback_add.add_argument("--verdict", choices=["true_positive", "false_positive", "needs_review"], required=True)
    feedback_add.add_argument("--impact", default="")
    feedback_add.add_argument("--sink", default="")
    feedback_add.add_argument("--notes", default="")

    sub.add_parser("feedback-stats", help="Show feedback database summary")
    sub.add_parser("feedback-tune", help="Emit rule tuning recommendations from feedback")

    snapshot_parser = sub.add_parser("snapshot", help="Save full topological GraphSnapshot")
    snapshot_parser.add_argument("--out", required=True)

    diff_parser = sub.add_parser("diff", help="Diff two snapshots")
    diff_parser.add_argument("snap_a")
    diff_parser.add_argument("snap_b")

    query_parser = sub.add_parser("query", help="Run deterministic graph query DSL")
    query_parser.add_argument("--expr", required=True, help='Query expression, e.g. "path source=request target=eval relations=dataflow,calls"')
    query_parser.add_argument("--snapshot", help="Read graph from GraphSnapshot JSON instead of parsing root")
    query_parser.add_argument("--format", choices=["json", "text"], default="json")
    query_parser.add_argument("--out", help="Write query result to file instead of stdout")

    eval_parser = sub.add_parser("evaluate", help="Evaluate deterministic graph queries against gold cases")
    eval_parser.add_argument("--cases", required=True, help="Evaluation cases JSON")
    eval_parser.add_argument("--snapshot", help="Read graph from GraphSnapshot JSON instead of parsing root")
    eval_parser.add_argument("--out", help="Write evaluation report JSON to file instead of stdout")

    sub.add_parser("ir-spec", help="Emit formal machine-readable IR specification")
    sub.add_parser("init-project", help="Emit pyproject.toml skeleton")
    sub.add_parser("info", help="Show parser backend configuration")
    sub.add_parser("self-test", help="Run embedded unit tests")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint.

    Domain errors are reported as a message on stderr rather than a traceback.
    A bad query expression or an unreadable config file is a usage problem, not
    a crash, and a stack trace tells the operator nothing actionable.
    """
    try:
        return _main(argv)
    except GraphQueryError as exc:
        print(f"query error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"file not found: {exc.filename or exc}", file=sys.stderr)
        return 2
    except IsADirectoryError as exc:
        print(f"expected a file: {exc.filename or exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"permission denied: {exc.filename or exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"invalid JSON: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


def _main(argv: Optional[List[str]] = None) -> int:
    cli = _build_cli()
    args = cli.parse_args(argv)

    if getattr(args, "plugin", None):
        load_plugin_modules(args.plugin)

    if args.command == "self-test":
        from legacy_impl import run_self_tests

        return run_self_tests()
    if args.command == "feedback-add":
        if not args.feedback_db:
            cli.error("--feedback-db is required for feedback-add")
        record_feedback(
            args.feedback_db,
            FeedbackEntry(
                fingerprint=args.fingerprint,
                verdict=args.verdict,
                impact=args.impact,
                sink=args.sink,
                notes=args.notes,
            ),
        )
        print(f"Recorded feedback for {args.fingerprint}")
        return 0
    if args.command == "feedback-stats":
        if not args.feedback_db:
            cli.error("--feedback-db is required for feedback-stats")
        print(json.dumps(feedback_stats(load_feedback_db(args.feedback_db)), indent=2))
        return 0
    if args.command == "feedback-tune":
        if not args.feedback_db:
            cli.error("--feedback-db is required for feedback-tune")
        print(json.dumps(tune_rules(load_feedback_db(args.feedback_db)), indent=2))
        return 0
    if args.command == "ir-spec":
        print(json.dumps(formal_ir_spec(), indent=2))
        return 0
    if args.command == "init-project":
        from pathlib import Path

        print(Path("/home/alphareasoning/rootai_semantic_parser/pyproject.toml").read_text(encoding="utf-8"))
        return 0
    profile_def = load_finding_profile(args.profile_file) if args.profile_file else FindingProfile.built_in(args.profile)

    if args.command == "info":
        print(f"Semantic Graph Parser v{__version__} (Enterprise Edition)")
        print(f"  SSA Engine           : {'Quick mode enabled' if args.quick_mode else 'Enabled (Python AST)'}")
        print("  Extra languages      : Java, PHP, Ruby, C#")
        print(f"  Active profile       : {profile_def.name}")
        return 0

    no_root_commands = {"diff", "ir-spec"}
    if not args.root and args.command not in no_root_commands and not getattr(args, "snapshot", None):
        cli.print_help()
        return 1

    if args.config:
        sec_cfg = SecurityConfig.from_file(args.config)
    elif args.profile == "bugbounty":
        sec_cfg = SecurityConfig.default_bugbounty()
    elif args.profile == "human-only":
        sec_cfg = SecurityConfig.default_human_only()
    else:
        sec_cfg = SecurityConfig.default_web()

    taint_cfg = sec_cfg.to_taint_config() if args.config else TaintConfig.profile(args.profile)
    if args.ruleset:
        taint_cfg = load_ruleset(args.ruleset, taint_cfg)
    effective_min_score = args.min_score if args.min_score is not None else profile_def.min_score
    options = AnalysisOptions(
        quick_mode=args.quick_mode,
        profile=args.profile,
        enable_reachability=not args.no_reachability,
        enable_auth_checks=not args.no_auth_checks,
        min_score=effective_min_score,
        only_reachable_unsanitized=args.only_unsanitized_reachable,
    )
    excludes = [p.strip() for p in args.exclude.split(",")] if args.exclude else None
    parser = MultiFileParser(args.root, security_config=sec_cfg, exclude_patterns=excludes, options=options, use_cache=not args.no_cache) if args.root else None

    def _graph_for_command() -> dict:
        if getattr(args, "snapshot", None):
            snap = GraphSnapshot.load(args.snapshot)
            return snap.full_graph
        parser.parse_all()
        return parser.get_graph()

    if args.command in {"scan", "bounty-report", "ci-scan", "submit-report", "poc", "web-ui", "explain"}:
        cve_enricher = CVEEnricher.from_feed(args.cve_feed) if getattr(args, "cve_feed", None) else None
        external_graphs = []
        if getattr(args, "dependencies", None):
            for path in args.dependencies.split(","):
                snap = GraphSnapshot.load(path.strip())
                if snap.full_graph:
                    external_graphs.append(snap.full_graph)
        report = parser.scan(taint_config=taint_cfg, cve_enricher=cve_enricher, external_graphs=external_graphs)
        bounty = build_bounty_report(report, profile=profile_def, quick_mode=args.quick_mode)
        baseline_report = None
        if args.baseline:
            with open(args.baseline, encoding="utf-8") as handle:
                raw = json.load(handle)
            from models import BountyReport

            baseline_report = BountyReport(**raw)
        bounty = apply_baseline_and_suppressions(bounty, baseline=baseline_report, suppressions=_load_suppressions(args.suppressions))
        if args.feedback_db:
            bounty = apply_feedback_scores(bounty, load_feedback_db(args.feedback_db))

        if args.command == "scan":
            if args.format == "json":
                output = report.to_json()
            elif args.format == "text":
                output = report.to_text()
            elif args.format == "markdown":
                output = export_llm_context(report.graph, report.taint_paths)
            else:
                output = render_bounty_output(bounty, args.format)
        elif args.command == "ci-scan":
            output = render_bounty_output(bounty, args.format)
        elif args.command == "submit-report":
            output = bounty_report_to_submission_markdown(bounty, args.platform, collaborator_base=args.collaborator)
        elif args.command == "explain":
            from analyzers.evidence import build_evidence_report

            output = json.dumps(
                build_evidence_report(bounty.findings, limit=args.limit), indent=2
            )
        elif args.command == "poc":
            output = json.dumps([generate_poc_hints(finding, collaborator_base=args.collaborator) for finding in bounty.findings[:10]], indent=2)
        elif args.command == "web-ui":
            output = bounty_report_to_web_ui(bounty)
        else:
            if args.html:
                output = render_bounty_output(bounty, "bounty-html")
            elif args.markdown:
                output = render_bounty_output(bounty, "bounty-markdown")
            elif args.sarif:
                output = render_bounty_output(bounty, "sarif")
            else:
                output = bounty.to_json()
        if getattr(args, "out", None):
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output)
        return 0

    if args.command == "what-changed":
        changed = changed_files_between_commits(args.root, args.commit_a, args.commit_b)
        parser.parse_changed_files(changed)
        report = parser.scan(taint_config=taint_cfg)
        bounty = build_bounty_report(report, profile=profile_def, quick_mode=args.quick_mode)
        output = render_bounty_output(bounty, args.format)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output)
        return 0

    if args.command == "query":
        graph = _graph_for_command()
        result = GraphQueryEngine(graph).execute(args.expr)
        output = json.dumps(result, indent=2) if args.format == "json" else render_query_text(result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output)
        return 0

    if args.command == "evaluate":
        graph = _graph_for_command()
        report = evaluate_graph_queries(graph, load_evaluation_cases(args.cases))
        output = report.to_json()
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output)
        return 0

    if args.command == "cloud-mode":
        manifest = {
            "mode": "cloud-native",
            "target": args.root,
            "goal_seconds": 30,
            "quick_mode": True,
            "parallel": True,
            "incremental": True,
            "report_formats": ["bounty-json", "sarif", "bounty-html"],
        }
        output = json.dumps(manifest, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            print(output)
        return 0

    if args.command == "export":
        parser.parse_all()
        graph = parser.get_graph()
        print(export_llm_context(graph, token_budget=args.tokens))
        return 0

    if args.command == "snapshot":
        parser.parse_all()
        snap = GraphSnapshot.from_graph(parser.get_graph())
        snap.save(args.out)
        print(f"Snapshot saved -> {args.out} (fingerprint: {snap.fingerprint[:12]}...)")
        return 0

    if args.command == "diff":
        snap_a = GraphSnapshot.load(args.snap_a)
        snap_b = GraphSnapshot.load(args.snap_b)
        print(snap_a.diff(snap_b).summary())
        return 0

    cli.print_help()
    return 1
