"""Integration tests for real repositories when they are available locally."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rootai_semantic_parser.legacy_impl import AnalysisOptions, MultiFileParser, SecurityConfig, TaintConfig

RAW_REPOS = os.environ.get("ROOTAI_INTEGRATION_REPOS", "")
REPO_CASES = [(item.strip(), "repo") for item in RAW_REPOS.split(":") if item.strip()]


@pytest.mark.parametrize(("repo_root", "expected_hint"), REPO_CASES)
def test_scan_real_repo_if_present(repo_root: str, expected_hint: str) -> None:
    """Scan a real local repo when it exists in the workspace."""
    if not REPO_CASES:
        pytest.skip("Set ROOTAI_INTEGRATION_REPOS to enable real-repo integration scans")
    if not Path(repo_root).exists():
        pytest.skip(f"{repo_root} is not available in this workspace")
    parser = MultiFileParser(
        repo_root,
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", quick_mode=True),
    )
    report = parser.scan(taint_config=TaintConfig.profile("bugbounty"))
    assert report.node_count > 0
    assert isinstance(expected_hint, str)
