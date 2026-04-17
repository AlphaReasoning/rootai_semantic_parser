"""Configuration validation tests."""

from __future__ import annotations

import json

import pytest

from rootai_semantic_parser.config import ParserConfigModel, load_finding_profile


def test_parser_config_accepts_bugbounty_profile() -> None:
    """Validate a known-good configuration."""
    config = ParserConfigModel(root="repo", profile="bugbounty", min_score=60)
    assert config.profile == "bugbounty"
    assert config.min_score == 60


def test_parser_config_accepts_human_only_profile() -> None:
    """Validate the human-only profile name."""
    config = ParserConfigModel(root="repo", profile="human-only", min_score=6.5)
    assert config.profile == "human-only"
    assert config.min_score == 6.5


def test_parser_config_allows_profile_default_min_score() -> None:
    """Allow min_score to be omitted so profile defaults can apply."""
    config = ParserConfigModel(root="repo", profile="human-only")
    assert config.profile == "human-only"
    assert config.min_score is None


def test_parser_config_rejects_unknown_profile() -> None:
    """Reject unsupported profiles."""
    with pytest.raises(ValueError):
        ParserConfigModel(root="repo", profile="unknown")


def test_parser_config_allows_profile_file_override() -> None:
    """Allow a custom profile file to override built-in profile validation."""
    config = ParserConfigModel(root="repo", profile="default", profile_file="custom.json")
    assert config.profile_file == "custom.json"


def test_load_finding_profile_from_json_file(tmp_path) -> None:
    """Load the custom profile JSON schema from disk."""
    path = tmp_path / "custom-profile.json"
    path.write_text(
        json.dumps(
            {
                "name": "custom-human-only",
                "description": "Focuses on logic, business, and auth flaws that scanners usually miss",
                "min_score": 6.5,
                "disabled_patterns": ["ssrf", "open_redirect", "workflow_bypass"],
                "boosted_scoring": {
                    "business_logic_flaw": 1.8,
                    "workflow_bypass": 1.6,
                    "race_condition": 1.5,
                },
            }
        ),
        encoding="utf-8",
    )
    profile = load_finding_profile(str(path))
    assert profile.name == "custom-human-only"
    assert profile.min_score == 6.5
    assert "ssrf" in profile.disabled_patterns
    assert profile.boosted_scoring["business_logic_flaw"] == 1.8
