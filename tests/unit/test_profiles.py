"""Taint profile and payload tests."""

from __future__ import annotations

from rootai_semantic_parser.analyzers import TaintAnalyzer
from rootai_semantic_parser.models import FindingProfile, SecurityConfig, TaintConfig


def test_bugbounty_profile_contains_high_signal_sinks() -> None:
    """Ensure the bug-bounty profile keeps dangerous sinks enabled."""
    profile = TaintConfig.profile("bugbounty")
    assert "grantadmin" in profile.sinks
    assert "processbuilder" in profile.critical_sinks


def test_human_only_profile_focuses_on_auth_and_business_logic_sinks() -> None:
    """Ensure the human-only profile prefers auth and workflow signals."""
    profile = TaintConfig.profile("human-only")
    assert "grantadmin" in profile.sinks
    assert "workflow" in profile.sinks
    assert "transfer" in profile.critical_sinks
    assert "os.system" not in profile.sinks


def test_human_only_security_config_uses_matching_taint_profile() -> None:
    """Ensure the security config exposes the human-only taint definitions."""
    config = SecurityConfig.default_human_only()
    assert config.stack == "human-only"
    assert "grantadmin" in config.taint_sinks
    assert "workflow" in config.taint_sinks
    assert "transfer" in config.taint_critical_sinks


def test_human_only_profile_keeps_boosted_patterns_enabled() -> None:
    """Boosted patterns should not be disabled away."""
    profile = FindingProfile.built_in("human-only")
    assert "workflow_bypass" in profile.disabled_patterns
    assert "workflow_bypass" in profile.boosted_scoring
    assert "workflow_bypass" not in profile.effective_disabled_patterns
    assert "privilege_escalation" not in profile.effective_disabled_patterns


def test_payload_hints_include_rce_probe() -> None:
    """Return payload hints for code execution sinks."""
    payloads = TaintAnalyzer._payload_hints("eval")
    assert any("system" in item or "child_process" in item for item in payloads)
