"""Validated configuration objects."""

from __future__ import annotations

import json
from typing import List

from pydantic import BaseModel, ConfigDict, Field, model_validator

from models import FindingProfile, TaintConfig

SUPPORTED_PROFILES = FindingProfile.supported_names()


class ParserConfigModel(BaseModel):
    """Validated runtime configuration for CLI and library usage."""

    model_config = ConfigDict(extra="forbid")

    root: str = Field(..., min_length=1)
    profile: str = Field(default="default")
    quick_mode: bool = False
    exclude: List[str] = Field(default_factory=list)
    min_score: float | None = Field(default=None, ge=0.0, le=100.0)
    only_unsanitized_reachable: bool = False
    plugins: List[str] = Field(default_factory=list)
    profile_file: str | None = None
    ruleset: str | None = None
    suppressions: str | None = None
    baseline: str | None = None

    @model_validator(mode="after")
    def validate_profile(self) -> "ParserConfigModel":
        """Reject unsupported built-in profiles."""
        if self.profile_file:
            return self
        if self.profile not in SUPPORTED_PROFILES:
            raise ValueError(
                "profile must be one of: " + ", ".join(SUPPORTED_PROFILES)
            )
        return self


class FindingProfileModel(BaseModel):
    """Validated JSON schema for finding-policy profiles."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    min_score: float = Field(default=0.0, ge=0.0, le=100.0)
    disabled_patterns: List[str] = Field(default_factory=list)
    boosted_scoring: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_boosted_scoring(self) -> "FindingProfileModel":
        """Reject empty keys and non-positive multipliers."""
        for key, value in self.boosted_scoring.items():
            if not key.strip():
                raise ValueError("boosted_scoring keys must be non-empty")
            if value <= 0.0:
                raise ValueError("boosted_scoring values must be greater than 0")
        return self


class CustomRuleModel(BaseModel):
    """User-defined taint rule extension."""

    model_config = ConfigDict(extra="forbid")

    sources: List[str] = Field(default_factory=list)
    sinks: List[str] = Field(default_factory=list)
    sanitizers: List[str] = Field(default_factory=list)
    critical_sinks: List[str] = Field(default_factory=list)


def load_ruleset(path: str, base: TaintConfig) -> TaintConfig:
    """Load and merge a custom ruleset onto a base taint config."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    rule = CustomRuleModel.model_validate(raw)
    return TaintConfig(
        sources=set(base.sources) | set(rule.sources),
        sinks=set(base.sinks) | set(rule.sinks),
        sanitizers=set(base.sanitizers) | set(rule.sanitizers),
        critical_sinks=set(base.critical_sinks) | set(rule.critical_sinks),
    )


def load_finding_profile(path: str) -> FindingProfile:
    """Load a finding-policy profile from JSON."""
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    profile = FindingProfileModel.model_validate(raw)
    return FindingProfile(
        name=profile.name,
        description=profile.description,
        min_score=profile.min_score,
        disabled_patterns=frozenset(profile.disabled_patterns),
        boosted_scoring=dict(profile.boosted_scoring),
    )
