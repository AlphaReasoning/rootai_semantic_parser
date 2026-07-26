"""Tests for on-disk parse-cache keying and invalidation.

Every test redirects ``HOME`` to ``tmp_path`` so nothing here reads or writes the
developer's real ``~/.cache/rootai-semantic-parser``.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

from rootai_semantic_parser.core import runtime
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig
from rootai_semantic_parser.parsers.engines import PythonParser

# Everything is reached through the single ``runtime`` module object. Importing
# names from ``rootai_semantic_parser.core.runtime`` as well would load a second
# copy of the module under the compat shim, and monkeypatching would then land on
# a module the code under test never consults.
ParseCache = runtime.ParseCache
engine_fingerprint = runtime.engine_fingerprint

SOURCE = "def handler(request):\n    cmd = request.args.get('cmd')\n    return eval(cmd)\n"


@pytest.fixture(autouse=True)
def _isolated_cache_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point os.path.expanduser('~') at a scratch dir for every test here."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


def _cache(version: str = "0.21.0", **overrides) -> ParseCache:
    options = overrides.pop("options", AnalysisOptions(profile="bugbounty"))
    config = overrides.pop("config", SecurityConfig.default_bugbounty())
    return ParseCache(version, options, config)


def _parsed(tmp_path: Path) -> tuple:
    """Parse a small Python file and return (path, parser)."""
    path = tmp_path / "sample.py"
    path.write_text(SOURCE, encoding="utf-8")
    parser = PythonParser(
        SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty"),
    )
    parser.parse(str(path))
    return str(path), parser


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_saved_entry_is_served_back(tmp_path: Path) -> None:
    path, parser = _parsed(tmp_path)
    cache = _cache()
    cache.save(path, parser)

    restored = _cache().load(path)
    assert restored is not None
    assert set(restored.nodes) == set(parser.nodes)
    assert len(restored.edges) == len(parser.edges)


def test_missing_entry_counts_as_a_miss(tmp_path: Path) -> None:
    path, _ = _parsed(tmp_path)
    cache = _cache()

    assert cache.load(path) is None
    assert cache.misses == 1
    assert cache.hits == 0


def test_edited_file_is_not_served_from_cache(tmp_path: Path) -> None:
    """The pre-existing mtime/size fingerprint must still work."""
    path, parser = _parsed(tmp_path)
    cache = _cache()
    cache.save(path, parser)

    Path(path).write_text(SOURCE + "\ndef added():\n    pass\n", encoding="utf-8")
    assert _cache().load(path) is None


# ---------------------------------------------------------------------------
# Engine-code invalidation
# ---------------------------------------------------------------------------


def test_namespace_changes_when_engine_fingerprint_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "engine_fingerprint", lambda: "a" * 16)
    before = _cache().namespace

    monkeypatch.setattr(runtime, "engine_fingerprint", lambda: "b" * 16)
    assert _cache().namespace != before


def test_entry_is_not_served_after_the_engine_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: parser code was absent from the key.

    A scan run after an engine fix silently replayed graphs produced by the old
    code, because the scanned file's mtime had not changed.
    """
    path, parser = _parsed(tmp_path)

    monkeypatch.setattr(runtime, "engine_fingerprint", lambda: "a" * 16)
    _cache().save(path, parser)
    assert _cache().load(path) is not None, "sanity: same engine should hit"

    monkeypatch.setattr(runtime, "engine_fingerprint", lambda: "b" * 16)
    assert _cache().load(path) is None


def test_fingerprint_follows_tracked_file_contents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tracked = tmp_path / "fake_engine.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")

    module = types.ModuleType("fake_engine")
    module.__file__ = str(tracked)
    monkeypatch.setitem(sys.modules, "fake_engine", module)
    monkeypatch.setattr(runtime, "_CACHE_RELEVANT_MODULES", ("models", "fake_engine"))

    before = engine_fingerprint()
    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    assert engine_fingerprint() != before


def test_fingerprint_ignores_mtime_when_contents_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh checkout rewrites mtimes; that must not discard a valid cache."""
    tracked = tmp_path / "fake_engine.py"
    tracked.write_text("VALUE = 1\n", encoding="utf-8")

    module = types.ModuleType("fake_engine")
    module.__file__ = str(tracked)
    monkeypatch.setitem(sys.modules, "fake_engine", module)
    monkeypatch.setattr(runtime, "_CACHE_RELEVANT_MODULES", ("models", "fake_engine"))

    before = engine_fingerprint()
    os.utime(tracked, (1_000_000, 1_000_000))
    assert engine_fingerprint() == before


def test_fingerprint_is_deterministic_and_short() -> None:
    value = engine_fingerprint()
    assert value == engine_fingerprint()
    assert len(value) == 16
    assert all(ch in "0123456789abcdef" for ch in value)


def test_fingerprint_covers_the_real_parser_modules() -> None:
    """The registered engines must actually be among the hashed files."""
    tracked = {
        os.path.realpath(sys.modules[cls.__module__].__file__)
        for cls in runtime.iter_parser_classes()
        if getattr(sys.modules.get(cls.__module__), "__file__", None)
    }
    assert any(name.endswith("engines.py") for name in tracked)
    assert any(name.endswith("rust_engine.py") for name in tracked)
    assert any(name.endswith("c_engine.py") for name in tracked)


# ---------------------------------------------------------------------------
# Config keying
# ---------------------------------------------------------------------------


def test_namespace_changes_when_classification_patterns_change() -> None:
    """Regression: only stack/sources/sinks were keyed.

    ``classify_node`` also reads the pii and logic-class sets, so a custom
    --config that changes them was served stale is_pii_sensitive / logic_class.
    """
    base = SecurityConfig.default_bugbounty()
    before = _cache(config=base).namespace

    altered = SecurityConfig.default_bugbounty()
    altered.pii_functions = set(altered.pii_functions) | {"totally_new_pii_marker"}
    assert _cache(config=altered).namespace != before


def test_namespace_changes_for_each_classification_field() -> None:
    fields_under_test = (
        "pii_functions",
        "pii_variable_patterns",
        "destructive_functions",
        "write_functions",
        "read_only_functions",
        "taint_sources",
        "taint_sinks",
    )
    base = _cache(config=SecurityConfig.default_bugbounty()).namespace

    for field_name in fields_under_test:
        altered = SecurityConfig.default_bugbounty()
        setattr(altered, field_name, set(getattr(altered, field_name)) | {"sentinel_value"})
        assert _cache(config=altered).namespace != base, field_name


def test_namespace_changes_with_version_and_parse_options() -> None:
    base = _cache().namespace

    assert _cache(version="0.99.0").namespace != base
    assert _cache(options=AnalysisOptions(profile="human-only")).namespace != base
    assert _cache(options=AnalysisOptions(profile="bugbounty", quick_mode=True)).namespace != base


def test_namespace_is_stable_across_scoring_only_options() -> None:
    """Scoring flags apply after the cache, so tuning them must not evict it."""
    base = _cache(options=AnalysisOptions(profile="bugbounty")).namespace

    for options in (
        AnalysisOptions(profile="bugbounty", min_score=9.5),
        AnalysisOptions(profile="bugbounty", enable_reachability=False),
        AnalysisOptions(profile="bugbounty", enable_auth_checks=False),
        AnalysisOptions(profile="bugbounty", only_reachable_unsanitized=True),
    ):
        assert _cache(options=options).namespace == base


# ---------------------------------------------------------------------------
# Corrupt entries
# ---------------------------------------------------------------------------


def test_corrupt_entry_is_a_miss_not_a_crash(tmp_path: Path) -> None:
    path, parser = _parsed(tmp_path)
    cache = _cache()
    cache.save(path, parser)

    # Nodes carrying a field the dataclass does not accept.
    entry = Path(cache._cache_path(path))
    entry.write_text(
        '{"parser": "PythonParser", "stack": "bugbounty", '
        '"nodes": [{"id": "x", "unexpected_field": 1}], "edges": []}',
        encoding="utf-8",
    )

    fresh = _cache()
    assert fresh.load(path) is None
    assert fresh.misses == 1


def test_unparseable_entry_is_a_miss(tmp_path: Path) -> None:
    path, parser = _parsed(tmp_path)
    cache = _cache()
    cache.save(path, parser)

    Path(cache._cache_path(path)).write_text("{not json", encoding="utf-8")
    assert _cache().load(path) is None
