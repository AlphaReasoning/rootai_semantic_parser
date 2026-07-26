"""Tests for the ``rootai_semantic_parser`` compatibility package.

The project's modules live at the top level but are also importable under the
``rootai_semantic_parser`` namespace. Both spellings must resolve to the same
module objects; when they did not, each file executed twice, producing duplicate
parser classes, duplicate ``register_parser()`` side effects, and monkeypatches
that landed on a module the code under test never consulted.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import core.runtime
import models
import parsers.c_engine
import parsers.registry
import parsers.rust_engine
import reports.renderers
import rootai_semantic_parser
import rootai_semantic_parser.core.runtime
import rootai_semantic_parser.models
import rootai_semantic_parser.parsers.c_engine
import rootai_semantic_parser.parsers.registry
import rootai_semantic_parser.parsers.rust_engine
import rootai_semantic_parser.reports.renderers


# ---------------------------------------------------------------------------
# Module identity
# ---------------------------------------------------------------------------


def test_top_level_alias_resolves_to_the_same_module() -> None:
    assert rootai_semantic_parser.models is models


def test_package_alias_resolves_to_the_same_module() -> None:
    assert rootai_semantic_parser.parsers is parsers


def test_submodule_alias_resolves_to_the_same_module() -> None:
    """Regression: this is the level the old shim did not cover."""
    assert rootai_semantic_parser.parsers.rust_engine is parsers.rust_engine
    assert rootai_semantic_parser.parsers.c_engine is parsers.c_engine
    assert rootai_semantic_parser.core.runtime is core.runtime
    assert rootai_semantic_parser.reports.renderers is reports.renderers


def test_classes_are_identical_through_both_paths() -> None:
    assert rootai_semantic_parser.parsers.rust_engine.RustParser is parsers.rust_engine.RustParser
    assert rootai_semantic_parser.parsers.c_engine.CParser is parsers.c_engine.CParser


def test_module_state_is_shared_not_copied() -> None:
    """A second execution would give each copy its own registry list."""
    assert (
        rootai_semantic_parser.parsers.registry.PARSER_PLUGINS
        is parsers.registry.PARSER_PLUGINS
    )


def test_each_aliased_module_appears_once_in_sys_modules() -> None:
    """Both names must map to one object, not two entries holding two copies."""
    for real_name in (
        "models",
        "parsers.rust_engine",
        "parsers.c_engine",
        "core.runtime",
        "reports.renderers",
    ):
        aliased = f"rootai_semantic_parser.{real_name}"
        assert sys.modules[aliased] is sys.modules[real_name], real_name


# ---------------------------------------------------------------------------
# The practical consequences
# ---------------------------------------------------------------------------


def test_patching_through_one_path_is_visible_from_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: patches used to land on a module nothing else consulted."""
    monkeypatch.setattr(
        rootai_semantic_parser.core.runtime, "engine_fingerprint", lambda: "z" * 16
    )
    assert core.runtime.engine_fingerprint() == "z" * 16


def test_dispatch_list_has_no_duplicate_parsers() -> None:
    """Module-level register_parser() calls used to fire once per copy."""
    registered = list(parsers.registry.iter_parser_classes())
    assert len(registered) == len(set(registered))

    names = [cls.__name__ for cls in registered]
    assert len(names) == len(set(names)), names


def test_registry_plugins_hold_no_duplicate_names() -> None:
    names = [cls.__name__ for cls in parsers.registry.PARSER_PLUGINS]
    assert len(names) == len(set(names)), names


# ---------------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------------


def test_real_package_submodules_are_not_aliased() -> None:
    """``cli`` exists both inside the package and at top level; keep them apart."""
    import cli as top_level
    import rootai_semantic_parser.cli as inner

    assert inner is not top_level
    assert Path(inner.__file__).parent.name == "rootai_semantic_parser"
    # The inner wrapper still re-exports the flat CLI entry point.
    assert inner.main is top_level.main


def test_unknown_submodule_of_an_aliased_package_still_raises() -> None:
    with pytest.raises(ModuleNotFoundError):
        __import__("rootai_semantic_parser.parsers.does_not_exist")


def test_unknown_top_level_alias_still_raises() -> None:
    with pytest.raises(ModuleNotFoundError):
        __import__("rootai_semantic_parser.not_a_real_module")


def _installed_finders() -> list:
    tag = f"{rootai_semantic_parser.__name__}._AliasFinder"
    return [f for f in sys.meta_path if getattr(f, "_tag", None) == tag]


def test_finder_is_installed_and_takes_precedence() -> None:
    assert len(_installed_finders()) == 1
    assert getattr(sys.meta_path[0], "_tag", None) is not None


def test_reloading_the_package_does_not_stack_finders() -> None:
    """Regression: the guard used isinstance against a class reload rebinds.

    Every reload therefore pushed another finder. Streamlit re-executes its
    script on each interaction, so they would accumulate for the whole process
    and slow down every import.
    """
    import importlib

    for _ in range(3):
        importlib.reload(rootai_semantic_parser)
        assert len(_installed_finders()) == 1

    # The alias mapping must still work after reloading.
    assert sys.modules["rootai_semantic_parser.parsers.rust_engine"] is parsers.rust_engine


def test_version_is_exposed() -> None:
    import version

    assert rootai_semantic_parser.__version__ == version.__version__
