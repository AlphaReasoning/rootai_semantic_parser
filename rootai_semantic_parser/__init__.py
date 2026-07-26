"""Compatibility package for the flat RootAI semantic parser source tree.

The project ships its modules at the top level (``models``, ``parsers``,
``core``, ...) but installs and imports them under the ``rootai_semantic_parser``
namespace. This package makes the two spellings refer to the *same* module
objects rather than to separate copies.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional, Sequence

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

__version__ = importlib.import_module("version").__version__

#: Top-level modules and packages re-exported under this package's namespace.
#: Names outside this set (``cli``, ``__main__``) are genuine submodules of this
#: package and must keep loading from its own directory.
_ALIASES = frozenset(
    {
        "analyzers",
        "benchmark",
        "api",
        "config",
        "core",
        "evaluation",
        "feedback",
        "graph_queries",
        "legacy_impl",
        "metrics",
        "models",
        "parsers",
        "plugins",
        "reports",
        "version",
    }
)


#: Stable identity for the finder across module reloads. ``isinstance`` cannot be
#: used for this: reloading rebinds ``_AliasFinder`` to a new class object, so an
#: already-installed instance stops matching and a duplicate gets pushed onto
#: ``sys.meta_path``. Streamlit re-executes its script on every interaction, so
#: that would accumulate finders for the lifetime of the process.
_FINDER_TAG = f"{__name__}._AliasFinder"


class _AliasLoader(importlib.abc.Loader):
    """Bind an already-imported module under a second, aliased name."""

    def __init__(self, module: ModuleType) -> None:
        self._module = module

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        return self._module

    def exec_module(self, module: ModuleType) -> None:
        """No-op: the target already executed under its real name."""


class _AliasFinder(importlib.abc.MetaPathFinder):
    """Resolve ``rootai_semantic_parser.X`` to the top-level module ``X``.

    Pre-seeding ``sys.modules`` with only the top-level names is not enough.
    Importing ``rootai_semantic_parser.parsers.rust_engine`` finds the aliased
    parent but no entry for the submodule, so the import machinery loads the
    file a *second* time under the dotted name. That produced two distinct
    class objects per parser, fired module-level ``register_parser()`` side
    effects twice (leaving a duplicate in the dispatch list), and made
    ``monkeypatch`` land on a module the code under test never consults.

    Handing back a spec whose loader returns the already-imported module makes
    both spellings resolve to one object, so each file executes exactly once.
    Resolution is lazy, so importing this package no longer drags in every
    optional dependency up front.
    """

    _PREFIX = f"{__name__}."
    _tag = _FINDER_TAG

    def find_spec(
        self,
        fullname: str,
        path: Optional[Sequence[str]] = None,
        target: Optional[ModuleType] = None,
    ) -> Optional[importlib.machinery.ModuleSpec]:
        if not fullname.startswith(self._PREFIX):
            return None
        real_name = fullname[len(self._PREFIX) :]
        if real_name.split(".", 1)[0] not in _ALIASES:
            return None
        # A failure here is a real problem with the aliased module, most often a
        # missing third-party dependency. It is deliberately allowed to
        # propagate: the previous implementation swallowed ModuleNotFoundError,
        # so an alias silently did not exist and the true cause stayed hidden
        # behind "No module named 'rootai_semantic_parser.<name>'".
        module = importlib.import_module(real_name)

        is_package = hasattr(module, "__path__")
        spec = importlib.util.spec_from_loader(
            fullname,
            _AliasLoader(module),
            origin=getattr(module, "__file__", None),
            is_package=is_package,
        )
        if spec is not None and is_package:
            spec.submodule_search_locations = list(module.__path__)
        return spec


# Drop any finder left by an earlier execution of this module, then install the
# one defined above. Reloading therefore swaps the finder rather than stacking a
# second one, and the active finder is always the freshly defined class.
sys.meta_path[:] = [
    finder for finder in sys.meta_path if getattr(finder, "_tag", None) != _FINDER_TAG
]
# Inserted at the front so the alias mapping wins for the names it claims. The
# prefix check makes it a cheap no-op for every other import in the process.
sys.meta_path.insert(0, _AliasFinder())

__all__ = ["__version__"]
