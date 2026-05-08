"""Compatibility package for the flat RootAI semantic parser source tree."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

__version__ = importlib.import_module("version").__version__

_ALIASES = (
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
)

for _name in _ALIASES:
    try:
        sys.modules[f"{__name__}.{_name}"] = importlib.import_module(_name)
    except ModuleNotFoundError:
        pass

__all__ = ["__version__"]
