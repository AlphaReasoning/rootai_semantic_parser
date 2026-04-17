"""Plugin loader for external parser modules."""

from __future__ import annotations

import importlib
import logging
from typing import Iterable, List

log = logging.getLogger(__name__)


def load_plugin_modules(modules: Iterable[str]) -> List[str]:
    """Import plugin modules and return the successfully loaded names."""
    loaded: List[str] = []
    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            log.warning("Failed to load plugin %s: %s", module_name, exc)
            continue
        loaded.append(module_name)
    return loaded
