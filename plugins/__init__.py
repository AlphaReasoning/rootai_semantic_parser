"""Plugin discovery helpers."""

from plugins.loader import load_plugin_modules
from pathlib import Path
import json


def load_marketplace() -> dict:
    """Load the local plugin marketplace index."""
    return json.loads((Path(__file__).with_name("marketplace.json")).read_text(encoding="utf-8"))

__all__ = ["load_marketplace", "load_plugin_modules"]
