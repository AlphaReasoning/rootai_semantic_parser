"""Small plugin registry for parser extensions."""

from __future__ import annotations

from typing import Iterable, List, Type

PARSER_PLUGINS: List[Type[object]] = []


def register_parser(parser_cls: Type[object]) -> None:
    """Register a custom parser class if it is not already loaded."""
    if parser_cls not in PARSER_PLUGINS:
        PARSER_PLUGINS.append(parser_cls)


def iter_parser_classes() -> Iterable[Type[object]]:
    """Yield built-in and plugin parser classes in registration order.

    IR v0.3.0 additions: RustParser (.rs) and CParser (.c, .h) are appended
    after the existing seven targets.  Their file extensions have no overlap
    with any prior parser's ``supports()`` check, so dispatch order is
    irrelevant for correctness — placement at the end is defensive.
    """
    # Local imports prevent circular-import issues at module load time.
    from parsers.engines import (
        CSharpParser, GoParser, JavaParser, JavaScriptParser,
        PHPParser, PythonParser, RubyParser,
    )
    from parsers.rust_engine import RustParser  # IR v0.3.0
    from parsers.c_engine import CParser        # IR v0.3.0

    builtins: List[Type[object]] = [
        PythonParser,
        JavaScriptParser,
        GoParser,
        JavaParser,
        PHPParser,
        RubyParser,
        CSharpParser,
        # --- IR v0.3.0 additions ---
        RustParser,
        CParser,
    ]
    ordered: List[Type[object]] = []
    for parser_cls in builtins + PARSER_PLUGINS:
        if parser_cls not in ordered:
            ordered.append(parser_cls)
    return tuple(ordered)
