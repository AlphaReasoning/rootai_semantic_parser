"""Small plugin registry for parser extensions."""

from __future__ import annotations

from typing import Iterable, List, Type

PARSER_PLUGINS: List[Type[object]] = []


def register_parser(parser_cls: Type[object]) -> None:
    """Register a custom parser class if it is not already loaded."""
    if parser_cls not in PARSER_PLUGINS:
        PARSER_PLUGINS.append(parser_cls)


def iter_parser_classes() -> Iterable[Type[object]]:
    """Yield built-in and plugin parser classes in registration order."""
    from engines import CSharpParser, GoParser, JavaParser, JavaScriptParser, PHPParser, PythonParser, RubyParser

    builtins: List[Type[object]] = [
        PythonParser,
        JavaScriptParser,
        GoParser,
        JavaParser,
        PHPParser,
        RubyParser,
        CSharpParser,
    ]
    ordered: List[Type[object]] = []
    for parser_cls in builtins + PARSER_PLUGINS:
        if parser_cls not in ordered:
            ordered.append(parser_cls)
    return tuple(ordered)
