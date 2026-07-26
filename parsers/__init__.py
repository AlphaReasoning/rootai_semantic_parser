"""Parser package exports."""

from parsers.registry import PARSER_PLUGINS, iter_parser_classes, register_parser
from parsers.engines import PythonParser
from parsers.generic_engine import (
    CSharpParser, GoParser, JavaParser, JavaScriptParser,
    PHPParser, RubyParser, TSXParser, TypeScriptParser,
)
from parsers.generic_engine import (
    BashParser, CppParser, KotlinParser, LuaParser,
    ObjCParser, RParser, ScalaParser, SwiftParser,
)
from parsers.rust_engine import RustParser
from parsers.c_engine import CParser

__all__ = [
    "CParser",
    "CSharpParser",
    "GoParser",
    "JavaParser",
    "JavaScriptParser",
    "PARSER_PLUGINS",
    "PHPParser",
    "PythonParser",
    "RubyParser",
    "RustParser",
    "TSXParser",
    "TypeScriptParser",
    "CppParser",
    "ObjCParser",
    "KotlinParser",
    "SwiftParser",
    "ScalaParser",
    "LuaParser",
    "RParser",
    "BashParser",
    "iter_parser_classes",
    "register_parser",
]
