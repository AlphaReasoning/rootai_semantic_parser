"""Plugin registry tests."""

from __future__ import annotations

from rootai_semantic_parser.parsers.registry import PARSER_PLUGINS, register_parser


class DummyParser:
    """Dummy parser used to verify plugin registration."""


def test_register_parser_adds_once() -> None:
    """Avoid duplicate plugin registration."""
    before = len(PARSER_PLUGINS)
    register_parser(DummyParser)  # type: ignore[arg-type]
    register_parser(DummyParser)  # type: ignore[arg-type]
    assert len(PARSER_PLUGINS) == before + 1
