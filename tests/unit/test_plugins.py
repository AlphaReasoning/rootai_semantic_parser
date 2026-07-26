"""Plugin registry tests."""

from __future__ import annotations

from typing import Iterator

import pytest

from rootai_semantic_parser.parsers.registry import PARSER_PLUGINS, register_parser


class DummyParser:
    """Dummy parser used to verify plugin registration."""

    @classmethod
    def supports(cls, path: str) -> bool:
        return path.endswith(".dummy")


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    """Stop registrations from leaking into other tests.

    PARSER_PLUGINS is process-global and feeds MultiFileParser's dispatch list,
    so an entry left behind here changes how unrelated tests parse files.
    """
    before = list(PARSER_PLUGINS)
    yield
    PARSER_PLUGINS[:] = before


def test_register_parser_adds_once() -> None:
    """Avoid duplicate plugin registration."""
    before = len(PARSER_PLUGINS)
    register_parser(DummyParser)
    register_parser(DummyParser)
    assert len(PARSER_PLUGINS) == before + 1


def test_registered_parser_reaches_the_dispatch_list() -> None:
    from rootai_semantic_parser.parsers.registry import iter_parser_classes

    register_parser(DummyParser)
    assert DummyParser in list(iter_parser_classes())


def test_register_parser_rejects_a_class_without_supports() -> None:
    """A plugin without supports() would crash mid-scan; reject it at registration."""

    class NotAParser:
        pass

    with pytest.raises(TypeError, match="supports"):
        register_parser(NotAParser)
    assert NotAParser not in PARSER_PLUGINS
