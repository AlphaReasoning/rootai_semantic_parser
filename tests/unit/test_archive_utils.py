from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path

import pytest

from archive_utils import ArchiveLimits, UnsafeArchiveError, extract_zip_bytes


def _archive(entries: dict[str, bytes], *, compression=zipfile.ZIP_STORED) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return payload.getvalue()


def _factory(root: Path):
    def create(**kwargs) -> str:
        root.mkdir()
        return str(root)

    return create


def test_extracts_a_valid_single_root_archive(tmp_path) -> None:
    destination = tmp_path / "extract"

    workspace, label = extract_zip_bytes(
        _archive({"project/src/main.py": b"print('ok')\n", "project/README.md": b"hello\n"}),
        "../../source.zip",
        temp_factory=_factory(destination),
    )

    assert Path(workspace) == destination / "project"
    assert (Path(workspace) / "src/main.py").read_text(encoding="utf-8") == "print('ok')\n"
    assert label == "source.zip"


@pytest.mark.parametrize("member", ["../escape.py", "..\\escape.py", "/tmp/escape.py", "C:\\escape.py"])
def test_rejects_member_paths_outside_the_workspace(tmp_path, member) -> None:
    destination = tmp_path / "extract"

    with pytest.raises(UnsafeArchiveError, match="absolute|escapes"):
        extract_zip_bytes(
            _archive({member: b"owned"}),
            "source.zip",
            temp_factory=_factory(destination),
        )

    assert not (tmp_path / "escape.py").exists()
    assert not destination.exists()


def test_rejects_symbolic_links(tmp_path) -> None:
    payload = io.BytesIO()
    link = zipfile.ZipInfo("project/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(link, "../outside")

    with pytest.raises(UnsafeArchiveError, match="link or special"):
        extract_zip_bytes(
            payload.getvalue(),
            "source.zip",
            temp_factory=_factory(tmp_path / "extract"),
        )


def test_rejects_high_ratio_archives(tmp_path) -> None:
    payload = _archive({"project/large.txt": b"A" * 100_000}, compression=zipfile.ZIP_DEFLATED)

    with pytest.raises(UnsafeArchiveError, match="compression-ratio"):
        extract_zip_bytes(
            payload,
            "source.zip",
            temp_factory=_factory(tmp_path / "extract"),
        )


def test_rejects_archives_over_the_member_limit(tmp_path) -> None:
    with pytest.raises(UnsafeArchiveError, match="too many members"):
        extract_zip_bytes(
            _archive({"one.txt": b"1", "two.txt": b"2"}),
            "source.zip",
            limits=ArchiveLimits(max_members=1),
            temp_factory=_factory(tmp_path / "extract"),
        )


def test_rejects_oversized_compressed_upload_before_creating_a_workspace(tmp_path) -> None:
    destination = tmp_path / "extract"

    with pytest.raises(UnsafeArchiveError, match="compressed upload size"):
        extract_zip_bytes(
            b"not-even-opened",
            "source.zip",
            limits=ArchiveLimits(max_archive_bytes=4),
            temp_factory=_factory(destination),
        )

    assert not destination.exists()
