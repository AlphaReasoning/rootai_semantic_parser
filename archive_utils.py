"""Safe, bounded extraction for source archives uploaded to RootAI."""

from __future__ import annotations

import io
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable


class UnsafeArchiveError(ValueError):
    """The uploaded archive cannot be extracted inside the workspace boundary."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_archive_bytes: int = 128 * 1024 * 1024
    max_members: int = 10_000
    max_member_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: float = 200.0


def _member_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name:
        raise UnsafeArchiveError("archive contains an empty or invalid member name")
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or normalized.startswith("//"):
        raise UnsafeArchiveError("archive contains an absolute member path")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts or ".." in parts or parts[0].endswith(":"):
        raise UnsafeArchiveError("archive member escapes the extraction root")
    return parts


def _validate_member(info: zipfile.ZipInfo, limits: ArchiveLimits) -> tuple[str, ...]:
    parts = _member_parts(info.filename)
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if stat.S_ISLNK(mode) or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise UnsafeArchiveError("archive contains a link or special file")
    if info.flag_bits & 0x1:
        raise UnsafeArchiveError("encrypted archives are not supported")
    if info.file_size > limits.max_member_bytes:
        raise UnsafeArchiveError("archive member exceeds the per-file size limit")
    if info.file_size:
        if info.compress_size <= 0:
            raise UnsafeArchiveError("archive member has an invalid compressed size")
        if info.file_size / info.compress_size > limits.max_compression_ratio:
            raise UnsafeArchiveError("archive member exceeds the compression-ratio limit")
    return parts


def extract_zip_bytes(
    payload: bytes,
    label: str,
    *,
    limits: ArchiveLimits = ArchiveLimits(),
    temp_factory: Callable[..., str] = tempfile.mkdtemp,
) -> tuple[str, str]:
    """Extract a ZIP into a new temporary workspace without trusting member paths."""
    if len(payload) > limits.max_archive_bytes:
        raise UnsafeArchiveError("archive exceeds the compressed upload size limit")
    tmp_dir = Path(temp_factory(prefix="rootai-archive-")).resolve()
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            members = archive.infolist()
            if len(members) > limits.max_members:
                raise UnsafeArchiveError("archive contains too many members")

            total_bytes = 0
            planned = []
            seen = set()
            for info in members:
                parts = _validate_member(info, limits)
                normalized = "/".join(parts)
                if normalized in seen:
                    raise UnsafeArchiveError("archive contains duplicate member paths")
                seen.add(normalized)
                total_bytes += info.file_size
                if total_bytes > limits.max_total_bytes:
                    raise UnsafeArchiveError("archive exceeds the total extraction size limit")
                target = tmp_dir.joinpath(*parts).resolve()
                if not target.is_relative_to(tmp_dir):
                    raise UnsafeArchiveError("archive member escapes the extraction root")
                planned.append((info, target))

            for info, target in planned:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)

        extracted_roots = list(tmp_dir.iterdir())
        workspace_root = tmp_dir
        if len(extracted_roots) == 1 and extracted_roots[0].is_dir():
            workspace_root = extracted_roots[0]
        safe_label = Path(label.replace("\\", "/")).name or "upload.zip"
        return str(workspace_root), safe_label
    except (OSError, zipfile.BadZipFile, UnsafeArchiveError):
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
