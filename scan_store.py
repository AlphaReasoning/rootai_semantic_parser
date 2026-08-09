"""Content-addressed storage for immutable Streamlit scan artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


_ARTIFACT_ID = re.compile(r"[0-9a-f]{64}")


class ScanArtifactStore:
    """Persist heavyweight scan/export payloads outside widget session state."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root or Path.home() / ".cache" / "rootai-semantic-parser" / "scan-artifacts")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    @staticmethod
    def _validate(identifier: str) -> str:
        if not _ARTIFACT_ID.fullmatch(identifier):
            raise ValueError("invalid artifact identifier")
        return identifier

    @staticmethod
    def _json_bytes(payload: Any) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as handle:
            pending = Path(handle.name)
            handle.write(payload)
        try:
            pending.chmod(0o600)
            os.replace(pending, path)
            path.chmod(0o600)
        finally:
            pending.unlink(missing_ok=True)

    @staticmethod
    def _summary(result: Mapping[str, Any]) -> Dict[str, Any]:
        report = result.get("report", {})
        bounty = result.get("bounty", {})
        meta = result.get("meta", {})
        trace_summary = meta.get("trace_summary", {})
        return {
            "node_count": int(report.get("node_count", 0)),
            "edge_count": int(report.get("edge_count", 0)),
            "taint_path_count": int(report.get("taint_path_count", 0)),
            "finding_count": len(bounty.get("findings", [])),
            "profile": str(meta.get("profile", bounty.get("profile", ""))),
            "duration_seconds": float(trace_summary.get("duration_seconds", 0.0)),
        }

    def _scan_path(self, scan_id: str) -> Path:
        return self.root / self._validate(scan_id) / "scan.json"

    def _export_path(self, scan_id: str, cache_key: str) -> Path:
        return self.root / self._validate(scan_id) / "exports" / f"{self._validate(cache_key)}.bin"

    def store_scan(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Write a scan once and return a lightweight content-addressed reference."""
        payload = self._json_bytes(result)
        scan_id = hashlib.sha256(payload).hexdigest()
        path = self._scan_path(scan_id)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != scan_id:
            self._atomic_write(path, payload)
        return {"scan_id": scan_id, "summary": self._summary(result)}

    def load_scan(self, scan_id: str) -> Dict[str, Any]:
        """Load a stored scan by its validated identifier."""
        path = self._scan_path(scan_id)
        if not path.is_file():
            raise FileNotFoundError(f"scan artifact not found: {scan_id}")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != scan_id:
            raise ValueError(f"scan artifact failed integrity check: {scan_id}")
        return json.loads(payload)

    def export_cache_key(self, export_key: str, options: Mapping[str, Any]) -> str:
        """Return a stable cache key without exposing option values in file paths."""
        return hashlib.sha256(self._json_bytes({"format": export_key, "options": options})).hexdigest()

    def store_export(self, scan_id: str, cache_key: str, data: str | bytes) -> None:
        """Store one generated export for a scan."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        self._atomic_write(self._export_path(scan_id, cache_key), payload)

    def load_export(self, scan_id: str, cache_key: str, *, text: bool) -> str | bytes | None:
        """Load a cached export, returning ``None`` when it has not been generated."""
        path = self._export_path(scan_id, cache_key)
        if not path.is_file():
            return None
        payload = path.read_bytes()
        return payload.decode("utf-8") if text else payload
