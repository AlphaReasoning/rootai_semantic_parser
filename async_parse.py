"""Async helpers for large repository scans."""

from __future__ import annotations

import asyncio

from core.runtime import MultiFileParser
from models import AnalysisOptions, ScanReport, SecurityConfig, TaintConfig


async def scan_async(root: str) -> ScanReport:
    """Run a bug-bounty oriented scan in a worker thread."""
    parser = MultiFileParser(
        root,
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", quick_mode=True),
    )
    return await asyncio.to_thread(parser.scan, TaintConfig.profile("bugbounty"))
