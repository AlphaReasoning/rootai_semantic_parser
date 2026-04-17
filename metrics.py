"""Minimal Prometheus/Grafana-friendly metric export."""

from __future__ import annotations

from typing import Dict

from models import ScanReport


def scan_report_prometheus(report: ScanReport) -> str:
    """Render a Prometheus text payload for a scan report."""
    metrics: Dict[str, float] = {
        "rootai_nodes_total": float(report.node_count),
        "rootai_edges_total": float(report.edge_count),
        "rootai_taint_paths_total": float(report.taint_path_count),
        "rootai_pii_nodes_total": float(report.pii_node_count),
        "rootai_unresolved_calls_total": float(report.unresolved_calls),
        "rootai_cache_hits_total": float(report.cache_hits),
        "rootai_cache_misses_total": float(report.cache_misses),
    }
    return "\n".join(f"{name} {value}" for name, value in metrics.items()) + "\n"
