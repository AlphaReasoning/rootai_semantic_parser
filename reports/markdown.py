"""Helpers for Markdown-friendly reporting."""

from __future__ import annotations

from models import BountyReport


def bounty_report_to_markdown_table(bounty: BountyReport) -> str:
    """Return a copy-pasteable Markdown table of ranked findings."""
    lines = [
        "| Score | Confidence | Severity | Potential Impact | Exploitability | Reachable | Sanitization | Source | Sink | Explainability | Payloads |",
        "| ---: | ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in bounty.findings:
        path_text = str(finding.get("explanation", "")) or " -> ".join(str(item) for item in finding.get("path_labels", []))
        payload_text = "<br>".join(str(item) for item in finding.get("payload_hints", []))
        lines.append(
            "| {score:.1f} | {confidence:.2f} | {severity} | {impact} | {exploitability} | {reachable} | {sanitization} | {source} | {sink} | {path} | {payloads} |".format(
                score=float(finding.get("score", 0.0)),
                confidence=float(finding.get("confidence", 0.0)),
                severity=str(finding.get("severity", "")).upper(),
                impact=str(finding.get("potential_impact", finding.get("impact", ""))).replace("|", "/"),
                exploitability=str(finding.get("exploitability", "unconfirmed")).replace("|", "/"),
                reachable="yes" if finding.get("reachable") else "no",
                sanitization=str(finding.get("sanitization_status", "unknown")).replace("|", "/"),
                source=str(finding.get("source_location", "")).replace("|", "/"),
                sink=str(finding.get("sink_location", "")).replace("|", "/"),
                path=path_text.replace("|", "/"),
                payloads=payload_text.replace("|", "/"),
            )
        )
    return "\n".join(lines)


def findings_markdown_table(report: BountyReport) -> str:
    """Return a copy-pasteable Markdown table of ranked findings."""
    return bounty_report_to_markdown_table(report)
