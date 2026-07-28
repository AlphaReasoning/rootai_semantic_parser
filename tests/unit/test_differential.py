"""Differential analysis: a check and a sink that parse the same value differently.

The class this catches is the one that ships *because* the code looks defended:
an SSRF allowlist validated with one URL parser and fetched with another, a path
checked for '..' before the filesystem normalises it. Taint sees a guard and
calls the value safe; the boundary layer sees a URL fetch, not a grammar. Only a
curated table of known-divergent (validator, consumer) pairs catches it, and it
fires only when *both* sit on the same flow -- which is why it barely false-
positives.

Both directions are tested: a matched divergence must re-surface a guarded
finding (the guard does not defend it), and an ordinary injection with no
validator/consumer split must produce no differential.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from rootai_semantic_parser.analyzers import differential
from rootai_semantic_parser.core.runtime import MultiFileParser
from rootai_semantic_parser.models import AnalysisOptions, SecurityConfig, TaintConfig


# ---------------------------------------------------------------------------
# The knowledge base -- pure, table-driven
# ---------------------------------------------------------------------------


def test_validator_kinds_are_recognised() -> None:
    assert differential.validator_kind("urlparse(u).hostname") == differential.URL_HOST_CHECK
    assert differential.validator_kind("new URL(u).hostname") == differential.URL_HOST_CHECK
    assert differential.validator_kind("p.includes('..')") == differential.DOTDOT_CHECK
    assert differential.validator_kind("path.startsWith(root)") == differential.PATH_PREFIX_CHECK
    assert differential.validator_kind("nothing relevant") is None


def test_consumer_kinds_are_recognised() -> None:
    assert differential.consumer_kind("requests.get") == differential.HTTP_FETCH
    assert differential.consumer_kind("axios.get") == differential.HTTP_FETCH
    assert differential.consumer_kind("fs.readFile") == differential.FILE_OPEN
    assert differential.consumer_kind("res.redirect") == differential.REDIRECT
    assert differential.consumer_kind("cursor.execute") is None  # SQL is the boundary layer's job


def test_only_documented_pairs_diverge() -> None:
    """A validator and consumer that happen to co-occur but are not a known
    divergent pair must not be flagged."""
    assert differential.find_divergence(differential.URL_HOST_CHECK, differential.HTTP_FETCH) is not None
    assert differential.find_divergence(differential.DOTDOT_CHECK, differential.FILE_OPEN) is not None
    # A URL host check in front of a file open is not a known parser-differential
    # class -- do not invent one.
    assert differential.find_divergence(differential.URL_HOST_CHECK, differential.FILE_OPEN) is None


def test_analyse_path_needs_both_a_validator_and_a_divergent_consumer() -> None:
    # Validator present, consumer divergent -> flagged.
    assert differential.analyse_path(["urlparse(u).hostname"], [], "requests.get") is not None
    # Consumer present, no validator -> nothing (an unvalidated SSRF is the
    # ordinary taint finding, not a parser-differential one).
    assert differential.analyse_path([], ["req.query.url"], "requests.get") is None
    # Validator present, consumer not a divergent partner -> nothing.
    assert differential.analyse_path(["urlparse(u).hostname"], [], "cursor.execute") is None


def test_a_matched_divergence_carries_bypass_techniques() -> None:
    result = differential.analyse_path(["new URL(u).hostname"], [], "axios.get")
    assert result is not None
    assert result["impact"] == "SSRF (allowlist bypass)"
    assert result["defeats_guard"] is True
    assert any("@evil" in technique for technique in result["techniques"])


def test_a_validator_on_the_path_is_enough_without_an_explicit_guard() -> None:
    """The disagreement is structural, so a validating call anywhere on the flow
    counts even when the guard modeller did not record it."""
    assert differential.analyse_path([], ["urlparse", "url", "requests.get"], "requests.get") is not None


# ---------------------------------------------------------------------------
# End to end -- a guarded finding the divergence re-surfaces
# ---------------------------------------------------------------------------


def _scan(filename: str, source: str) -> List[Dict]:
    directory = Path(tempfile.mkdtemp())
    (directory / filename).write_text(source, encoding="utf-8")
    parser = MultiFileParser(
        str(directory),
        security_config=SecurityConfig.default_bugbounty(),
        options=AnalysisOptions(profile="bugbounty", min_score=0.0),
        use_cache=False,
    )
    return parser.scan(taint_config=TaintConfig.profile("bugbounty")).taint_paths


def _differential_finding(paths):
    for path in paths:
        record = path if isinstance(path, dict) else path.__dict__
        if record.get("differential"):
            return record
    return None


DIVERGENT = {
    "ssrf_host_check": (
        "a.js",
        "const axios = require('axios');\n"
        "app.get('/f', (req, res) => {\n"
        "  const u = req.query.url;\n"
        "  if (new URL(u).hostname !== 'api.internal') return res.status(400).end();\n"
        "  axios.get(u);\n});\n",
        "SSRF (allowlist bypass)",
    ),
    "path_traversal": (
        "b.js",
        "const fs = require('fs');\n"
        "app.get('/f', (req, res) => {\n"
        "  const p = req.query.p;\n"
        "  if (p.includes('..')) return;\n"
        "  fs.readFile('/data/' + p, cb);\n});\n",
        "Path traversal (check-before-normalise)",
    ),
    "open_redirect": (
        "c.js",
        "app.get('/go', (req, res) => {\n"
        "  const u = req.query.next;\n"
        "  if (new URL(u).hostname !== 'ok.com') return;\n"
        "  res.redirect(u);\n});\n",
        "Open redirect (host-check bypass)",
    ),
}


@pytest.mark.parametrize("case", sorted(DIVERGENT))
def test_divergence_is_detected_and_defeats_the_guard(case: str) -> None:
    filename, source, impact = DIVERGENT[case]
    finding = _differential_finding(_scan(filename, source))
    assert finding is not None, f"{case}: no differential finding"
    assert finding["differential"]["impact"] == impact
    # The guard is bypassable, so the finding must not read as sanitised, and it
    # must survive the reporting threshold rather than staying buried.
    assert finding["sanitized"] is False
    assert finding["score"] > 20


def test_an_ordinary_injection_has_no_differential() -> None:
    """A plain reflected XSS has no validator/consumer parser split."""
    paths = _scan("d.js", "app.get('/h', (req, res) => { res.send('<div>' + req.query.n + '</div>'); });\n")
    assert _differential_finding(paths) is None


def test_a_probe_ready_technique_is_available_for_the_prober() -> None:
    """The static->dynamic handoff: the finding names concrete bypass payloads."""
    finding = _differential_finding(_scan(*DIVERGENT["ssrf_host_check"][:2]))
    assert finding is not None
    assert finding["differential"]["techniques"]
