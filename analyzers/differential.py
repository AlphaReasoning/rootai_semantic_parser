"""Differential analysis: when a check and a sink parse the same value differently.

The boundary layer asks *where* a value lands in the consumed language. This asks
a different question: was the value **validated by one parser and consumed by
another that disagrees**? That mismatch is where "I checked it, so it's safe"
becomes a vulnerability, and it is invisible to both taint tracking (a guard was
present, so the value looks defended) and to the boundary layer (the sink is a
URL fetch or a file open, not an embedded grammar).

The canonical case is an SSRF allowlist. The code parses the URL with one
library to check the host is allowed:

    if urlparse(url).hostname not in ALLOWED: abort()
    requests.get(url)          # a *different* URL parser fetches it

`http://allowed@evil.com` has hostname `allowed` to `urlparse` but authority
`evil.com` to many HTTP stacks, so the check passes and the request goes to the
attacker's host. The guard is real and does nothing.

This is deliberately a **curated table of known-divergent (validator, consumer)
pairs, not a solver**. Detecting parser disagreement in general is open
research; the value here is concentrated in a handful of well-documented classes
(SSRF host-check bypass, path traversal after normalisation, open redirect), and
a table catches those with almost no false positives because it only fires when
*both* a validator and a divergent consumer sit on the same flow.

A finding here is high-signal precisely because it contradicts a defence the
code appears to have. So a matched divergence *defeats* the guard: taint that a
guard would otherwise mark defended is re-surfaced, with the bypass techniques
attached so a prober knows exactly what to send.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Validator kinds -- what a check on the value established, and with which parser.
URL_HOST_CHECK = "url-host-check"
PATH_PREFIX_CHECK = "path-prefix-check"
DOTDOT_CHECK = "dotdot-check"
SCHEME_CHECK = "scheme-check"

# Consumer kinds -- what the sink does with the value, and with which parser.
HTTP_FETCH = "http-fetch"
FILE_OPEN = "file-open"
REDIRECT = "redirect"


@dataclass(frozen=True)
class Divergence:
    """A known disagreement between a validator's parser and a sink's parser."""

    validator: str
    consumer: str
    #: The vulnerability class this bypass produces.
    impact: str
    #: One line an operator can act on.
    rationale: str
    #: Concrete payloads that exploit the disagreement.
    techniques: Tuple[str, ...]


#: The curated table. Each entry is a pair that is documented to disagree, with
#: the payloads that exploit the gap. Kept small on purpose -- every entry is a
#: real, named class, not a guess.
DIVERGENCES: Tuple[Divergence, ...] = (
    Divergence(
        URL_HOST_CHECK, HTTP_FETCH, "SSRF (allowlist bypass)",
        "the host is validated by one URL parser but fetched by an HTTP stack "
        "that parses the authority differently, so a host that passes the check "
        "is not the host that is contacted",
        (
            "http://allowed@evil.com  (userinfo confusion)",
            "http://evil.com\\@allowed.com  (backslash authority split)",
            "http://allowed.com evil.com  (whitespace/control chars)",
            "http://0x7f.0.0.1 / http://2130706433  (alternate IP encodings)",
            "a redirect from the allowed host to an internal one",
        ),
    ),
    Divergence(
        SCHEME_CHECK, HTTP_FETCH, "SSRF (scheme bypass)",
        "the scheme is checked textually but the fetch library accepts schemes "
        "or forms the check did not anticipate (file:, gopher:, //host)",
        (
            "file:///etc/passwd", "gopher://internal:6379/_...",
            "//internal-host  (protocol-relative)",
        ),
    ),
    Divergence(
        DOTDOT_CHECK, FILE_OPEN, "Path traversal (check-before-normalise)",
        "the path is checked for '..' before the filesystem normalises it, so an "
        "encoded, absolute, or mixed-separator payload defeats the textual check",
        (
            "%2e%2e%2f%2e%2e%2f  (URL-encoded, decoded after the check)",
            "....//  (overlapping sequences a naive filter collapses wrong)",
            "/etc/passwd  (absolute path a prefix check misses)",
            "..\\..\\  (backslash separators on Windows)",
        ),
    ),
    Divergence(
        PATH_PREFIX_CHECK, FILE_OPEN, "Path traversal (prefix bypass)",
        "the path is checked to start with an allowed prefix before "
        "normalisation, so '..' inside it still escapes the intended root",
        (
            "ALLOWED/../../../etc/passwd",
            "ALLOWED/..%2f..%2fetc/passwd",
        ),
    ),
    Divergence(
        URL_HOST_CHECK, REDIRECT, "Open redirect (host-check bypass)",
        "the redirect target's host is validated by one URL parser but the "
        "browser follows a differently-parsed authority",
        (
            "//evil.com  (protocol-relative)",
            "https://allowed@evil.com",
            "https:/\\/\\evil.com",
        ),
    ),
)

_DIVERGENCE_INDEX: Dict[Tuple[str, str], Divergence] = {
    (d.validator, d.consumer): d for d in DIVERGENCES
}


#: Text signatures that identify a validator kind. Matched against a guard's
#: test expression *and* against the labels of calls on the path, so the
#: analysis works whether or not the guard modeller fired.
_VALIDATOR_SIGNATURES: Tuple[Tuple[str, re.Pattern], ...] = (
    (URL_HOST_CHECK, re.compile(
        r"urlparse|urlsplit|\.hostname|\.host\b|gethost|new\s+url\(|geturl|"
        r"parse_url|net/url|url\.parse|getauthority|\.netloc",
        re.IGNORECASE)),
    (SCHEME_CHECK, re.compile(r"\.scheme|\.protocol|startswith\(\s*['\"]https?", re.IGNORECASE)),
    (DOTDOT_CHECK, re.compile(r"\.\.|dotdot|contains\(\s*['\"]\.\.|indexof\(\s*['\"]\.\.", re.IGNORECASE)),
    (PATH_PREFIX_CHECK, re.compile(
        r"startswith|hasprefix|\.begins|normalize|realpath|canonicaliz|getcanonical",
        re.IGNORECASE)),
)

#: Sink label signatures that identify a consumer kind.
_CONSUMER_SIGNATURES: Tuple[Tuple[str, re.Pattern], ...] = (
    (HTTP_FETCH, re.compile(
        r"requests\.(get|post|put|head|request)|urlopen|urlretrieve|http\.get|"
        r"https\.get|axios|fetch\(|needle\.|httpclient|resttemplate|urlconnection|"
        r"webclient|curl_exec|file_get_contents|net/http|okhttp",
        re.IGNORECASE)),
    (FILE_OPEN, re.compile(
        r"\bopen\(|fopen|readfile|read_file|fileinputstream|fileoutputstream|"
        r"file\.readall|file\.open|sendfile|createreadstream|fs\.read|"
        r"paths\.get|files\.new|include\b|require_once|new\s+file\(",
        re.IGNORECASE)),
    (REDIRECT, re.compile(
        r"sendredirect|\.redirect|location\.href|header\(\s*['\"]location|"
        r"http\.redirect|res\.redirect",
        re.IGNORECASE)),
)


def validator_kind(text: str) -> Optional[str]:
    """The validator kind a check expression represents, if recognised."""
    for kind, pattern in _VALIDATOR_SIGNATURES:
        if pattern.search(text or ""):
            return kind
    return None


def consumer_kind(sink_label: str) -> Optional[str]:
    """The consumer kind a sink represents, if recognised."""
    for kind, pattern in _CONSUMER_SIGNATURES:
        if pattern.search(sink_label or ""):
            return kind
    return None


def find_divergence(validator: str, consumer: str) -> Optional[Divergence]:
    return _DIVERGENCE_INDEX.get((validator, consumer))


def analyse_path(guard_texts: List[str], path_labels: List[str], sink_label: str) -> Optional[Dict]:
    """Detect a parser-differential bypass on one taint path.

    Fires only when the flow carries *both* a recognised validator and a sink
    whose consumer is a documented divergent partner of it -- which is why it
    almost never false-positives. ``guard_texts`` are the value's modelled
    guards; ``path_labels`` are the labels of every node on the path, so a
    validating call (``urlparse(...)``) is caught even when the guard modeller
    did not record it as a guard.
    """
    consumer = consumer_kind(sink_label)
    if consumer is None:
        return None

    # Look for a validator among the modelled guards first, then anywhere on the
    # path. A guard is the stronger signal (the value was actually checked), but
    # a validating call on the path is enough -- the disagreement is structural.
    for candidate in list(guard_texts) + list(path_labels):
        validator = validator_kind(candidate)
        if validator is None:
            continue
        divergence = find_divergence(validator, consumer)
        if divergence is not None:
            return {
                "class": "parser-differential",
                "validator": divergence.validator,
                "consumer": divergence.consumer,
                "impact": divergence.impact,
                "rationale": divergence.rationale,
                "techniques": list(divergence.techniques),
                "matched_on": candidate[:120],
                # The whole point: the check does not defend this flow.
                "defeats_guard": True,
            }
    return None
