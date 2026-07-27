"""Language-boundary analysis: what the *consuming* parser sees.

A taint engine answers "did attacker data reach a dangerous function". That is
not what injection is. Injection is attacker data **changing the parse tree of
another language**, and whether it can depends entirely on where in that
language's grammar the value lands.

These four flows are indistinguishable to a taint tracker and require four
different defences:

    "SELECT * FROM t WHERE id = "   + x      -> comparison operand   parameterise
    "SELECT * FROM t WHERE n = '"   + x + "'"-> inside a literal     escape quotes
    "SELECT * FROM t ORDER BY "     + x      -> an identifier        allowlist ONLY
    "SELECT * FROM t WHERE id = ?"  , [x]    -> no hole at all       not injectable

The third is the one that matters in practice: escaping does nothing there and
parameter binding is not even expressible, so teams who parameterised their
WHERE clause and moved on still ship the bug. The fourth is provably safe and
should never reach a human.

So this module reconstructs the string the host language actually builds --
literal parts plus holes where runtime values go -- parses it with the consumer
language's own grammar, and reports the grammatical position of each hole. From
the position follows the required defence, and comparing that against the
defence actually applied turns "tainted value reaches sink" into "the escaping
here is the wrong kind for this position".

Conservative throughout. A template that will not parse, a consumer with no
grammar, or a hole that cannot be located yields ``None`` and the caller falls
back to ordinary taint reasoning. Being unable to classify never suppresses a
finding; it only forgoes the extra precision.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

#: Token substituted for a runtime value. Must survive tokenisation as a plain
#: identifier in every consumer grammar, so no punctuation and no keywords.
HOLE_PREFIX = "ROOTAIHOLE"


def hole_token(index: int) -> str:
    return f"{HOLE_PREFIX}{index}"


# ---------------------------------------------------------------------------
# Defences
# ---------------------------------------------------------------------------

#: What a defence actually accomplishes, named by the position it makes safe.
#: These are capabilities, not function names, so one vocabulary covers every
#: language's spelling of the same idea.
PARAMETERISE = "parameterise"
QUOTE_ESCAPE = "quote-escape"
ALLOWLIST = "allowlist"
NUMERIC_CAST = "numeric-cast"
SHELL_QUOTE = "shell-quote"
ARGV_ARRAY = "argv-array"
HTML_TEXT_ESCAPE = "html-text-escape"
HTML_ATTR_ESCAPE = "html-attr-escape"
JS_STRING_ESCAPE = "js-string-escape"
URL_SCHEME_CHECK = "url-scheme-check"
CSS_ESCAPE = "css-escape"
REJECT = "reject"

#: Sanitiser names mapped to the capability they provide. A defence absent here
#: is treated as unknown rather than as absent, so an unrecognised helper never
#: turns into a false "undefended" claim -- it produces `unknown`, not `MISMATCH`.
DEFENCE_CAPABILITIES: Dict[str, FrozenSet[str]] = {
    # Parameter binding
    "preparestatement": frozenset({PARAMETERISE}),
    "createquery": frozenset({PARAMETERISE}),
    "bindparam": frozenset({PARAMETERISE}),
    "sqlcommand": frozenset({PARAMETERISE}),
    # Quote escaping. Defends a literal position and nothing else.
    "real_escape_string": frozenset({QUOTE_ESCAPE}),
    "mysqli_real_escape_string": frozenset({QUOTE_ESCAPE}),
    "escape_string": frozenset({QUOTE_ESCAPE}),
    "quote_ident": frozenset({QUOTE_ESCAPE, ALLOWLIST}),
    "addslashes": frozenset({QUOTE_ESCAPE}),
    # Numeric coercion. Total: a number cannot carry a payload anywhere.
    "int": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "parseint": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "integer.parseint": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "atoi": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "strconv.atoi": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "number": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    "tonumber": frozenset({NUMERIC_CAST, PARAMETERISE, ALLOWLIST, QUOTE_ESCAPE}),
    # Shell
    "shlex.quote": frozenset({SHELL_QUOTE}),
    "escapeshellarg": frozenset({SHELL_QUOTE}),
    "shellescape": frozenset({SHELL_QUOTE}),
    "escapeshellcmd": frozenset({SHELL_QUOTE}),
    # HTML/JS. html escaping defends TEXT and ATTRIBUTE, never a script body.
    "html.escape": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "htmlspecialchars": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "escapehtml": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "encodeforhtml": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "sanitize_html": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "dompurify.sanitize": frozenset({HTML_TEXT_ESCAPE, HTML_ATTR_ESCAPE}),
    "encodeforjavascript": frozenset({JS_STRING_ESCAPE}),
    "encodeforurl": frozenset({URL_SCHEME_CHECK}),
    "encodeurlcomponent": frozenset({URL_SCHEME_CHECK}),
    "encodeforcss": frozenset({CSS_ESCAPE}),
}


# ---------------------------------------------------------------------------
# Contexts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Position:
    """A grammatical position a value can occupy in the consumed language."""

    name: str
    #: Any one of these defences makes the position safe.
    accepts: FrozenSet[str]
    #: Why, in one line an operator can act on.
    rationale: str
    #: Positions where no escaping helps, only an allowlist or rejection.
    structural: bool = False


#: Ordered most-specific first. The first rule whose marker appears in the
#: node-type chain wins, so `script_element` beats the generic `text` that also
#: appears above it.
@dataclass(frozen=True)
class Rule:
    markers: Tuple[str, ...]
    position: Position


SQL_UNQUOTED = Position(
    "sql:unquoted-value",
    frozenset({PARAMETERISE, NUMERIC_CAST}),
    "a bare comparison operand; quote escaping does nothing because there are no quotes to escape",
)
SQL_LITERAL = Position(
    "sql:quoted-literal",
    frozenset({PARAMETERISE, QUOTE_ESCAPE, NUMERIC_CAST}),
    "inside a string literal; escaping the quote character closes the hole",
)
SQL_IDENTIFIER = Position(
    "sql:identifier",
    frozenset({ALLOWLIST, NUMERIC_CAST}),
    "a table, column or ORDER BY target; parameter binding cannot express this position and escaping does not apply",
    structural=True,
)
SQL_STATEMENT = Position(
    "sql:statement",
    frozenset({REJECT}),
    "statement position; the value can introduce an entire additional statement",
    structural=True,
)

#: Marker choice here is load-bearing and was got wrong once. This grammar
#: nests the whole query under `from`, so `from` appears in the chain of every
#: hole in a SELECT -- using it as a structural marker classified ordinary
#: comparison operands as identifiers. Markers must name the *tightest*
#: enclosing construct, never an ancestor that wraps unrelated positions.
#:
#: `literal` is checked before the structural clauses because quoting is the
#: tighter context: `ORDER BY 'x'` is inside a literal despite the clause.
SQL_RULES = (
    Rule(("literal", "string_literal"), SQL_LITERAL),
    Rule(
        (
            "order_target", "order_by", "group_by",
            "relation", "object_reference", "table_reference",
            "select_expression",
        ),
        SQL_IDENTIFIER,
    ),
    Rule(("binary_expression", "field", "identifier", "term", "list"), SQL_UNQUOTED),
    Rule(("statement", "program"), SQL_STATEMENT),
)

SHELL_COMMAND = Position(
    "shell:command-name",
    frozenset({ALLOWLIST}),
    "the command name itself; the value chooses which program runs",
    structural=True,
)
SHELL_BARE = Position(
    "shell:unquoted-argument",
    frozenset({SHELL_QUOTE, ARGV_ARRAY, NUMERIC_CAST}),
    "an unquoted word; ';', '|', '$()' and whitespace all break out",
)
SHELL_DOUBLE = Position(
    "shell:double-quoted",
    frozenset({SHELL_QUOTE, ARGV_ARRAY, NUMERIC_CAST}),
    "inside double quotes, which still expand $(...) and backticks",
)
SHELL_SINGLE = Position(
    "shell:single-quoted",
    frozenset({SHELL_QUOTE, ARGV_ARRAY, NUMERIC_CAST}),
    "inside single quotes; only an embedded quote breaks out",
)

SHELL_RULES = (
    Rule(("command_name",), SHELL_COMMAND),
    Rule(("raw_string",), SHELL_SINGLE),
    Rule(("string_content", "string"), SHELL_DOUBLE),
    Rule(("word", "concatenation"), SHELL_BARE),
)

HTML_SCRIPT = Position(
    "html:script-body",
    frozenset({JS_STRING_ESCAPE}),
    "inside a <script> block, so the value is JavaScript; HTML escaping is the wrong encoding here",
    structural=True,
)
HTML_STYLE = Position(
    "html:style-body",
    frozenset({CSS_ESCAPE}),
    "inside a <style> block; HTML escaping does not apply to CSS",
    structural=True,
)
HTML_ATTR_NAME = Position(
    "html:attribute-name",
    frozenset({ALLOWLIST}),
    "the attribute name; the value can introduce an event handler such as onerror",
    structural=True,
)
HTML_URL_ATTR = Position(
    "html:url-attribute",
    frozenset({URL_SCHEME_CHECK}),
    "a URL attribute; escaping permits javascript: and data: schemes",
    structural=True,
)
HTML_ATTR_VALUE = Position(
    "html:attribute-value",
    frozenset({HTML_ATTR_ESCAPE}),
    "a quoted attribute value; escaping the quote and angle brackets closes it",
)
HTML_TEXT = Position(
    "html:text",
    frozenset({HTML_TEXT_ESCAPE}),
    "element text; escaping angle brackets and ampersands closes it",
)

HTML_RULES = (
    Rule(("script_element",), HTML_SCRIPT),
    Rule(("style_element",), HTML_STYLE),
    Rule(("attribute_name",), HTML_ATTR_NAME),
    Rule(("attribute_value", "quoted_attribute_value"), HTML_ATTR_VALUE),
    Rule(("text", "raw_text"), HTML_TEXT),
)

#: Attributes whose value is fetched or navigated to, where escaping is not the
#: defence. Applied on top of the generic attribute-value rule.
URL_ATTRIBUTES = frozenset({"href", "src", "action", "formaction", "data", "poster", "srcdoc", "xlink:href"})


@dataclass(frozen=True)
class Consumer:
    name: str
    grammar: str
    rules: Tuple[Rule, ...]
    #: Wrapper text needed to make a fragment parse on its own.
    prefix: str = ""
    suffix: str = ""


CONSUMERS: Dict[str, Consumer] = {
    "sql": Consumer("sql", "sql", SQL_RULES),
    "shell": Consumer("shell", "bash", SHELL_RULES),
    "html": Consumer("html", "html", HTML_RULES),
}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@dataclass
class Hole:
    index: int
    position: Position
    chain: Tuple[str, ...]

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "position": self.position.name,
            "structural": self.position.structural,
            "accepts": sorted(self.position.accepts),
            "rationale": self.position.rationale,
            "grammar_path": list(self.chain),
        }


@dataclass
class BoundaryAnalysis:
    """Where each runtime value lands in the consumed language."""

    consumer: str
    template: str
    holes: List[Hole] = field(default_factory=list)
    #: Set when the template parsed but contained no holes at all -- the value
    #: never reaches the consumer as syntax, which is a proof of safety rather
    #: than an absence of evidence.
    no_holes: bool = False

    @property
    def structural(self) -> bool:
        return any(hole.position.structural for hole in self.holes)

    def to_dict(self) -> Dict:
        return {
            "consumer": self.consumer,
            "template": self.template[:400],
            "no_holes": self.no_holes,
            "structural": self.structural,
            "holes": [hole.to_dict() for hole in self.holes],
        }


@functools.lru_cache(maxsize=32)
def _parser(grammar: str):
    from tree_sitter_language_pack import get_parser

    return get_parser(grammar)


def analyse(template: str, consumer_name: str) -> Optional[BoundaryAnalysis]:
    """Classify every hole in ``template`` against ``consumer_name``'s grammar.

    ``template`` is the string the host language builds, with runtime values
    replaced by :func:`hole_token`. Returns ``None`` when the consumer is
    unknown or its grammar is unavailable, so callers degrade to plain taint
    reasoning rather than losing the finding.
    """
    consumer = CONSUMERS.get(consumer_name)
    if consumer is None or not template:
        return None
    try:
        parser = _parser(consumer.grammar)
    except Exception:
        return None

    text = f"{consumer.prefix}{template}{consumer.suffix}"
    try:
        tree = parser.parse(text.encode("utf-8"))
    except Exception:
        return None

    analysis = BoundaryAnalysis(consumer=consumer_name, template=template)
    offsets = _hole_offsets(text)
    if not offsets:
        analysis.no_holes = True
        return analysis

    for index, offset in offsets:
        chain = _chain(tree.root_node, offset)
        if not chain:
            continue
        position = _classify(chain, consumer, text, offset)
        if position is not None:
            analysis.holes.append(Hole(index=index, position=position, chain=chain))
    return analysis


def _hole_offsets(text: str) -> List[Tuple[int, int]]:
    offsets: List[Tuple[int, int]] = []
    start = 0
    while True:
        found = text.find(HOLE_PREFIX, start)
        if found < 0:
            return offsets
        digits = ""
        cursor = found + len(HOLE_PREFIX)
        while cursor < len(text) and text[cursor].isdigit():
            digits += text[cursor]
            cursor += 1
        offsets.append((int(digits) if digits else 0, found))
        start = cursor


def _chain(root, offset: int) -> Tuple[str, ...]:
    """Node types from the root down to the leaf containing ``offset``."""
    chain: List[str] = []
    node = root
    while True:
        child = next(
            (c for c in node.children if c.start_byte <= offset < c.end_byte), None
        )
        if child is None:
            break
        node = child
        chain.append(node.type)
        if len(chain) > 40:
            break
    return tuple(chain)


def _classify(chain: Tuple[str, ...], consumer: Consumer, text: str, offset: int) -> Optional[Position]:
    for rule in consumer.rules:
        if not any(marker in chain for marker in rule.markers):
            continue
        # A URL attribute is still an attribute value grammatically, but
        # escaping does not stop `javascript:`, so the attribute name decides.
        if rule.position is HTML_ATTR_VALUE and _attribute_name(text, offset) in URL_ATTRIBUTES:
            return HTML_URL_ATTR
        return rule.position
    return None


def _attribute_name(text: str, offset: int) -> str:
    """The attribute whose value contains ``offset``, lowercased."""
    head = text[:offset]
    equals = head.rfind("=")
    if equals < 0:
        return ""
    name = head[:equals].strip().rsplit(None, 1)
    return name[-1].lower().strip("\"'") if name else ""


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

SAFE = "SAFE"
MISMATCH = "MISMATCH"
UNDEFENDED = "UNDEFENDED"
UNKNOWN = "UNKNOWN"


@dataclass
class Verdict:
    outcome: str
    hole: Optional[Hole]
    applied: Tuple[str, ...]
    detail: str

    def to_dict(self) -> Dict:
        return {
            "outcome": self.outcome,
            "position": self.hole.position.name if self.hole else None,
            "structural": self.hole.position.structural if self.hole else False,
            "required_one_of": sorted(self.hole.position.accepts) if self.hole else [],
            "applied": list(self.applied),
            "detail": self.detail,
        }


def capabilities_of(sanitizers: Sequence[str]) -> Tuple[FrozenSet[str], Tuple[str, ...]]:
    """Split applied sanitiser names into known capabilities and unknown names."""
    known: set = set()
    unknown: List[str] = []
    for name in sanitizers:
        lowered = str(name).lower().strip()
        matched = None
        for candidate, capability in DEFENCE_CAPABILITIES.items():
            if candidate == lowered or lowered.endswith("." + candidate) or candidate in lowered:
                matched = capability
                break
        if matched:
            known |= matched
        elif lowered:
            unknown.append(lowered)
    return frozenset(known), tuple(unknown)


def judge(analysis: BoundaryAnalysis, sanitizers: Sequence[str]) -> Verdict:
    """Compare the defences applied against the ones the position requires.

    The interesting outcome is ``MISMATCH``: a defence *was* applied and it is
    the wrong kind for where the value lands. `html.escape` on a value that
    ends up inside a `<script>` block is the canonical case, and both a taint
    engine and a reviewer skimming the diff will call it defended.
    """
    applied, unknown = capabilities_of(sanitizers)
    if analysis.no_holes:
        return Verdict(SAFE, None, tuple(sorted(applied)),
                       "no runtime value reaches the consumed language as syntax")
    if not analysis.holes:
        return Verdict(UNKNOWN, None, tuple(sorted(applied)),
                       "the value's position in the consumed language could not be determined")

    # Report the worst hole: structural first, then undefended.
    worst = max(
        analysis.holes,
        key=lambda hole: (hole.position.structural, not (hole.position.accepts & applied)),
    )
    if worst.position.accepts & applied:
        return Verdict(SAFE, worst, tuple(sorted(applied)),
                       f"{worst.position.name} is defended by {sorted(worst.position.accepts & applied)}")
    if applied:
        return Verdict(
            MISMATCH, worst, tuple(sorted(applied)),
            f"applied {sorted(applied)} but {worst.position.name} requires one of "
            f"{sorted(worst.position.accepts)} -- {worst.position.rationale}",
        )
    if unknown:
        return Verdict(UNKNOWN, worst, tuple(unknown),
                       f"{', '.join(unknown)} is not a recognised defence, so its effect here is unknown")
    return Verdict(UNDEFENDED, worst, (),
                   f"{worst.position.name}: {worst.position.rationale}")
