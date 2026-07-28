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
from typing import Callable, Dict, FrozenSet, List, Optional, Sequence, Tuple

#: Token substituted for a runtime value. Must survive tokenisation as a plain
#: identifier in every consumer grammar, so no punctuation and no keywords.
HOLE_PREFIX = "ROOTAIHOLE"


def hole_token(index: int) -> str:
    return f"{HOLE_PREFIX}{index}"


@dataclass
class StringTemplate:
    """What the host language builds, split into fixed text and runtime values.

    ``"SELECT * FROM t WHERE n = '" + name + "'"`` becomes three segments: two
    literals and one hole. Rendering substitutes a probe token for each hole so
    the consumer's grammar can be asked where that value lands.

    ``complete`` is false when reconstruction gave up part way -- a helper call
    it could not follow, a loop-built string, a format it does not model. The
    template is still worth analysing (an incomplete prefix often pins the
    position exactly), but a *safe* verdict from an incomplete template is not
    trustworthy and callers must not act on one.
    """

    #: ``("lit", text)`` or ``("hole", source expression)``, in order.
    segments: List[Tuple[str, str]] = field(default_factory=list)
    complete: bool = True

    def add_literal(self, text: str) -> None:
        if not text:
            return
        if self.segments and self.segments[-1][0] == "lit":
            kind, previous = self.segments[-1]
            self.segments[-1] = (kind, previous + text)
        else:
            self.segments.append(("lit", text))

    def add_hole(self, expression: str) -> None:
        self.segments.append(("hole", expression))

    @property
    def hole_expressions(self) -> List[str]:
        return [text for kind, text in self.segments if kind == "hole"]

    def render(self) -> str:
        parts: List[str] = []
        index = 0
        for kind, text in self.segments:
            if kind == "lit":
                parts.append(text)
            else:
                parts.append(hole_token(index))
                index += 1
        return "".join(parts)

    def to_dict(self) -> Dict:
        # `hole_expressions`, not `holes`: the analysis emits `holes` as
        # classified positions, and merging the two dicts silently replaced
        # them with bare source strings.
        return {
            "template": self.render()[:400],
            "complete": self.complete,
            "hole_expressions": self.hole_expressions[:12],
        }


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
XPATH_ESCAPE = "xpath-escape"
LDAP_ESCAPE = "ldap-escape"
REGEX_ESCAPE = "regex-escape"
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
    # XPath and LDAP encoders. XPath 1.0 has no way to escape a quote inside a
    # string literal, so ESAPI's encodeForXPath is the only escaping defence and
    # variable binding is the robust one.
    "encodeforxpath": frozenset({XPATH_ESCAPE}),
    "encodeforldap": frozenset({LDAP_ESCAPE}),
    "encodefordn": frozenset({LDAP_ESCAPE}),
    "ldap_escape": frozenset({LDAP_ESCAPE}),
    "escapeldapsearchfilter": frozenset({LDAP_ESCAPE}),
    # Regex-literal escaping: a value escaped this way matches literally and
    # cannot alter the pattern's structure.
    "re.escape": frozenset({REGEX_ESCAPE}),
    "regexp.escape": frozenset({REGEX_ESCAPE}),
    "pattern.quote": frozenset({REGEX_ESCAPE}),
    "escaperegexp": frozenset({REGEX_ESCAPE}),
    "quotemeta": frozenset({REGEX_ESCAPE}),
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


# ---------------------------------------------------------------------------
# XPath and LDAP -- no tree-sitter grammar, so classified by a focused scan.
#
# Both languages are regular enough that a character-level scan of the template
# up to each hole identifies its position reliably. The same principle holds as
# for SQL: a value inside a string literal needs escaping; a value in a
# structural slot (a node name, a filter attribute, an operator) cannot be
# defended by escaping at all.
# ---------------------------------------------------------------------------

XPATH_STRING = Position(
    "xpath:string-literal",
    frozenset({XPATH_ESCAPE, PARAMETERISE, NUMERIC_CAST}),
    "inside an XPath string literal; XPath 1.0 cannot escape the quote, so variable binding is the robust fix",
)
XPATH_EXPRESSION = Position(
    "xpath:expression",
    frozenset({PARAMETERISE, NUMERIC_CAST, ALLOWLIST}),
    "an XPath expression or predicate operand outside any string; escaping does not apply",
    structural=True,
)
XPATH_NODE = Position(
    "xpath:node-name",
    frozenset({ALLOWLIST, NUMERIC_CAST}),
    "a node or axis name; the value selects which nodes are addressed and no escaping constrains it",
    structural=True,
)

LDAP_VALUE = Position(
    "ldap:filter-value",
    frozenset({LDAP_ESCAPE, NUMERIC_CAST}),
    "an LDAP assertion value; escaping '*()\\\\' and NUL closes it",
)
LDAP_STRUCTURE = Position(
    "ldap:filter-structure",
    frozenset({ALLOWLIST, NUMERIC_CAST}),
    "an LDAP attribute name or filter operator; the value alters the filter itself, which escaping cannot stop",
    structural=True,
)


def _classify_xpath(text: str, offset: int) -> Position:
    """Position of a hole in an XPath expression, by scanning up to ``offset``.

    Tracks quote state and predicate depth in one pass. Inside a string literal
    the value needs escaping/binding; inside a predicate but outside a string it
    is an expression operand; a value adjacent to ``/`` or ``@`` selects a node
    name.
    """
    quote = None
    depth = 0
    for char in text[:offset]:
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
    if quote:
        return XPATH_STRING
    # A node-name position is one written straight after a path or axis step
    # with no comparison in between. Look at the character before the hole.
    before = text[:offset].rstrip()
    if before.endswith("/") or before.endswith("@") or before.endswith("::"):
        return XPATH_NODE
    if depth > 0:
        return XPATH_EXPRESSION
    return XPATH_NODE


def _classify_ldap(text: str, offset: int) -> Position:
    """Position of a hole in an LDAP filter, by scanning up to ``offset``.

    An LDAP filter is ``(attr op value)``. Within the innermost open paren, a
    hole after a comparison operator is a value; a hole before any operator is
    the attribute name; a hole not inside a paren at all is filter structure.
    All but the value position are structural.
    """
    # Find the start of the innermost unclosed group before the hole.
    depth = 0
    group_start = None
    for index, char in enumerate(text[:offset]):
        if char == "(":
            depth += 1
            group_start = index
        elif char == ")":
            depth -= 1
            group_start = None
    if group_start is None:
        return LDAP_STRUCTURE
    segment = text[group_start + 1 : offset]
    # A logical group `(&`, `(|`, `(!` contains sub-filters, not a value.
    if segment[:1] in "&|!":
        return LDAP_STRUCTURE
    if any(op in segment for op in ("=", "~=", ">=", "<=", "<", ">")):
        return LDAP_VALUE
    return LDAP_STRUCTURE


# ---------------------------------------------------------------------------
# Regex, format strings, template bodies -- consumers where the interesting
# question is not "which slot" but "should attacker input reach this at all".
# ---------------------------------------------------------------------------

REGEX_PATTERN = Position(
    "regex:pattern",
    frozenset({REGEX_ESCAPE, NUMERIC_CAST}),
    "interpolated into a regex; unescaped metacharacters change what it matches (regex injection)",
)
REGEX_QUANTIFIER = Position(
    "regex:quantifier",
    frozenset({NUMERIC_CAST, REJECT}),
    "a repetition count in a regex; a crafted value triggers catastrophic backtracking (ReDoS) that escaping cannot prevent",
    structural=True,
)

FORMAT_STRING = Position(
    "format:format-string",
    frozenset({REJECT, NUMERIC_CAST}),
    "the format string itself; %n and %x let the value read or write memory. Use a constant format string and pass the value as an argument",
    structural=True,
)

TEMPLATE_BODY = Position(
    "template:template-body",
    frozenset({REJECT}),
    "the template source; template syntax in the value is evaluated (server-side template injection -> RCE). Pass the value as a context variable, never into the template text",
    structural=True,
)


def _classify_regex(text: str, offset: int) -> Position:
    """Position of a hole in a regex pattern.

    A value inside a `{...}` quantifier controls repetition and is a ReDoS
    vector no escaping fixes; anywhere else the value is pattern text, made
    literal by regex escaping.
    """
    depth_brace = 0
    for char in text[:offset]:
        if char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace = max(0, depth_brace - 1)
    if depth_brace > 0:
        return REGEX_QUANTIFIER
    return REGEX_PATTERN


def _classify_format(text: str, offset: int) -> Position:
    """Any value reaching the format-string argument is the vulnerability.

    There is no safe position *within* a format string for attacker input; the
    format string must be a constant. The scan is unused -- the position is the
    same wherever the hole falls -- but the signature matches the others.
    """
    del text, offset
    return FORMAT_STRING


def _classify_template(text: str, offset: int) -> Position:
    """Any value reaching the template body is server-side template injection."""
    del text, offset
    return TEMPLATE_BODY


@dataclass(frozen=True)
class Consumer:
    name: str
    #: tree-sitter grammar name, or "" for a hand-written classifier.
    grammar: str
    rules: Tuple[Rule, ...] = ()
    #: Wrapper text needed to make a fragment parse on its own.
    prefix: str = ""
    suffix: str = ""
    #: ``(text, hole offset) -> Position`` for languages with no tree-sitter
    #: grammar. When set, it is used instead of grammar parsing.
    classify: Optional[Callable[[str, int], "Position"]] = None


CONSUMERS: Dict[str, Consumer] = {
    "sql": Consumer("sql", "sql", SQL_RULES),
    "shell": Consumer("shell", "bash", SHELL_RULES),
    "html": Consumer("html", "html", HTML_RULES),
    "xpath": Consumer("xpath", "", classify=_classify_xpath),
    "ldap": Consumer("ldap", "", classify=_classify_ldap),
    "regex": Consumer("regex", "", classify=_classify_regex),
    "format": Consumer("format", "", classify=_classify_format),
    "template": Consumer("template", "", classify=_classify_template),
}

#: Consumers where a bare tainted value -- a single hole with no surrounding
#: syntax -- is itself the finding, rather than an unanalysable expression.
#: `printf(userInput)`, `render_template_string(userInput)` and
#: `re.compile(userInput)` are the vulnerability precisely because the value is
#: the whole thing. For grammar consumers a lone hole carries no context and is
#: skipped, but here there is nothing to skip -- the value *is* the format
#: string / template / pattern.
WHOLE_VALUE_CONSUMERS = frozenset({"format", "template", "regex"})


# ---------------------------------------------------------------------------
# Which grammar consumes which sink
# ---------------------------------------------------------------------------

#: Sink name fragment -> the language that parses its argument.
#:
#: This is the piece a flat sink list cannot express. `executeQuery` and
#: `execSync` are both "dangerous", but one hands its argument to a SQL parser
#: and the other to a shell, and the defence that works for one is inert for
#: the other. Matching is on lowercased segments of the callee expression, so
#: `connection.prepareStatement` and `db.sequelize.query` both resolve.
#:
#: The second element is which argument is consumed. It is not always the
#: first: `mysqli_query($link, $sql)` and `pg_query($conn, $sql)` take the
#: connection first, and reading position 0 there analyses the handle instead
#: of the query.
SINK_CONSUMERS: Dict[str, Tuple[str, int]] = {
    # SQL
    "executequery": ("sql", 0), "executeupdate": ("sql", 0), "preparestatement": ("sql", 0),
    "createquery": ("sql", 0), "rawquery": ("sql", 0), "nativequery": ("sql", 0),
    "cursor.execute": ("sql", 0), "cur.execute": ("sql", 0), "conn.execute": ("sql", 0),
    "connection.execute": ("sql", 0), "session.execute": ("sql", 0),
    "stmt.execute": ("sql", 0), "statement.execute": ("sql", 0),
    "executescript": ("sql", 0), "executemany": ("sql", 0),
    "db.query": ("sql", 0), "db.exec": ("sql", 0), "sequelize.query": ("sql", 0),
    "knex.raw": ("sql", 0), "mysqli_query": ("sql", 1), "pg_query": ("sql", 1),
    "sqlx::query": ("sql", 0), "sqlcommand": ("sql", 0),
    # Shell
    "os.system": ("shell", 0), "subprocess.run": ("shell", 0), "subprocess.call": ("shell", 0),
    "popen": ("shell", 0), "execsync": ("shell", 0), "spawnsync": ("shell", 0),
    "child_process.exec": ("shell", 0), "shell_exec": ("shell", 0), "proc_open": ("shell", 0),
    "system": ("shell", 0), "runtime.exec": ("shell", 0), "processbuilder": ("shell", 0),
    "os.execute": ("shell", 0), "io.popen": ("shell", 0), "kernel.system": ("shell", 0),
    "invoke-expression": ("shell", 0), "process.start": ("shell", 0),
    # HTML
    "innerhtml": ("html", 0), "outerhtml": ("html", 0), "insertadjacenthtml": ("html", 0),
    "document.write": ("html", 0), "dangerouslysetinnerhtml": ("html", 0),
    "getwriter.println": ("html", 0), "getwriter.write": ("html", 0), "getwriter.print": ("html", 0),
    "res.send": ("html", 0), "res.write": ("html", 0), "render_template_string": ("html", 0),
    # XPath -- the expression is the first argument to evaluate/compile.
    "xpath.evaluate": ("xpath", 0), "xp.evaluate": ("xpath", 0),
    "xpathexpression.evaluate": ("xpath", 0), "xpath.compile": ("xpath", 0),
    "selectnodes": ("xpath", 0), "selectsinglenode": ("xpath", 0),
    # LDAP -- Java's DirContext.search takes the filter as its second argument;
    # PHP's ldap_search takes it third.
    "dircontext.search": ("ldap", 1), "initialdircontext.search": ("ldap", 1),
    "ldapcontext.search": ("ldap", 1), "idc.search": ("ldap", 1), "ctx.search": ("ldap", 1),
    "ldap_search": ("ldap", 2), "ldap_list": ("ldap", 2),
    # Regex -- the pattern is the first argument to compile/match/search/sub.
    "re.compile": ("regex", 0), "re.match": ("regex", 0), "re.search": ("regex", 0),
    "re.findall": ("regex", 0), "re.finditer": ("regex", 0), "re.fullmatch": ("regex", 0),
    "re.sub": ("regex", 0), "re.split": ("regex", 0),
    "pattern.compile": ("regex", 0),
    # Format strings -- the format argument's index varies by function. A
    # tainted value there is a format-string vulnerability; tainted *arguments*
    # after it are not, which is why the index matters.
    "printf": ("format", 0), "vprintf": ("format", 0),
    "fprintf": ("format", 1), "vfprintf": ("format", 1),
    "sprintf": ("format", 1), "vsprintf": ("format", 1),
    "snprintf": ("format", 2), "vsnprintf": ("format", 2),
    "syslog": ("format", 1),
    # Java/Python string formatting is deliberately absent: neither exposes the
    # %n write primitive that makes C format strings a memory-corruption sink,
    # so a tainted format there is not the same vulnerability class.
    # Server-side templates -- the template body is the first argument.
    "render_template_string": ("template", 0), "handlebars.compile": ("template", 0),
    "ejs.render": ("template", 0), "pug.compile": ("template", 0),
    "jinja2.template": ("template", 0), "twig.render": ("template", 0),
}

#: Sinks whose argument is not parsed as another language at all. Recorded so
#: an unmapped sink is a known gap rather than an oversight.
UNMAPPED_SINKS: Dict[str, str] = {
    "pickle.loads": "deserialization; the payload is an object graph, not a grammar this models",
    "yaml.load": "deserialization; same",
    "eval": "the host language parses it; a host-grammar consumer, not yet modelled",
    "strcpy": "memory safety, not a parser boundary",
    "fs.readfile": "path resolution; needs a path-normalisation model rather than a grammar",
    "urlopen": "URL parsing; belongs with the differential analysis layer",
}


def consumer_for(sink_label: str) -> Optional[Tuple[str, int]]:
    """``(consumer, argument index)`` for ``sink_label``, if it is one we model.

    Longest match wins, so `child_process.exec` beats a bare `exec` and
    `getWriter.println` is not confused with an arbitrary `println`.
    """
    # Method-chain sinks are written `response.getWriter().println`, so the
    # empty argument list has to come out before fragment matching or
    # `getwriter.println` never matches.
    lowered = str(sink_label).lower().replace("()", "")
    best: Optional[Tuple[str, int]] = None
    best_length = 0
    for fragment, mapping in SINK_CONSUMERS.items():
        if fragment in lowered and len(fragment) > best_length:
            best, best_length = mapping, len(fragment)
    return best


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

    text = f"{consumer.prefix}{template}{consumer.suffix}"
    analysis = BoundaryAnalysis(consumer=consumer_name, template=template)
    offsets = _hole_offsets(text)
    if not offsets:
        analysis.no_holes = True
        return analysis

    if consumer.classify is not None:
        # Hand-written consumer: XPath, LDAP -- no tree-sitter grammar exists,
        # so each hole is classified by a focused scan rather than a parse tree.
        for index, offset in offsets:
            position = consumer.classify(text, offset)
            analysis.holes.append(Hole(index=index, position=position, chain=(consumer_name,)))
        return analysis

    try:
        parser = _parser(consumer.grammar)
    except Exception:
        return None
    try:
        tree = parser.parse(text.encode("utf-8"))
    except Exception:
        return None

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


def judge(
    analysis: BoundaryAnalysis,
    sanitizers: Sequence[str],
    extra_capabilities: FrozenSet[str] = frozenset(),
) -> Verdict:
    """Compare the defences applied against the ones the position requires.

    The interesting outcome is ``MISMATCH``: a defence *was* applied and it is
    the wrong kind for where the value lands. `html.escape` on a value that
    ends up inside a `<script>` block is the canonical case, and both a taint
    engine and a reviewer skimming the diff will call it defended.

    ``extra_capabilities`` are defences established by something other than a
    named call on the path -- most importantly a validation guard. An allowlist
    check (`if (!ALLOWED.includes(sort)) return;`) is the *only* thing that
    defends a structural position, but it is a control-flow construct, not a
    sanitiser call, so without this it would be invisible here and a guarded
    ORDER BY would be reported as undefended.
    """
    applied, unknown = capabilities_of(sanitizers)
    applied = applied | extra_capabilities
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
    if worst.position.structural:
        # No escaping defends a structural position -- only an allowlist, a
        # numeric cast, or rejection. An unrecognised wrapper is not evidence of
        # any of those, so it does not earn the benefit of the doubt an escaper
        # would at a quotable position: the honest verdict is that no applicable
        # defence was found, not that the wrapper's effect is unknown.
        detail = f"{worst.position.name}: {worst.position.rationale}"
        if unknown:
            detail += (
                f" -- an unrecognised wrapper ({', '.join(unknown)}) is present, but no "
                f"escaper can defend this position"
            )
        return Verdict(UNDEFENDED, worst, tuple(unknown), detail)
    if unknown:
        return Verdict(UNKNOWN, worst, tuple(unknown),
                       f"{', '.join(unknown)} is not a recognised defence, so its effect here is unknown")
    return Verdict(UNDEFENDED, worst, (),
                   f"{worst.position.name}: {worst.position.rationale}")
