"""Compile-time constant evaluation over tree-sitter nodes.

A reachability-based taint engine reports any path the graph contains. That is
the right default and it is also why the largest single class of false
positives is code where the *graph* says a tainted value flows and *evaluation*
says it never does:

    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    char target = "ABC".charAt(1);
    switch (target) { case 'A': bar = param; break;
                      case 'B': bar = "bob";  break; }

Both assign a constant, always. Scoring against OWASP Benchmark measured 58 of
95 false positives as this shape. No amount of sink or source tuning touches
them, because the flow is real right up until you evaluate the condition.

This module answers one question -- "is this expression a compile-time
constant, and if so what is it?" -- so the parsers can decline to walk branches
that provably do not execute.

Deliberately conservative. Anything not understood evaluates to :data:`UNKNOWN`
and the caller behaves exactly as it did before, so a gap in the folder costs
precision, never recall. It is driven by node-type *shape* rather than a table
per language, because the arithmetic is the same everywhere and only the
grammar's spelling differs.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, FrozenSet, Optional

#: Returned when an expression is not a compile-time constant. A distinct
#: sentinel rather than ``None``, because ``null`` is itself a constant some
#: languages compare against.
UNKNOWN = object()

#: Numeric literal suffixes and separators: `106L`, `0x2A`, `1_000`, `3.0f`.
_INT_PATTERN = re.compile(r"^[+-]?(0[xX][0-9a-fA-F_]+|0[bB][01_]+|[0-9][0-9_]*)[lLuU]*$")
_FLOAT_PATTERN = re.compile(r"^[+-]?[0-9][0-9_]*\.[0-9_]*([eE][+-]?[0-9]+)?[fFdD]?$")

#: String methods that are pure and total on constant inputs. Restricted on
#: purpose: a method not listed here makes the whole expression UNKNOWN, which
#: is the safe answer.
_STRING_METHODS = {
    "charat", "length", "touppercase", "tolowercase", "trim", "substring",
    "equals", "equalsignorecase", "indexof", "contains", "startswith",
    "endswith", "isempty", "concat", "tostring", "replace",
}

#: `$name` and `$name[key]` -- PHP, shell and Perl interpolate without braces.
_UNBRACED_INTERPOLATION = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")

_TRUE_TOKENS = frozenset({"true", "True", "TRUE"})
_FALSE_TOKENS = frozenset({"false", "False", "FALSE"})


class ConstantFolder:
    """Evaluates expressions that do not depend on runtime input.

    ``get_text`` is the parser's own byte-correct text extractor; ``literals``
    is the profile's literal node set, used to recognise a leaf value before
    falling back to shape matching on the type name.
    """

    def __init__(self, literals: FrozenSet[str], get_text: Callable[[str, Any], str]) -> None:
        self._literals = literals
        self._get_text = get_text

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def value(self, node, src: str, env: Optional[Dict[str, Any]] = None) -> Any:
        """Evaluate ``node``, or return :data:`UNKNOWN`."""
        try:
            return self._value(node, src, env or {}, depth=0)
        except (ArithmeticError, ValueError, TypeError, IndexError, AttributeError):
            # A constant expression that raises is not one this analysis should
            # be reasoning about, and it must never take the scan down with it.
            return UNKNOWN

    def truth(self, node, src: str, env: Optional[Dict[str, Any]] = None) -> Optional[bool]:
        """Whether ``node`` is provably true or provably false; ``None`` if neither."""
        result = self.value(node, src, env)
        if result is UNKNOWN:
            return None
        if isinstance(result, bool):
            return result
        if isinstance(result, (int, float)):
            return bool(result)
        return None

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def _value(self, node, src: str, env: Dict[str, Any], depth: int) -> Any:
        if node is None or depth > 24:
            return UNKNOWN

        node_type = node.type
        children = [c for c in node.children if c.is_named or self._is_operator(c, src)]

        # Wrappers that contribute nothing of their own.
        if "parenthesized" in node_type or node_type in {"expression_statement", "argument"}:
            named = [c for c in node.children if c.is_named]
            return self._value(named[0], src, env, depth + 1) if len(named) == 1 else UNKNOWN

        if node_type in self._literals or node_type.endswith("_literal"):
            return self._literal(node, src)

        if node_type in _TRUE_TOKENS | _FALSE_TOKENS:
            return node_type in _TRUE_TOKENS

        if "ternary" in node_type or node_type in {"conditional_expression", "conditional"}:
            return self._ternary(node, src, env, depth)

        if node_type.endswith("unary_expression") or node_type == "unary_operator":
            return self._unary(node, src, env, depth)

        if node_type.endswith("binary_expression") or node_type in {"binary_operator", "comparison_operator"}:
            return self._binary(node, src, env, depth)

        if node_type in {"cast_expression"}:
            named = [c for c in node.children if c.is_named]
            return self._value(named[-1], src, env, depth + 1) if named else UNKNOWN

        if node_type in {"method_invocation", "call_expression", "call"}:
            return self._method(node, src, env, depth)

        if node_type in {"identifier", "simple_identifier", "variable_name", "name"}:
            return env.get(self._get_text(src, node).strip(), UNKNOWN)

        # A lone wrapper with one named child (`integral_type`, `_expression`).
        named = [c for c in node.children if c.is_named]
        if len(named) == 1 and not children[1:]:
            return self._value(named[0], src, env, depth + 1)

        return UNKNOWN

    def _literal(self, node, src: str) -> Any:
        text = self._get_text(src, node).strip()
        if not text:
            return UNKNOWN
        lowered = text.lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        if lowered in {"null", "nil", "none", "undefined"}:
            return None
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
            body = text[1:-1]
            # An interpolation makes the literal a runtime value, not a
            # constant. Single quotes interpolate in no language here, so they
            # are exempt; everything else is checked, including the *unbraced*
            # `$name` form. Missing that read PHP's "WHERE n = '$c'" as fixed
            # text and reported a template with no holes -- which the boundary
            # layer treats as proof of safety. A false constant here becomes a
            # false "not injectable" there, so this check has to be strict.
            if text[0] != "'" and (
                "${" in body
                or "$(" in body
                or _UNBRACED_INTERPOLATION.search(body)
                or ("{" in body and "}" in body)
            ):
                return UNKNOWN
            return self._unescape(body)
        if _INT_PATTERN.match(text):
            cleaned = text.rstrip("lLuU").replace("_", "")
            base = 16 if cleaned[:2].lower() == "0x" else 2 if cleaned[:2].lower() == "0b" else 10
            return int(cleaned, base)
        if _FLOAT_PATTERN.match(text):
            return float(text.rstrip("fFdD").replace("_", ""))
        return UNKNOWN

    @staticmethod
    def _unescape(body: str) -> str:
        for escape, literal in (("\\n", "\n"), ("\\t", "\t"), ("\\\\", "\\"), ('\\"', '"'), ("\\'", "'")):
            body = body.replace(escape, literal)
        return body

    def _ternary(self, node, src: str, env: Dict[str, Any], depth: int) -> Any:
        branches = self.ternary_branches(node, src, env)
        if branches is None:
            return UNKNOWN
        taken, _ = branches
        return self._value(taken, src, env, depth + 1)

    def ternary_branches(self, node, src: str, env: Optional[Dict[str, Any]] = None):
        """Return ``(taken, discarded)`` subtrees, or ``None`` if undecidable.

        Exposed separately from :meth:`value` because the taken branch is often
        *not* constant -- ``cond ? "safe" : param`` resolves to ``param`` when
        the condition is false, and the caller needs the subtree rather than a
        value it cannot compute.
        """
        named = [child for child in node.children if child.is_named]
        if len(named) != 3:
            return None
        condition, consequence, alternative = named
        verdict = self.truth(condition, src, env)
        if verdict is None:
            return None
        return (consequence, alternative) if verdict else (alternative, consequence)

    def _unary(self, node, src: str, env: Dict[str, Any], depth: int) -> Any:
        operator = ""
        operand = None
        for child in node.children:
            if child.is_named:
                operand = child
            elif not operator:
                operator = self._get_text(src, child).strip()
        if operand is None:
            return UNKNOWN
        value = self._value(operand, src, env, depth + 1)
        if value is UNKNOWN:
            return UNKNOWN
        if operator in {"!", "not"}:
            return not value
        if operator == "-":
            return -value
        if operator == "+":
            return +value
        if operator == "~":
            return ~value
        return UNKNOWN

    def _binary(self, node, src: str, env: Dict[str, Any], depth: int) -> Any:
        named = [child for child in node.children if child.is_named]
        operators = [child for child in node.children if not child.is_named]
        if len(named) != 2 or not operators:
            return UNKNOWN
        operator = self._get_text(src, operators[0]).strip()

        left = self._value(named[0], src, env, depth + 1)
        # Short-circuit before evaluating the right side, so `false && anything`
        # folds even when `anything` is a runtime value.
        if operator in {"&&", "and"} and left is not UNKNOWN and not left:
            return False
        if operator in {"||", "or"} and left is not UNKNOWN and left:
            return True
        right = self._value(named[1], src, env, depth + 1)
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        return self._apply(operator, left, right)

    @staticmethod
    def _apply(operator: str, left: Any, right: Any) -> Any:
        if operator == "+":
            if isinstance(left, str) or isinstance(right, str):
                return f"{left}{right}"
            return left + right
        if operator == "-":
            return left - right
        if operator == "*":
            return left * right
        if operator in {"/", "//"}:
            if right == 0:
                return UNKNOWN
            if isinstance(left, int) and isinstance(right, int):
                return int(left / right)  # C/Java integer division truncates toward zero
            return left / right
        if operator == "%":
            return UNKNOWN if right == 0 else left % right
        if operator in {"==", "===", "eq"}:
            return left == right
        if operator in {"!=", "!==", "<>"}:
            return left != right
        if operator == ">":
            return left > right
        if operator == "<":
            return left < right
        if operator == ">=":
            return left >= right
        if operator == "<=":
            return left <= right
        if operator in {"&&", "and"}:
            return bool(left and right)
        if operator in {"||", "or"}:
            return bool(left or right)
        if operator == "&":
            return left & right
        if operator == "|":
            return left | right
        if operator == "^":
            return left ^ right
        if operator == "<<":
            return left << right
        if operator == ">>":
            return left >> right
        return UNKNOWN

    def _method(self, node, src: str, env: Dict[str, Any], depth: int) -> Any:
        """Evaluate a pure string method on a constant receiver.

        Only reached for `"ABC".charAt(1)` and friends, which Benchmark uses to
        make a switch discriminant look computed while being fixed.
        """
        named = [child for child in node.children if child.is_named]
        if len(named) < 2:
            return UNKNOWN
        receiver = self._value(named[0], src, env, depth + 1)
        if receiver is UNKNOWN or not isinstance(receiver, str):
            return UNKNOWN

        method = ""
        arguments_node = None
        for child in named[1:]:
            if child.type in {"argument_list", "arguments"}:
                arguments_node = child
            else:
                method = self._get_text(src, child).strip().lower()
        if method not in _STRING_METHODS:
            return UNKNOWN

        arguments = []
        if arguments_node is not None:
            for child in arguments_node.children:
                if not child.is_named:
                    continue
                value = self._value(child, src, env, depth + 1)
                if value is UNKNOWN:
                    return UNKNOWN
                arguments.append(value)

        return self._string_method(receiver, method, arguments)

    @staticmethod
    def _string_method(receiver: str, method: str, arguments: list) -> Any:
        if method == "charat" and len(arguments) == 1:
            index = int(arguments[0])
            return receiver[index] if 0 <= index < len(receiver) else UNKNOWN
        if method == "length" and not arguments:
            return len(receiver)
        if method == "touppercase":
            return receiver.upper()
        if method == "tolowercase":
            return receiver.lower()
        if method == "trim":
            return receiver.strip()
        if method == "tostring":
            return receiver
        if method == "isempty":
            return not receiver
        if method == "substring":
            if len(arguments) == 1:
                return receiver[int(arguments[0]):]
            if len(arguments) == 2:
                return receiver[int(arguments[0]):int(arguments[1])]
            return UNKNOWN
        if method in {"equals", "equalsignorecase"} and len(arguments) == 1:
            other = str(arguments[0])
            return (
                receiver.lower() == other.lower()
                if method == "equalsignorecase"
                else receiver == other
            )
        if method == "indexof" and len(arguments) == 1:
            return receiver.find(str(arguments[0]))
        if method == "contains" and len(arguments) == 1:
            return str(arguments[0]) in receiver
        if method == "startswith" and len(arguments) == 1:
            return receiver.startswith(str(arguments[0]))
        if method == "endswith" and len(arguments) == 1:
            return receiver.endswith(str(arguments[0]))
        if method == "concat" and len(arguments) == 1:
            return receiver + str(arguments[0])
        if method == "replace" and len(arguments) == 2:
            return receiver.replace(str(arguments[0]), str(arguments[1]))
        return UNKNOWN

    def _is_operator(self, node, src: str) -> bool:
        return not node.is_named and bool(self._get_text(src, node).strip())
