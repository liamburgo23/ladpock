"""Just enough JavaScript/TypeScript structure for the checks that need it.

This is not a parser. It strips comments, matches brackets and splits call
arguments while skipping over string literals, which is what the route matrix
and React checks need. Offsets are preserved so line numbers stay correct.

Rust code passes quotes='"', because a single quote there usually starts a
lifetime ('_, 'a) rather than a string.
"""

from __future__ import annotations

_PAIRS = {"(": ")", "{": "}", "[": "]"}
_QUOTES = "'\"`"


def strip_comments(code: str, quotes: str = _QUOTES) -> str:
    out: list[str] = []
    i, n = 0, len(code)
    state: str | None = None
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "//"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "/*"
                out.append("  ")
                i += 2
                continue
            if c in quotes:
                state = c
            out.append(c)
            i += 1
            continue
        if state == "//":
            if c == "\n":
                state = None
                out.append(c)
            else:
                out.append(" ")
            i += 1
            continue
        if state == "/*":
            if c == "*" and nxt == "/":
                state = None
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if c == "\\":
            out.append(code[i : i + 2])
            i += 2
            continue
        # JS strings can't span lines, so recover from an unterminated one; Rust strings can.
        if c == state or (c == "\n" and state in "'\"" and "'" in quotes):
            state = None
        out.append(c)
        i += 1
    return "".join(out)


def match_bracket(code: str, open_idx: int, quotes: str = _QUOTES) -> int:
    """Index of the bracket closing the one at ``open_idx``, or -1."""
    stack: list[str] = []
    i, n = open_idx, len(code)
    state: str | None = None
    while i < n:
        c = code[i]
        if state:
            if c == "\\":
                i += 2
                continue
            if c == state:
                state = None
            i += 1
            continue
        if c in quotes:
            state = c
        elif c in _PAIRS:
            stack.append(_PAIRS[c])
        elif c in ")}]":
            if not stack or stack.pop() != c:
                return -1
            if not stack:
                return i
        i += 1
    return -1


def split_args(code: str, open_idx: int, close_idx: int, quotes: str = _QUOTES) -> list[str]:
    """Top-level comma-separated arguments between a pair of brackets."""
    args: list[str] = []
    depth = 0
    state: str | None = None
    start = open_idx + 1
    i = start
    while i < close_idx:
        c = code[i]
        if state:
            if c == "\\":
                i += 2
                continue
            if c == state:
                state = None
        elif c in quotes:
            state = c
        elif c in _PAIRS:
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif c == "," and depth == 0:
            args.append(code[start:i])
            start = i + 1
        i += 1
    tail = code[start:close_idx]
    if tail.strip():
        args.append(tail)
    return args


def line_of(code: str, idx: int) -> int:
    return code.count("\n", 0, idx) + 1
