"""Terminal output helpers (mirrors raiju/orochi style)."""

import sys

OK = "✓"
NO = "✗"
ARR = "→"


def _c(code: str, s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[{code}m{s}\033[0m"


green = lambda s: _c("32", s)
red = lambda s: _c("31", s)
yellow = lambda s: _c("33", s)
cyan = lambda s: _c("36", s)
dim = lambda s: _c("2", s)
bold = lambda s: _c("1", s)


def ok(s: str) -> str:
    return green(f"  {OK}  {s}")


def err(s: str) -> str:
    return red(f"  {NO}  {s}")


def info(s: str) -> str:
    return f"  {ARR}  {s}"


def warn(s: str) -> str:
    return yellow(f"  !  {s}")


def heading(s: str) -> str:
    return bold(cyan(s))


def table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    sep = "  "
    lines = [sep.join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append(sep.join("-" * w for w in widths))
    for row in rows:
        lines.append(
            sep.join(
                str(row[i]).ljust(widths[i]) if i < len(row) else ""
                for i in range(len(headers))
            )
        )
    return "\n".join(lines)
