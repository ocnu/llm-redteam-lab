#!/usr/bin/env python3
"""
Combine several garak `.report.jsonl` files into one, safely.

garak reports are line-delimited JSON. Naive concatenation (Windows `copy /b`,
for example) can glue the last line of one file to the first line of the next
when a trailing newline is missing, producing a line with two JSON objects on
it. This reads each file line by line and writes clean, newline-separated
output in UTF-8, so the result parses cleanly on any platform.

Usage:
    python3 combine_reports.py out.report.jsonl in1.jsonl in2.jsonl [in3.jsonl ...]
"""

from __future__ import annotations

import sys
from pathlib import Path


def combine(output: Path, inputs: list[Path]) -> int:
    written = 0
    with output.open("w", encoding="utf-8") as out:
        for path in inputs:
            with path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    out.write(line + "\n")
                    written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print(
            "usage: combine_reports.py OUTPUT.jsonl INPUT1.jsonl INPUT2.jsonl [...]",
            file=sys.stderr,
        )
        return 2
    output = Path(argv[0])
    inputs = [Path(p) for p in argv[1:]]
    missing = [str(p) for p in inputs if not p.exists()]
    if missing:
        print("missing input file(s): " + ", ".join(missing), file=sys.stderr)
        return 1
    n = combine(output, inputs)
    print(f"Wrote {n} lines to {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
