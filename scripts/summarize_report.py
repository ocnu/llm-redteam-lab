#!/usr/bin/env python3
"""
Summarize one or two garak `.report.jsonl` files into a markdown or CSV table.

garak's report.jsonl is a stream of JSON objects, one per line, each tagged
with an `entry_type` field. This tool pulls out the `eval` entries, added
once per probe/detector pair after that pair finishes running, and formats
them as a table sorted by attack success rate (worst first).

garak's eval-row field names vary between versions (I ran into this directly:
the total-count field was named differently than an earlier run expected). So
parsing checks a few common key-name variants per field rather than assuming one
fixed schema. Any eval row that doesn't match a known layout is counted and
reported, not silently dropped.

Usage:
    # Single report -> markdown table to stdout
    python3 summarize_report.py run.report.jsonl

    # Only the 10 worst rows, written to a file
    python3 summarize_report.py run.report.jsonl --top 10 --output findings.md

    # Drop low-sample-size rows (avoid n=3 100% results skewing the ranking)
    python3 summarize_report.py run.report.jsonl --min-sample 30

    # CSV instead of markdown
    python3 summarize_report.py run.report.jsonl --format csv

    # Compare two models/runs side by side
    python3 summarize_report.py llama3.1.report.jsonl mistral.report.jsonl \\
        --labels "llama3.1:8b,mistral:7b" --output comparison.md
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path


def _first_present(d: dict, *keys: str) -> object | None:
    """Return the first key in `keys` present (and non-null) in `d`."""
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return None


@dataclass(frozen=True)
class EvalRow:
    """One probe/detector result from a garak report."""

    probe: str
    detector: str
    passed: int
    total: int
    ci_low: float | None = None  # percentage points, e.g. 19.92
    ci_high: float | None = None

    @property
    def attack_success_rate(self) -> float:
        """Percentage of attempts that were NOT caught/passed by the detector."""
        if self.total == 0:
            return 0.0
        return (self.total - self.passed) / self.total * 100

    @classmethod
    def from_json(cls, row: dict) -> EvalRow | None:
        probe = _first_present(row, "probe", "probe_name")
        detector = _first_present(row, "detector", "detector_name")
        passed = _first_present(row, "passed", "passed_count", "passes")
        total = _first_present(row, "total", "total_count", "instances", "total_evaluated", "total_processed")

        if probe is None or detector is None or passed is None or total is None:
            return None

        try:
            total_i = int(total)
            passed_i = int(passed)
        except (TypeError, ValueError):
            return None

        if total_i == 0:
            return None

        ci_low = _first_present(row, "ci_low", "confidence_interval_low", "confidence_lower")
        ci_high = _first_present(row, "ci_high", "confidence_interval_high", "confidence_upper")

        return cls(
            probe=str(probe),
            detector=str(detector),
            passed=passed_i,
            total=total_i,
            ci_low=ci_low * 100 if isinstance(ci_low, (int, float)) else None,
            ci_high=ci_high * 100 if isinstance(ci_high, (int, float)) else None,
        )


def parse_report(path: Path) -> tuple[list[EvalRow], int]:
    """Parse a garak report.jsonl file. Returns (eval_rows, unparsed_eval_row_count)."""
    rows: list[EvalRow] = []
    unparsed = 0

    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if obj.get("entry_type") != "eval":
                continue

            parsed = EvalRow.from_json(obj)
            if parsed is not None:
                rows.append(parsed)
            else:
                unparsed += 1

    return rows, unparsed


def filter_and_sort(
    rows: list[EvalRow], min_sample: int = 1, top: int | None = None
) -> list[EvalRow]:
    """Drop rows below min_sample attempts, sort worst-first, optionally truncate."""
    filtered = [r for r in rows if r.total >= min_sample]
    filtered.sort(key=lambda r: r.attack_success_rate, reverse=True)
    if top is not None:
        filtered = filtered[:top]
    return filtered


def format_markdown(rows: list[EvalRow]) -> str:
    lines = ["| Probe | Detector | n | Attack success rate |", "|---|---|---|---|"]
    for r in rows:
        ci = (
            f" [{r.ci_low:.2f}%, {r.ci_high:.2f}%]"
            if r.ci_low is not None and r.ci_high is not None
            else ""
        )
        lines.append(f"| `{r.probe}` | {r.detector} | {r.total} | {r.attack_success_rate:.2f}%{ci} |")
    return "\n".join(lines)


def format_csv(rows: list[EvalRow]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["probe", "detector", "passed", "total", "attack_success_rate", "ci_low", "ci_high"])
    for r in rows:
        writer.writerow(
            [
                r.probe,
                r.detector,
                r.passed,
                r.total,
                f"{r.attack_success_rate:.4f}",
                f"{r.ci_low:.4f}" if r.ci_low is not None else "",
                f"{r.ci_high:.4f}" if r.ci_high is not None else "",
            ]
        )
    return buf.getvalue()


def compare_reports(
    rows_a: list[EvalRow], rows_b: list[EvalRow], label_a: str, label_b: str
) -> str:
    """Build a side-by-side comparison table keyed on (probe, detector)."""

    def key(r: EvalRow) -> tuple[str, str]:
        return (r.probe, r.detector)

    map_a = {key(r): r for r in rows_a}
    map_b = {key(r): r for r in rows_b}
    all_keys = set(map_a) | set(map_b)

    def sort_key(k: tuple[str, str]) -> float:
        a_rate = map_a[k].attack_success_rate if k in map_a else -1.0
        b_rate = map_b[k].attack_success_rate if k in map_b else -1.0
        return max(a_rate, b_rate)

    ordered_keys = sorted(all_keys, key=sort_key, reverse=True)

    lines = [f"| Probe | Detector | {label_a} | {label_b} | Delta |", "|---|---|---|---|---|"]
    for probe, detector in ordered_keys:
        a = map_a.get((probe, detector))
        b = map_b.get((probe, detector))
        a_val = f"{a.attack_success_rate:.2f}%" if a else "—"
        b_val = f"{b.attack_success_rate:.2f}%" if b else "—"
        if a is not None and b is not None:
            delta = b.attack_success_rate - a.attack_success_rate
            delta_str = f"{delta:+.2f}%"
        else:
            delta_str = "—"
        lines.append(f"| `{probe}` | {detector} | {a_val} | {b_val} | {delta_str} |")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize garak report.jsonl file(s) into a markdown or CSV table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "reports", nargs="+", type=Path, help="One report.jsonl to summarize, or two to compare."
    )
    parser.add_argument("--top", type=int, default=None, help="Only show the N highest attack-success-rate rows.")
    parser.add_argument(
        "--min-sample",
        type=int,
        default=1,
        help="Drop rows with fewer than N total attempts (default: 1, i.e. no filtering).",
    )
    parser.add_argument(
        "--format",
        choices=["md", "csv"],
        default="md",
        help="Output format for single-report mode (compare mode is always markdown).",
    )
    parser.add_argument("--output", type=Path, default=None, help="Write to this file instead of stdout.")
    parser.add_argument(
        "--labels",
        type=str,
        default=None,
        help="Compare mode only: comma-separated column labels, e.g. 'llama3.1:8b,mistral:7b'. "
        "Defaults to each file's stem.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if len(args.reports) > 2:
        parser.error("At most two report files are supported (one to summarize, or two to compare).")

    unparsed_total = 0

    if len(args.reports) == 2:
        rows_a, unparsed_a = parse_report(args.reports[0])
        rows_b, unparsed_b = parse_report(args.reports[1])
        rows_a = filter_and_sort(rows_a, args.min_sample)
        rows_b = filter_and_sort(rows_b, args.min_sample)
        unparsed_total = unparsed_a + unparsed_b

        if args.labels:
            label_a, label_b = (s.strip() for s in args.labels.split(",", 1))
        else:
            label_a, label_b = args.reports[0].stem, args.reports[1].stem

        output = compare_reports(rows_a, rows_b, label_a, label_b)
    else:
        rows, unparsed_total = parse_report(args.reports[0])
        rows = filter_and_sort(rows, args.min_sample, args.top)
        output = format_markdown(rows) if args.format == "md" else format_csv(rows)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)

    if unparsed_total:
        print(
            f"\n({unparsed_total} eval row(s) had an unrecognized field layout and were skipped.)",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
