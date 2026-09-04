"""
Tests for scripts/summarize_report.py.

Run with: pytest
(from the repo root, after `pip install -r requirements-dev.txt`)
"""

from __future__ import annotations

import csv
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import summarize_report as sr  # noqa: E402


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "summarize_report.py"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parses_known_attack_success_rates(tmp_path: Path) -> None:
    """Reproduces the real numbers garak printed for the encoding probe run,
    to catch any regression in the core math."""
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [
            {"entry_type": "start_run setup", "foo": "bar"},
            {
                "entry_type": "eval",
                "probe": "encoding.InjectZalgo",
                "detector": "encoding.DecodeApprox",
                "passed": 191,
                "total": 256,
                "ci_low": 0.1992,
                "ci_high": 0.3086,
            },
            {
                "entry_type": "eval",
                "probe": "encoding.InjectROT13",
                "detector": "encoding.DecodeApprox",
                "passed": 254,
                "total": 256,
                "ci_low": 0.0,
                "ci_high": 0.0195,
            },
        ],
    )

    rows, unparsed = sr.parse_report(report)

    assert unparsed == 0
    assert len(rows) == 2

    zalgo = next(r for r in rows if r.probe == "encoding.InjectZalgo")
    assert zalgo.attack_success_rate == pytest.approx(25.39, abs=0.01)
    assert zalgo.ci_low == pytest.approx(19.92, abs=0.01)
    assert zalgo.ci_high == pytest.approx(30.86, abs=0.01)

    rot13 = next(r for r in rows if r.probe == "encoding.InjectROT13")
    assert rot13.attack_success_rate == pytest.approx(0.78, abs=0.01)


def test_ignores_non_eval_entry_types(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [
            {"entry_type": "start_run setup"},
            {"entry_type": "init", "garak_version": "0.16.0"},
            {"entry_type": "attempt", "uuid": "abc-123"},
            {"entry_type": "eval", "probe": "dan.DanInTheWild", "detector": "mitigation.MitigationBypass",
             "passed": 100, "total": 256},
        ],
    )

    rows, unparsed = sr.parse_report(report)

    assert unparsed == 0
    assert len(rows) == 1
    assert rows[0].probe == "dan.DanInTheWild"


def test_malformed_eval_row_counted_not_crashed(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [
            # missing "total" entirely
            {"entry_type": "eval", "probe": "x.Y", "detector": "z.W", "passed": 5},
            # total present but not numeric
            {"entry_type": "eval", "probe": "x.Y", "detector": "z.W", "passed": 5, "total": "lots"},
            # a well-formed row so we can confirm parsing continued afterward
            {"entry_type": "eval", "probe": "good.Probe", "detector": "good.Detector", "passed": 9, "total": 10},
        ],
    )

    rows, unparsed = sr.parse_report(report)

    assert unparsed == 2
    assert len(rows) == 1
    assert rows[0].probe == "good.Probe"


def test_alternate_key_names_supported(tmp_path: Path) -> None:
    """garak's schema has shifted before; the parser should tolerate the
    documented alternate field names, not just one exact spelling."""
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [
            {
                "entry_type": "eval",
                "probe_name": "leakreplay.NYTCloze",
                "detector_name": "leakreplay.StartsWith",
                "passed_count": 40,
                "total_count": 50,
            }
        ],
    )

    rows, unparsed = sr.parse_report(report)

    assert unparsed == 0
    assert len(rows) == 1
    assert rows[0].attack_success_rate == pytest.approx(20.0)


def test_zero_total_row_dropped_not_crashed(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [{"entry_type": "eval", "probe": "x.Y", "detector": "z.W", "passed": 0, "total": 0}],
    )

    rows, unparsed = sr.parse_report(report)

    assert rows == []
    assert unparsed == 1


# ---------------------------------------------------------------------------
# Filtering / sorting
# ---------------------------------------------------------------------------


def _row(probe: str, passed: int, total: int) -> sr.EvalRow:
    return sr.EvalRow(probe=probe, detector="d", passed=passed, total=total)


def test_min_sample_filters_small_n() -> None:
    rows = [_row("small_n", 0, 3), _row("big_n", 200, 256)]

    kept_strict = sr.filter_and_sort(rows, min_sample=30)
    assert [r.probe for r in kept_strict] == ["big_n"]

    kept_loose = sr.filter_and_sort(rows, min_sample=1)
    assert {r.probe for r in kept_loose} == {"small_n", "big_n"}


def test_sorted_worst_first() -> None:
    rows = [_row("low", 90, 100), _row("high", 10, 100), _row("mid", 50, 100)]

    result = sr.filter_and_sort(rows)

    assert [r.probe for r in result] == ["high", "mid", "low"]


def test_top_n_truncates_after_sorting() -> None:
    # ASR = 100 - passed, since total=100: p0=100% (worst) .. p4=20% (best)
    rows = [_row(f"p{i}", i * 20, 100) for i in range(5)]

    result = sr.filter_and_sort(rows, top=2)

    assert [r.probe for r in result] == ["p0", "p1"]


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def test_format_csv_roundtrips_values() -> None:
    rows = [_row("badchars.BadCharacters", 36, 256)]

    output = sr.format_csv(rows)
    reader = csv.DictReader(io.StringIO(output))
    parsed_rows = list(reader)

    assert len(parsed_rows) == 1
    assert parsed_rows[0]["probe"] == "badchars.BadCharacters"
    assert parsed_rows[0]["total"] == "256"
    assert float(parsed_rows[0]["attack_success_rate"]) == pytest.approx(85.9375, abs=0.001)


def test_format_markdown_includes_confidence_interval_when_present() -> None:
    row = sr.EvalRow(probe="p", detector="d", passed=191, total=256, ci_low=19.92, ci_high=30.86)

    output = sr.format_markdown([row])

    assert "[19.92%, 30.86%]" in output


def test_format_markdown_omits_confidence_interval_when_absent() -> None:
    row = sr.EvalRow(probe="p", detector="d", passed=191, total=256)

    output = sr.format_markdown([row])

    assert "[" not in output


# ---------------------------------------------------------------------------
# Compare mode
# ---------------------------------------------------------------------------


def test_compare_reports_computes_delta_in_right_direction() -> None:
    rows_a = [_row("shared.Probe", 90, 100)]  # 10% ASR
    rows_b = [_row("shared.Probe", 60, 100)]  # 40% ASR, worse

    output = sr.compare_reports(rows_a, rows_b, "model-a", "model-b")

    assert "10.00%" in output
    assert "40.00%" in output
    assert "+30.00%" in output  # b is 30 points worse than a


def test_compare_reports_handles_probe_present_in_only_one_side() -> None:
    rows_a = [_row("only_in_a.Probe", 50, 100)]
    rows_b = [_row("only_in_b.Probe", 50, 100)]

    output = sr.compare_reports(rows_a, rows_b, "model-a", "model-b")

    assert "only_in_a.Probe" in output
    assert "only_in_b.Probe" in output
    assert "—" in output  # placeholder for the missing side


# ---------------------------------------------------------------------------
# CLI end-to-end (invokes the real script as a subprocess)
# ---------------------------------------------------------------------------


def test_cli_writes_output_file(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    write_jsonl(
        report,
        [{"entry_type": "eval", "probe": "a.B", "detector": "c.D", "passed": 1, "total": 10}],
    )
    out_file = tmp_path / "out.md"

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(report), "--output", str(out_file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert out_file.exists()
    assert "a.B" in out_file.read_text()


def test_cli_rejects_more_than_two_reports(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    write_jsonl(report, [{"entry_type": "eval", "probe": "a.B", "detector": "c.D", "passed": 1, "total": 10}])

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), str(report), str(report), str(report)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "At most two report files" in result.stderr
