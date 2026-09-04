# Reports

This folder holds `findings.md`, the summarized results table generated from a
garak run with `scripts/summarize_report.py`.

The raw garak `.report.jsonl` and `.report.html` files are not committed (they're
gitignored). Those contain the model's full response to every attack prompt,
including the output from attempts that succeeded, so they're kept local rather
than published.

To regenerate the table from your own run:

```bash
python3 ../../scripts/summarize_report.py your-run.report.jsonl --min-sample 30 --output findings.md
```

`--min-sample 30` drops very low-sample probes so a single lucky hit doesn't
skew the ranking.
