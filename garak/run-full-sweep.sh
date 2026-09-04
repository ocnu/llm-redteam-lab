#!/usr/bin/env bash
# Run every other active probe family in garak's default catalog
# (everything except `encoding`, which was already run separately —
# see run-encoding.sh). If you're starting fresh and haven't run
# encoding yet, just use `--probes all` instead of the explicit list
# below.
#
# garak marks some probes 💤 (sleeping) in `--list_probes` output —
# those are excluded from a default run automatically (usually because
# they need extra dependencies, run live optimization attacks like
# GCG/BEAST, or duplicate a smaller "cached" variant that's already
# active). This list only includes the active ones.
#
# Heads up: `atkgen.Tox` runs its own little attacker-model conversation
# loop against the target rather than firing a fixed prompt list, so its
# runtime doesn't scale predictably like the rest. If the run looks stuck
# on it for a long stretch, that's expected, not broken.
#
# Expect several hours for this to complete. Run inside tmux/screen.
#
# On Python 3.14, a few probes that pull datasets from the Hugging Face
# Hub at runtime (packagehallucination, some leakreplay) crash on a
# dill/pickle incompatibility. If you hit that, drop those probes from
# the list and run the rest — garak writes results incrementally, and
# summarize_report.py reads across multiple report files.

set -euo pipefail

MODEL_NAME="${MODEL_NAME:-llama3.1:8b}"
REPORT_PREFIX="${REPORT_PREFIX:-full-sweep}"

PROBES="adaptive_attacks,ansiescape,apikey,atkgen,badchars,continuation,dan,\
divergence,dra,exploitation,goodside,grandma,latentinjection,leakreplay,\
lmrc,malwaregen,misleading,packagehallucination,phrasing,promptinject,\
realtoxicityprompts,sata,snowball,suffix,sysprompt_extraction,tap,topic,\
web_injection"

garak \
  --model_type ollama \
  --model_name "$MODEL_NAME" \
  --probes "$PROBES" \
  --generations 1 \
  --report_prefix "$REPORT_PREFIX"

echo "Report written to ~/.local/share/garak/garak_runs/${REPORT_PREFIX}.report.jsonl"
