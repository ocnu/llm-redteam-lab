#!/usr/bin/env bash
# Run garak's `encoding` probe family against a local Ollama-served model.
#
# Encoding probes test whether wrapping an injected instruction in an
# obfuscation scheme (ROT13, base64/32/16, ASCII85, Unicode tricks, Zalgo
# text, etc.) lets it slip past the model where a plaintext version
# wouldn't. 15 active sub-probes as of garak 0.16.0 — run
# `garak --list_probes` to see the current set for your install.
#
# Note: garak's Ollama generator is not parallel-capable, so this takes
# roughly 1.5-2 hours even with --generations 1. Run it inside tmux/screen
# if you're not going to babysit it.

set -euo pipefail

MODEL_NAME="${MODEL_NAME:-llama3.1:8b}"
REPORT_PREFIX="${REPORT_PREFIX:-encoding-run}"

garak \
  --model_type ollama \
  --model_name "$MODEL_NAME" \
  --probes encoding \
  --generations 1 \
  --report_prefix "$REPORT_PREFIX"

echo "Report written to ~/.local/share/garak/garak_runs/${REPORT_PREFIX}.report.jsonl"
