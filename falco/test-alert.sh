#!/usr/bin/env bash
# Trigger a classic detection-worthy move inside a throwaway container:
# spawn a shell, then read /etc/shadow (the file holding password
# hashes on Linux — a standard move for an attacker trying to escalate
# privileges or steal credentials post-compromise).
#
# Run this in one terminal, and `kubectl logs -n falco -l
# app.kubernetes.io/name=falco -f` in another to watch Falco catch it
# live. Expect two alerts:
#   1. Notice  — "A shell was spawned in a container with an attached terminal"
#   2. Warning — "Sensitive file opened for reading by non-trusted program"

set -euo pipefail

kubectl run alpine-test --image=alpine -- sh -c "sleep 3600"
kubectl wait --for=condition=Ready pod/alpine-test --timeout=60s
kubectl exec -it alpine-test -- sh -c "cat /etc/shadow"

echo "Check the Falco log stream — you should see two alerts fire."
echo "Clean up with: kubectl delete pod alpine-test"
