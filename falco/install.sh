#!/usr/bin/env bash
# Stand up a single-node k3s cluster and deploy Falco with the modern
# eBPF driver (CO-RE based — no kernel module build required, works on
# any kernel with BTF + ring buffer support, min kernel 5.8).

set -euo pipefail

# 1. k3s — lightweight single-binary Kubernetes
curl -sfL https://get.k3s.io | sh -
sudo k3s kubectl get nodes

# Make `kubectl` work without sudo / without prefixing k3s
mkdir -p ~/.kube
sudo k3s kubectl config view --raw | tee ~/.kube/config >/dev/null
chmod 600 ~/.kube/config
export KUBECONFIG=~/.kube/config
grep -qxF 'export KUBECONFIG=~/.kube/config' ~/.bashrc || \
  echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc

# 2. Helm — Kubernetes package manager
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version

# 3. Falco, via its official Helm chart, modern eBPF driver
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true

kubectl get pods -n falco
echo "Tail live alerts with: kubectl logs -n falco -l app.kubernetes.io/name=falco -f"
