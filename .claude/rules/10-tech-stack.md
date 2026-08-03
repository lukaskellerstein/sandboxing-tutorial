---
description: "Reference: Technology stack — Python lesson leaves driving container and k8s isolation runtimes"
---

# Reference: Technology Stack

<!-- Read from manifests (pyproject.toml, compose files, k8s manifests), never
     guessed. Pin the versions that actually constrain choices; omit the ones
     that do not. Delete sections that do not apply.
     As of 2026-08-03 the repo declares NO dependencies — there are no lesson
     leaves yet. Everything below is the intended stack, and each entry becomes
     verifiable the moment the leaf that uses it exists. -->

## Lessons

- **Language**: Python 3.12+
- **Package manager**: `uv`, one project per lesson leaf. Never `pip install`,
  never a workspace.
- **Shape**: `main.py` per leaf, under ~200 lines, printing its way through the
  lesson. Helpers go in a sibling module in the same leaf.

## The isolation stack — the actual subject

| Layer | What it is | Notes |
|:--|:--|:--|
| **podman** | the preferred container engine | first choice everywhere; `podman compose` for multi-service lessons |
| **Docker** | fallback engine | only where a tool does not support podman — and the lesson must say why. `DOCKER_HOST=unix:///var/run/docker.sock` bridges to the podman socket on this machine |
| **Kubernetes** | the cluster half of the ladder | `RuntimeClass` is how gVisor and Kata are selected per pod |
| **gVisor** (`runsc`) | user-space kernel | intercepts syscalls; shrinks host kernel attack surface |
| **Kata Containers** | per-pod lightweight VM | its own guest kernel — which is why it keeps features a user-space kernel drops |
| **NVIDIA OpenShell** | per-binary + L7 policy on ordinary runc | **alpha** — pin the version in any lesson that uses it, and record the version it was verified against |

## Infrastructure

- **Deploy**: nothing is deployed. Lessons run locally against a container engine
  or a local cluster; any longer-lived cluster is external and reached by an
  isolated kubeconfig, never a committed one.
- **Runtime target**: macOS 26 on Apple Silicon is the development machine. Most
  of this stack is **Linux kernel functionality**, so it executes inside a VM
  (the podman machine) or a cluster node — not natively. A lesson that does not
  say where its boundary actually lives is misleading.

## Scripting & Automation

- Default: Python for anything a lesson runs, consistent with the rest of the
  stack
- Shell scripts only for setup that must happen outside Python — installing a
  runtime, registering a `RuntimeClass`, bringing up a cluster. The prior-art
  repo's `setup_runsc.sh` / `setup_gvisor_addon.sh` are the pattern.
- Scripts must pass `shellcheck`, and are formatted by `shfmt` via
  `.editorconfig`

## Conventions this machine imposes

- **One formatter per filetype.** Biome owns the JS/TS family; prettier and
  eslint are not installed. Python formats with the ruff CLI chain.
- Tools run only where the repo carries their config file — see
  `rules/09-code-quality.md`.
- The root `ruff.toml` excludes `**/*.md` on purpose: lesson prose is the
  product, and ruff reformats Python inside markdown fences.
