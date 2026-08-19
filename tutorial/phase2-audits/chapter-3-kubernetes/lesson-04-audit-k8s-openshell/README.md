# Lesson 2.3.4 — Auditing the OpenShell rung on a cluster

**Phase 2 audits what phase 1 measured.**
[Lesson 1.3.4](../../../phase1-attacks/chapter-3-kubernetes/lesson-04-k8s-openshell/) is the rung
where per-binary, method-aware policy closes the attacks a NetworkPolicy could not. This lesson runs
the **same policy file, byte for byte**, with three sensors watching.

| sensor | what it can see |
| :-- | :-- |
| **Tetragon** (host CO-RE eBPF) | the local attacks — OpenShell runs on ordinary runc, so the sandbox pod's syscalls reach the node's kernel |
| **OCSF** (OpenShell's L7 decision trail) | the network attacks, by binary, method and endpoint — and what the policy **denied** |
| **the apiserver audit log** | the control plane |

## The finding

**Two columns overlap, and a third is empty for a reason worth knowing.**

**11 of 19 written down** — Tetragon 7, OCSF 8, four attacks caught by both. This is
[2.2.4](../../chapter-2-one-host/lesson-04-audit-container-openshell/)'s two-sensor result moved onto
the cluster with the host sensor swapped from in-guest auditd to Tetragon, and it lands in the same
place: **full coverage is the union of sensors with disjoint blind spots.**

The third sensor records **nothing of the workload's**, and that is a finding rather than a gap. An
OpenShell sandbox is a Pod but **not a cluster principal**: it gets no service-account token and no
`KUBERNETES_SERVICE_HOST`, so `k8s_sa_token` reads `n/a-no-cluster` and does not even run. The attack
surface [2.3.1](../lesson-01-audit-k8s/) had to leave open in order to measure it is simply *absent*
here. The audit log is on and recording throughout; what it holds is the operator's actions.

### The row neither syscall sensor can reach

`fs_policy_write` — a write to `/etc` that **Landlock denies** before it resolves to anything a
syscall auditor records, and Landlock is a kernel verdict rather than an L7 one, so OCSF never sees it
either. That is 2.2.4's gap, structural and unchanged: *a host auditor records what the workload did;
only the enforcing layer knows what it refused.*

## No canaries here — and that is a sensor decision, not a shortcut

2.2.4 plants fake credentials (`PLANT_FAKE_SECRETS=1`) because its host sensor is **auditd**, which
fingerprints a `type=PATH` record — and that record only exists once a path resolves to an inode. With
nothing planted, the credential theft left no trail and the rung looked blind.

**Tetragon hooks the open *syscall*,** which fires on the attempt whether or not the file exists. So
no canary is needed, and this card is 1.3.4's containment **unchanged**: 17/19, with **zero rows
different**. A true audit twin.

## Attribution

Events are matched to the sandbox by **container id**, discovered rather than assumed: OpenShell owns
the pod, so the leaf looks for a pod in the `openshell` namespace whose name contains the sandbox
name and reads its `containerID`.

This precision is not decoration. The **OpenShell gateway is itself a pod on this node** and it
proxies every request the workload makes, producing a `tcp_connect` for each one. Attributing by "some
container" — or by pid namespace — would credit the workload with the traffic of its own jailer and
mark `exfiltrate` LOGGED on the strength of the sensor watching the proxy.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.4     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or the whole chapter on one box: `cd infra && ./chapter-03-audit.sh`.

OpenShell is **alpha**; the version is printed at the top of the run and recorded in the scorecard, so
drift is visible rather than mysterious.
