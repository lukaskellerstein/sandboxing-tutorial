# Lesson 2.4.1 — Auditing the OpenShift rung

**Phase 2 audits what phase 1 measured.**
[Lesson 1.4.1](../../../phase1-attacks/chapter-4-openshift/lesson-01-openshift-pod/) ran the hardened
pod on OpenShift. This lesson runs the same pod with the two sensors an OpenShift cluster actually
has, and reports per attack whether anything wrote it down.

**Containment is 1.4.1's exactly: 7/13, zero rows different.** Nothing about the boundary is weakened
for the audit.

## The finding: the platform audits the control plane, not the kernel

| sensor | state on a fresh cluster | what it cost to use |
| :-- | :-- | :-- |
| **kube-apiserver audit log** | **already on**, per-request, `oc adm node-logs --role=master` | nothing |
| **the node's `auditd`** | **running, and watching nothing** — two `exclude` rules, no syscall rules | had to be armed, and forgets on reboot |

Every rung before this one had a sensor you *installed*, watching the kernel — auditd in 2.1.1,
Tetragon in 2.2.1 and 2.3.1. A managed, immutable platform inverts that. The sensor you get for free
watches the **control plane**; the kernel-level one ships switched off, and switching it on is exactly
the kind of node mutation the platform exists to prevent.

This lesson arms it anyway, with `auditctl` at run time, and is explicit about the price: the rules
are **ephemeral**, gone at the next reboot, and the supported way to make them stick is a
MachineConfig — which edits the immutable OS. *A platform that reconciles your node back to a known
image also reconciles away your sensor.*

**4 of 13 written down** (measured 2026-08-15), all by the node's auditd: `read_credentials`,
`plant_backdoor`, `sys_module_count`, `kallsyms_readable`. The apiserver's column is empty here and
correctly so — 1.4.1's pod has `automountServiceAccountToken: false`, so it never becomes a cluster
principal and never makes a request to audit. [2.3.1](../../chapter-3-kubernetes/lesson-01-audit-k8s/)
is where that column is exercised, by deliberately leaving the token mounted.

## Attribution: a third mechanism, and the platform hands it to you

Three chapters, three different keys, each forced by what the layer underneath makes available:

| chapter | key | why the others don't work |
| :-- | :-- | :-- |
| 2.2.1 | **pid namespace** | rootless podman leaves `process.docker` empty on the workload |
| 2.3.1 | **container id** | the kubelet populates it; pid-ns can't separate the attack pod from the gateway pod |
| **2.4.1** | **SELinux MCS** | the platform labels every pod with its own category pair, and the kernel stamps it on every record |

**uid is the trap.** The image's `USER 1001` is shared with node components — a `uid=1001` rule also
catches `service-ca-operator`. uid decides *what gets recorded*; MCS decides *whose it was*.

### The correlation subtlety that makes it correct

An audit *event* is several records sharing one serial:

```text
type=SYSCALL msg=audit(…:1595): … subj=…container_t:s0:c19,c27
type=PATH    msg=audit(…:1595): name="/proc/kallsyms" … obj=…proc_t:s0
```

`subj=` on the SYSCALL record is the **process's** context and carries the pod's MCS. `obj=` on the
PATH record is the **file's** context — which carries the pod's MCS only for files in the container's
own layer, and never for `/proc`, `/sys` or anything on the host. Matching PATH records by MCS finds
the backdoor the agent wrote and silently misses every `/proc` read. Measured: that spelling reported
**2/13** where the truth is 4/13. So the leaf resolves serials first, then takes names from the PATH
companions.

## Two traps that made this intermittent, and how each was ruled out

Both are 2.1.1's and 2.2.4's traps in RHCOS clothing, and back-to-back runs reported **5/13 then
0/13** before they were fixed:

1. **Audit backlog.** RHCOS ships `backlog_limit 8192`, and a rule recording every `openat` is
   overrun by a Python interpreter's imports alone. The lesson raises it to 65536 and then **asserts
   `lost == 0`** — a dropped record and a boundary that hid something are indistinguishable in the
   trail, so the assertion is what keeps the RECORDED column from being a coin flip.
2. **Log rotation.** `max_log_file = 8` (MB) with `ROTATE`, and the flood fills a segment in under a
   minute — so the attack's records land in `audit.log.1` before the lesson reads. Chapter 2 fixed the
   equivalent by raising `max_log_file` in `auditd.conf`; that is **not available here**, because
   `auditd.conf` is part of the immutable image. The lesson reads the **rotated segments** instead,
   which mutates nothing and is what an operator on this platform would have to do too.

With both handled, back-to-back runs give **4/13 and 4/13**, 739 paths each.

## Run it

```bash
../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h, EUR 0.263/hr)
./run.sh
../../../infra/down.sh openshift-sno       # DESTROY it — nothing does this for you
```

Like every chapter-4 leaf this runs on **your machine** and drives `oc`; the boundary is on the node,
which is where it has to be. The teardown is a step you own.
