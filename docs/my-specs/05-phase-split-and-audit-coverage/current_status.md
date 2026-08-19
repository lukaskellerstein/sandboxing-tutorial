# Spec 05 — current status & handoff (2026-08-15)

This file is a handoff: where spec 05 stands and exactly what the next agent does to continue. The spec
is `spec.md`; the approved plan is `~/.claude/plans/sunny-dreaming-fox.md` (summarised in project memory
`spec-05-phase-split-renumber.md`). The **source-of-truth roadmap** is `syllabus.md` § "Phase 2 —
Auditing" (the leaf list, sensor stacks, and the G1–G4 discovery-gate results).

> **Nothing in this repo is committed.** Lukas commits. Everything is in the working tree on branch
> `lukas/05-auditing`. Do **not** `git commit` / `git push` unless Lukas explicitly asks.

---

## Where spec 05 stands

- **Stage A** (phase split + per-chapter dotted-id renumber) — DONE + verified.
- **Stage B** (the per-attack RECORDED band: `Finding.recorded`, `render.py` band, `overall.py` phase-2
  view) — DONE. **Extended 2026-08-18:** phase-2 pages now get their own layout from the same
  `render.py` (`is_audit()` keys on the id's leading digit): headline *N of M attacks recorded* over a
  segmented bar (logged / not logged / no sensor), containment demoted to a second meter, a callout
  naming the attacks that **succeeded and left no record** (split into *unseen* — a sensor watched and
  wrote nothing — and *blind* — no sensor in that layer), a containment × record 2×2 grid, and the
  RECORDED verdict as a column on each attack's row (the detached band stays on phase-1 pages only).
  `report.json` gained `logged`, `recorded_counts`, `unseen_breaches`, `unrecorded_breaches` and
  `measurements` (every non-structural card key — the sensor readings — verbatim); `overall.py`'s
  phase-2 matrix reads them into a two-line footer. `recorded_tally()` / `COVERAGE_STATES` is the one
  place the coverage denominator is defined — spec 06's `N_A` state slots in there. Note the
  denominator is every scored attack: a row a lesson never consulted a sensor for (2.2.3's
  `kernel_identity`, `recorded: None`) counts as `no sensor`, so the page says 12/13 where the lesson's
  own console tally said 12/12.
- **Stage C** (the phase-2 audit leaves) — **chapters 1–4 built and verified, with two leaves that cannot exist.**
  - **BUILT + verified:** `2.1.1` (host auditd, 11/13) · `2.2.1` (host Tetragon, **7/13**) · `2.2.2`
    (`runsc --strace` sentry, 11/12) · `2.2.3` (host Tetragon 0 / in-guest strace 12/12) · `2.2.4`
    (auditd + OCSF, **15/19**) · `2.3.1` (**8/19**) · `2.3.2` (sentry **10/19**, host sensor **0**) ·
    `2.3.3` (in-guest sidecar **12/19**, host sensor **0**) · `2.3.4` (**11/19**) · `2.3.5` (**12/18** +
    6 landlock findings) · `2.3.6` (**8/19**, host sensor **0**) · `2.4.1` (**4/13**) · `2.4.2` (**3/3**)
    · `2.4.3` (**0/14**, node sensor 0 vs 2.4.1's 739) · `2.4.4` (**12/19**). Every one is a true audit
    twin: **zero rows differ** from its phase-1 counterpart's containment card.
  - **Doc-only leaves (no `main.py`, not in `lessons.json`):** `2.2.5`, `2.2.6`, `2.4.5`.
  - **`2.4.6` is NOT BUILDABLE**, and that is a measured finding rather than a gap — its phase-1 twin
    `1.4.6` does not work on this stack. See § *1.4.6* below.
  - **Nothing in phase 2 is blocked any more.** The SNO cluster was built, used and destroyed on
    2026-08-15; the account was verified empty afterwards.

---

## Chapter 3 audit — what was built and what it cost to find (2026-08-15)

**All six** leaves under `tutorial/phase2-audits/chapter-3-kubernetes/`, green from a **from-scratch**
`infra/chapter-03-audit.sh` cycle (provision → 6 lessons → EXIT-trap teardown). New infra:

- `infra/substrates/chapter-3-audit/k8s-api-audit.sh` — apiserver audit policy + flags via
  `/etc/rancher/k3s/config.yaml`, then a k3s restart. **Must land at/with 60**, never after 80.
- `infra/substrates/chapter-3-audit/72-k8s-gvisor-trace.sh` — a SECOND `gvisor-trace` RuntimeClass
  selecting the same runsc with `--strace`. **Must run with 70/75, never after 80.**
- `infra/substrates/chapter-3-audit/85-kata-debug-kernel.sh` — enables the per-pod `kernel`
  annotation so 2.3.3's guest carries BTF. **Must run AFTER 80-k8s-kata** (kata-deploy lays down
  /opt/kata when its DaemonSet starts) and restarts nothing.
- `infra/substrates/chapter-3-audit/tetragon.sh` — rewritten (see the reversal below).
- `infra/chapter-03-audit.sh` — the chapter runner, EXIT-trap teardown, mirroring `chapter-03.sh`.
- `check.sh` arms for `k8s-api-audit`, `72-k8s-gvisor-trace`, `85-kata-debug-kernel`, and a **k8s
  branch** in the `tetragon` arm (pod trigger + container-id attribution instead of the
  podman/pid-namespace one).

### THE BIG ONE: Tetragon's `--enable-k8s-api` does not work here, and is harmful

The substrate used to set it, on the reasoning that native pod enrichment would make the k8s rung
cheaper to instrument than the container rung. **Five rounds on a live k3s box say otherwise**, and
each round is worth knowing because each failure mode reads like something else:

1. **Tetragon refuses to start.** The flag also switches on the TracingPolicy **CRD watcher**
   (`enable-tracing-policy-crd` defaults true) and the release **tarball ships no CRDs** — only the
   Helm chart installs them. It exits with
   `Failed to execute tetragon error="no matches for kind \"TracingPolicy\" in version \"cilium.io/v1alpha1\""`.
   `check.sh` reported this as `hits=0`, i.e. **indistinguishable from a sensor that saw nothing**.
2. With the CRD watcher off it runs, and **still resolves no pod**. `process.pod` is null on every
   event, with and without `NODE_NAME` set to the node's real name.
3. Tetragon names the missing half itself: `cgidmap is enabled but cri is not. This means that pod
   association will not work for existing pods.` So it wants `--enable-cri` against k3s's
   **non-standard** containerd socket (`/run/k3s/containerd/containerd.sock`) — the very hand-wiring
   the old comment claimed was *Falco's* problem and that Tetragon avoided. That comment was wrong.
4. Even with `--enable-cgidmap --enable-cri --cri-endpoint=unix:///run/k3s/containerd/containerd.sock`
   the CRI client initialises cleanly and **`process.pod` is still null**.
5. **And the flag makes the trail late.** Waiting on pod info it never gets, Tetragon holds events in
   its EventCache (`event-cache-retries:15` × `event-cache-retry-delay:2` = up to **30 s**) before
   exporting them without it. Measured: with the flag on and a 5 s drain the workload's events are
   ABSENT, reappearing only after ~45 s. **A lesson that stops its sensor when the workload finishes
   would report NOT LOGGED for every attack** — the exact false blank this repo exists to prevent.

**Resolution.** The sensor is configured exactly as chapter 2 configures it (which also preserves the
one-instrument-across-every-rung argument), and the leaves attribute events to one named pod by
**container id**: `process.docker` matched against the pod's own `containerID` read from the k8s API.

**The attribution rule inverts between chapters, and both halves are measured:**

| rung | `process.docker` | pid namespace | what the leaves use |
| :-- | :-- | :-- | :-- |
| chapter 2 (rootless podman) | **empty on the workload**, lands on host-side podman/crun/conmon | works | pid namespace (2.2.1) |
| chapter 3 (kubelet) | **populated** | works, but cannot separate the attack pod from the gateway pod | **container id** |

Measured on the audit box: every event bearing a container id was in a non-host pid namespace, and no
host-side runtime process carried one — so container-id attribution needs no extra conjunction.

### The gVisor trace path (gate G2), and its two traps

`gvisor-trace` works on k3s: a pod under it reports `4.19.0-gvisor` and the sentry's boot log carries
the app's syscalls verbatim (`E openat(AT_FDCWD /app, … /sandbox/.ssh/id_rsa, …)`). Two things cost a
round each:

- **`debug-log` must end in a slash.** runsc then treats it as a directory prefix and appends
  `<timestamp>.<command>.txt`, so `boot` — the only log with the application's syscalls — gets its own
  file. A plain path puts every command's log in one file and boot is overwritten.
- **Read the containerd plugin name as ROOT.** The generated config is mode 0600; an unprivileged
  `grep` returns "permission denied", falls through to the containerd-1.x branch, and appends a
  correct-looking block to a template k3s never reads. The pod then sits in `ContainerCreating`
  forever, which reads like a broken runsc install. (This bit me directly during discovery.)
- **`mkdir -p /etc/containerd`.** It does NOT exist on a k3s node. Missing it fails the substrate with
  `No such file or directory` — and it passed incremental testing only because a hand-run probe had
  created the directory. **Caught by the from-scratch run**, which is the argument for always doing one.

### Design decisions worth not re-litigating

- **`gvisor-trace` is a SECOND RuntimeClass**, not tracing on 1.3.2's `gvisor`. strace costs real time
  per syscall: `syscall_ms` is ~1700 in 2.3.2 against 1.3.2's ~209 on the identical boundary. Merging
  them would publish the instrument's cost as the boundary's.
- **2.3.1 turns off exactly two of 1.3.1's controls** (`automountServiceAccountToken`, one
  NetworkPolicy clause for the apiserver) and says so, because a sensor cannot record an attack the
  boundary stopped from being attempted. Containment 13/19 vs 1.3.1's 14/19, one row apart. Same move
  as 2.2.4's canaries.
- **2.3.4 needs NO canaries**, unlike 2.2.4: auditd fingerprints a `type=PATH` record (needs a real
  inode), Tetragon hooks the open *syscall* (fires on the attempt). 2.3.4 is a true twin — 17/19,
  **zero rows** different from 1.3.4.
- **Every "the sensor saw nothing" claim is guarded.** 2.3.2 and 2.3.6 refuse to report unless the same
  trail shows Tetragon recording *other* containers on the node in the same seconds. A sensor that
  never attached and one that cannot see through the boundary produce an identical empty column.
- **Tetragon export rotation raised to 512 MB, compression off** (chapter 3 only). install.sh's
  drop-ins default to 10 MB + gzip, so a long trail rotates mid-run and the lesson reads a truncated
  segment — the auditd `max_log_file` trap of 2.2.4 in new clothes. It changes nothing the sensor sees.
  **Chapter 2's substrate does not have this yet** and should get it, but that needs 2.2.1–2.2.3
  re-verified, so it was left alone rather than changed untested.

---

## Chapter 4 audit — built 2026-08-15, and what it cost to find

Four leaves under `tutorial/phase2-audits/chapter-4-openshift/`, all verified on a from-scratch
`openshift-sno` that was then destroyed. New shared module: `nodeaudit.py` (copied per leaf, as the
repo's no-shared-package rule requires).

**The chapter's phase-2 thesis mirrors its phase-1 one.** Phase 1: OpenShift adds *admission*, not
isolation. Phase 2: **the platform audits the CONTROL PLANE, not the kernel.** The kube-apiserver
audit log is on by default and readable with `oc adm node-logs --role=master`; the node's `auditd` is
running and watching nothing (two `exclude` rules, no syscall rules).

### Attribution — a third mechanism, and uid is the trap

Every pod gets its own **SELinux MCS** pair, stamped by the kernel into `subj=` on every
`type=SYSCALL` record. Three chapters now use three keys, each forced by the platform:

| chapter | key | why not the others |
| :-- | :-- | :-- |
| 2.2.1 | pid namespace | rootless podman leaves `process.docker` empty on the workload |
| 2.3.1 | container id | the kubelet fills it; pid-ns cannot separate the attack pod from the gateway |
| 2.4.1 | **SELinux MCS** | uid is shared — a `uid=1001` rule also catches `service-ca-operator` |

**The correlation subtlety** (cost one wrong result): an audit event is a `type=SYSCALL` record plus
`type=PATH` companions sharing a serial. The pod's MCS is on the SYSCALL record (`subj=`, the
process). The PATH record's `obj=` is the FILE's context, which carries the pod's MCS only for files
in the container's own layer and **never** for `/proc` or `/sys`. Matching PATH by MCS reported
**2/13** where the truth is 4/13. Resolve serials first.

### Two traps that made 2.4.1 intermittent (4/13 then 0/13, both with `lost=0`)

1. **Backlog** — RHCOS ships `backlog_limit 8192`, overrun by a Python interpreter's imports under an
   `openat` rule. Raised to 65536, and the lesson now **asserts `lost == 0`**.
2. **Rotation** — `max_log_file = 8` MB with `ROTATE`; a segment fills in under a minute, so the
   attack's records are in `audit.log.1` before the lesson reads. Chapter 2 fixed the equivalent by
   editing `auditd.conf`; **not available here** (immutable image), so the leaves read the rotated
   segments instead. With both handled, back-to-back runs give 4/13 and 4/13.

### Per-leaf findings

- **2.4.2 is the sharpest inversion in phase 2.** SCC admission is the ONLY boundary on the whole
  ladder that records what it refused: a 403, the asking identity, the full SCC evaluation, nothing
  installed. The rule: *a boundary records its refusals only when its decision is itself an event the
  platform already audits.* Kernels decide in silence; admission decides by answering an API call.
- **2.4.3 is the negative result.** Node auditd: 0 paths vs 2.4.1's 739 (guarded — `lost=0`, 17 992
  keyed records overall). A Kata pod reports **no MCS** to the node, so there is not even a key. And
  2.3.3's ptrace-sidecar rescue is **structurally unavailable**: the sidecar sees the workload
  (`shareProcessNamespace` works) but has no tracer — no `strace` in the stock UBI image, chapter 4
  cannot build images, and `dnf` refuses (read-only rootfs; non-root uid behind it).
- **2.4.4 needs a `subj_type=container_t` rule, not a uid one.** OpenShell owns its sandbox pod spec
  and sets no `runAsUser`, so there is no uid to guess or read — a uid-scoped rule recorded 0 paths
  for a runc sandbox whose syscalls demonstrably reach the kernel. Scope by SELinux type; let the MCS
  say whose. That also means reading EVERY rotated segment, not three.

### 1.4.6 does not work on OpenShift — so 2.4.6 has no boundary to audit

Measured while verifying the long-standing UNVERIFIED 1.4.6. OpenShell's supervisor builds a nested
network namespace with a **veth pair** (that is how its L7 proxy intercepts), and the sandbox
crashloops:

```text
Network namespace creation failed and proxy mode requires isolation.
/usr/sbin/ip link add veth-… type veth peer name veth-… failed: Error: Unknown device type.
```

Confirmed from inside a Kata pod on 4.18.49 + OSC 1.12.1 + OpenShell 0.0.99. The identical overlay
works on k3s (1.3.6, audited by 2.3.6). 1.4.6's README asserts the composition holds on OpenShift;
that is now known to be false, and the leaf needs reframing.

**The diagnosis was corrected on 2026-08-15 — do not repeat the earlier wording.** It is *not* a
kernel-config difference: the OSC Kata guest kernel **is** the node's RHEL kernel version (identical
`uname -r`, which is why 1.4.3/1.4.6 assert the VM by DMI — Trap #12). What is missing is `veth.ko`
from the **guest image's module set**. Red Hat's KATA-5628 is the same bug class (`nfsv4` /
`dns_resolver` present on the node, absent in the guest), fixed by rebuilding the `kata-containers`
RPM. **KATA-5840 — "[Docs] Agent Sandbox: OpenShell support (additional kernel modules)" — is
scheduled for OSC 1.14 (planned 2026-10-01).**

**The whole record now lives in 2.4.6's README**
([`tutorial/phase2-audits/chapter-4-openshift/lesson-06-audit-compose-kata-openshell/README.md`](../../../tutorial/phase2-audits/chapter-4-openshift/lesson-06-audit-compose-kata-openshell/README.md)) —
versions, the vendor evidence, why OpenShell's `deny_unknown_fields` driver-config allow-list rules
out the hostPath+`insmod` workaround, a calibrated confidence estimate, and a five-minute probe to run
**before** any lesson work. Read it before touching 1.4.6 or 2.4.6.

### Infra bugs found and fixed while doing this

- **`install.sh` exited 0 on a failed KataConfig.** The operator's CSV reports `Succeeded` before its
  controller-manager has endpoints, so the apply hit a webhook with no backend
  (`no endpoints available for service "controller-manager-service"`) — and the unchecked `oc apply`
  let the script finish green with **no Kata on the cluster**. Now retried for 5 minutes and `die`s.
  (The controller was also crashlooping on `stale GroupVersion discovery: metrics.k8s.io/v1beta1` — it
  starts inside the metrics-server rollout window. Self-clears; a NEW trap, not in REPRODUCE.md.)
- **hostPath PVs were `persistentVolumeReclaimPolicy: Delete`.** There is no deleter for hostPath, so
  every released volume went to `Failed` permanently. With 4 PVs and one held by the gateway, the
  chapter got **three sandboxes ever**; the fourth hung `Pending` on `unbound immediate
  PersistentVolumeClaims`, which reads like a broken gateway. Now 12 PVs with `Retain`, plus a
  `free_pvs()` that clears `claimRef` on Released/Failed volumes and runs as part of `--from storage`.
- **`uv.lock` was corrupt in BOTH phase-1 OpenShell leaves** (1.4.4 and 1.4.6) — `Dependency 'anyio'
  has missing 'source' field`. Both were unrunnable; regenerated.
- **The OpenShell gateway degrades after repeated sandbox churn** (`sandbox exec` times out at 180 s).
  Restarting the `openshell-0` pod clears it. Already known from chapter 2; it reproduces here.

---

## Box / account state

**No live box.** The chapter-3 audit cycle ends with an EXIT-trap teardown; the chapter-4 cluster was
destroyed by hand on 2026-08-15 (`infra/down.sh openshift-sno`). Verified empty afterwards:
`scw baremetal server list` → none, and `scw instance server list` / `block volume list` /
`instance volume list` / `instance ip list` (zone `fr-par-1`) all `0`, with no `.state/*.env` left.
**Never trust `destroyed, billing stopped`** — it prints before the API finishes; re-query all of
them (sbs root volumes live in the **block** api, not `instance volume list`, and the SNO box is
**baremetal**, which `instance server list` does not show at all).

> **The chapter-4 cluster is the expensive one and nothing tears it down for you.** ~2 h to install,
> EUR 0.263/hr. `install.sh --preflight` is free and worth running first; `--from <stage>` resumes.

---

## 2.3.3 — built, and it CORRECTS discovery gate G1

The last chapter-3 leaf, and the one whose plan was wrong. Worth reading before anyone re-opens the
"in-guest sensor" question, because the negative result cost four pod rounds to establish.

**G1's reframe said**: a workload container under nerdctl cannot stand up a kernel-side sensor in the
Kata guest (`auditctl` → EPERM), *but* a privileged Kubernetes pod holding "the guest's init context"
could — so the eBPF/auditd sidecar lands in 2.3.3.

**Measured: it cannot, and privilege is not what is being checked.** All four combinations tested on a
live cluster, every one `EPERM` from the guest's audit netlink:

| sidecar | CapEff | result |
| :-- | :-- | :-- |
| uid 1000, `capabilities.add` | `0000000000000000` (added caps are dropped for a non-root user) | EPERM |
| `runAsUser: 0` + explicit caps | `000000e0e82c25fb` | EPERM |
| `runAsUser: 0` + `privileged: true` | `000001ffffffffff` | EPERM |
| the above **+ `hostPID: true`** | `000001ffffffffff` | EPERM |

The kernel gates the audit netlink on the **initial pid namespace**
(`task_active_pid_ns(current) != &init_pid_ns`), and Kata's agent puts the whole pod in a child one.
The decisive evidence is that the process list under `hostPID: true` is **unchanged** — `pause` is
still PID 1, still 5 processes — so **under Kata the kubelet's "host" is the sandbox, not the VM's
init**. There is no pod-spec field that reaches the guest's init namespace.

**What works** is a **ptrace tracer**, for exactly 2.2.3's reason: it needs no netlink and no initial
namespace. What Kubernetes adds — and nerdctl cannot — is `shareProcessNamespace: true`, one pid
namespace for every container in the pod *inside the guest*, so the sidecar can see and trace the
workload. Under nerdctl one container is one VM and there is nothing to share. So Kubernetes does
rescue the rung, just not the way predicted and not with a kernel-side sensor.

**And the guest kernel is not the obstacle**: the sidecar LOADS a real two-instruction eBPF program
(`loaded`) with BTF present. The fence is specific to audit; eBPF is not namespace-gated. A CO-RE
eBPF sensor could live in the guest — it would simply have to be shipped into the pod, which is the
same per-pod cost the tracer pays.

### The trap in `85-kata-debug-kernel.sh` (cost two rounds)

Under **kata-deploy** — unlike chapter 2's kata-static — `configuration-qemu.toml` is a **symlink**
into `runtimes/qemu/`, and `sed -i` does not follow symlinks: it renames a temp file over the link,
so the edit lands on a new regular file and the config the shim reads is untouched. containerd still
passes the annotation (kata-deploy sets `pod_annotations = ["io.katacontainers.*"]`), the shim
rejects it as not enabled, and the pod sits in **ContainerCreating forever** — which reads like a
broken Kata install. The substrate now resolves the path with `readlink -f`, preferring the
`ConfigPath` out of containerd's own kata-deploy drop-in.

**BTF presence is the only discriminator.** Both kernels report `6.18.35`, so a `uname` comparison
passes on a guest that never got the annotation. `check.sh` asserts the contrast: `btf-absent` on the
default guest, `btf-present` on the annotated one.

The substrate runs **after 80-k8s-kata** (kata-deploy lays down `/opt/kata` when its DaemonSet starts,
so an earlier edit is overwritten) and **restarts nothing**, so it is safe there.

### Other 2.3.3 mechanics worth keeping

- **The handshake.** The sidecar must attach *before* the workload runs or it misses the credential
  read. Both containers share an `emptyDir`; the workload blocks on `/coord/go`, the sensor creates it
  only after `strace` is attached. A real property of sidecar sensors, left visible rather than hidden.
- **`kubectl logs` refuses on a multi-container pod**, so this leaf's `k8s.py` `run_pod` takes a
  `container=` name and selects every status by `containerStatuses[?(@.name==...)]` rather than `[0]`
  (which is right only because `agent` sorts before `sensor`). It also takes `delete=False`, because
  the sensor's verdicts have to be read before the pod is removed.
- **The trace never leaves the guest.** The sidecar greps its own `strace` output in-guest and emits
  one `SBX_FP <probe>` line per fingerprint; the fork bomb floods that file to tens of MB.

---

## Reuse these patterns (all built and verified)

- **The leaf skeleton** — `main.py`, `README.md`, `run.sh` (up→run→destroy EXIT trap, generic id/box
  resolution), `pyproject.toml` (extend `../../../../ruff.toml`), `.gitignore`, `uv.lock`; copy
  `scorecard.py` and `k8s.py` from a sibling. **Use the chapter-3 audit `k8s.py`** — its `run_pod`
  returns a 4-tuple including the pod's `containerID`, which the attribution needs and which the
  phase-1 copies do not have. Regenerate `pyrightconfig.json` after adding a leaf (`uv sync` in the
  leaf first, or the generator skips it).
- **The two-sensor mapping** — `combine()` = the union onto `Finding.recorded`; NOT_LOGGED and
  NO_SENSOR are different diagnoses and the same outcome, so report both as "not recorded".
- **The OCSF parse** — inlined `parse_decisions` (action/method/binary/target) over `openshell logs`;
  canonical source `~/…/agent-eval-benchmark/shared/shared/core/openshell/audit.py`. On k8s, match on
  the Service DNS name (`sbx-gateway` / `sbx-collector`), not on ports as 2.2.4 does.
- **The sentry trace mapping** — 2.3.2/2.3.5's `sentry_recorded()`; grep the boot logs **on the box**
  (the fork bomb floods them to tens of MB) and never read them into Python.

---

## READ THIS if you touch auditd (the 2.2.4 saga — three non-obvious `auditd.conf` requirements)

Each read as a workload/sandbox problem and each cost a from-scratch run. All fixed in
`chapter-2-audit/auditd-guest.sh` and **asserted by `check.sh`**; reuse them anywhere you run in-guest
auditd (e.g. if 2.3.3's sidecar uses auditd rather than raw eBPF):

1. **`log_format = RAW`** — Debian defaults to `ENRICHED`, which concatenates interpreted fields
   (`key="sbx_open"ARCH=…SYSCALL=…`) and prefixes `node=`, breaking every `grep type=PATH … name="…"`.
2. **`max_log_file = 500`** — the 8 MB default **rotates the log mid-run** under the suite's volume, so
   the sensitive records land in `audit.log.1` the mapping never reads. This was the intermittency: a
   probe read `LOGGED` one run and blank the next.
3. **Restart auditd** after editing `auditd.conf` — `systemctl enable --now` is a **no-op** on an
   already-running daemon, so 1+2 never applied until the restart was added. **Verify the LIVE daemon**,
   not the conf file (a fresh RAW record has no `ARCH=`/`SYSCALL=` interpreted fields).

And **map by RAW `type=PATH name="…"`**, never a `comm=`/`uid=` substring grep — those matched the
lesson's OWN `grep` commands (audited as EXECVE args) and `euid=`/`fsuid=` substrings. The
capability-denied kernel probes (bpf/io_uring/perf) ARE recorded by auditd: an `EPERM` syscall still
exits, so the audit hook fires.

---

## Gotchas (save re-discovery)

- **Tetragon `--enable-k8s-api` on k3s** — see the boxed section above. Do not re-enable it.
- **auditd on the guest** — see the boxed section above (RAW / max_log_file / restart / map-by-PATH).
- **Kata + `--privileged` FAILS** (`/dev/full … EEXIST`) — use explicit `--cap-add` under Kata.
- **auditd inside a Kata *workload container* does NOT work** by design (audit netlink is
  initial-namespace-only; `--pid host`/`--net host` don't lift it). The privileged pod sidecar (2.3.3) is
  the answer, not retries.
- **`nerdctl build` (BuildKit) cannot `FROM` a local-only containerd image** (pull denied) — derive from
  a registry base and assemble the context from `infra/images/agent`.
- **`enable --now` ≠ restart** — a running daemon keeps its old config until an explicit restart.
- **The repo rsync to a box is slow (~774 MB)** — `infra/tui/node_modules` and the `openshift-sno` `oc*`
  / `openshift-install` binaries aren't excluded in `up.sh`'s rsync. Normal, not a hang.
- **macOS has no `timeout`** — wrap box-side commands in a box-side `timeout N` (via `ssh.sh <box>
  'bash -s' < script.sh`), and NEVER run a lesson's `main.py` on the workstation.
- **OpenShell execs go flaky after heavy poking on one box** — many manual `sandbox create/delete/exec`
  cycles degrade the gateway. Do focused discovery on a `--keep` box; verify with a **fresh** cycle.
- **The gVisor rung's fork bomb kills the sandbox.** The sentry and its stubs live inside the
  container's cgroup, so `resource_exhaustion` never reaches stdout and the card is one row short. 2.2.2
  lets the row vanish; **2.3.5 names it explicitly** (`sandbox-died:exec-relay-closed`, `contained=None`
  unless the pod says `OOMKilled`) — prefer that shape.
- **`up.sh` exits early when a `.state` file exists**, so a chapter runner cannot rebuild a box that is
  already up. `down.sh <box>` first when you want a genuinely fresh provision.
- **A hand-patched box is not a verified box.** Substrates that were fixed by hand mid-session must be
  re-run from scratch before any result is reported — the `/etc/containerd` bug above existed only
  because an incremental run had a directory a fresh one does not.

---

## What's already built (reference)

- **Chapter 3 audit (this session)** — `2.3.3` (host Tetragon 0 vs 125 on other containers; in-guest
  ptrace sidecar 12/19; containment 14/19, zero rows different from 1.3.3; audit netlink EPERM even
  privileged, eBPF program `loaded`) · `2.3.1` (Tetragon 7 + apiserver 1 = 8/19; containment 13/19 vs
  1.3.1's 14/19, one row) · `2.3.2` (sentry 10/19 from ~97k syscalls, Tetragon 0 vs ~190 on other
  containers; containment 16/19, zero rows different from 1.3.2) · `2.3.4` (Tetragon 7 + OCSF 8, overlap
  4 = 11/19; containment 17/19, zero rows different from 1.3.4) · `2.3.5` (12/18, 6 HIGH
  `landlock-unavailable` while `fs_policy_write` stays BLOCKED — the masked-loss finding, witnessed) ·
  `2.3.6` (8/19 all OCSF; Tetragon 0 vs 109 on other containers; containment 17/19).
- **2.2.4** — two disjoint sensors, **15/19**. auditd catches 8 local/kernel attacks, OCSF the 8 network
  ones, `malicious_package` the overlap. Only `fs_policy_write` is caught by neither.
- **2.2.3** — host Tetragon **fully blind** behind Kata's guest kernel (0 recorded); coverage recovered
  only by an in-guest **strace** on the BTF/`AUDITSYSCALL` debug kernel (12/12).
- **2.2.1 / 2.2.2 / 2.1.1** — Tetragon on the container rung (sees through it, 7/13); `runsc --strace`
  on the gVisor rung (host blind, sentry 11/12); host auditd on the no-sandbox rung (11/13).
- **Boxes:** `chapter-01-audit` (2.1.1), `chapter-02-audit-host` (2.2.1–2.2.3), `2.2.4` on its own
  NAT-guest box, `chapter-03-audit-k8s` (all six 2.3.x).
  Regenerate `results/overall.html` (`python3 infra/report/overall.py`) after any lesson re-run, or the
  cross-lesson view silently shows the previous numbers.
- **Lint gate:** clean; the only finding is the pre-existing `infra/chapter-02.sh:82` (SC2016).
