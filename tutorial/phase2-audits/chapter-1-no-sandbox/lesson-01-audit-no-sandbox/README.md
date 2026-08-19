# Lesson 2.1.1 — Auditing the no-sandbox baseline

**Phase 2 audits what phase 1 measured.** [Lesson 1.1.1](../../../phase1-attacks/chapter-1-no-sandbox/lesson-01-no-sandbox/)
asked *did the boundary hold?* — and at the no-sandbox rung the answer was "there is no boundary", so
all nine attacks landed (3/13 blocked). This lesson asks the second question: **would you ever know
the attacks were tried?**

It runs the **same** nine attacks as a bare host process, with the host kernel's **`auditd`**
subsystem watching, then reports — per attack — a **RECORDED** verdict: `LOGGED`, `NOT LOGGED`, or
`no sensor`.

## The finding

Near-everything is **LOGGED**. The rung with *zero isolation* has *near-total observability*, because
there is no boundary between the attack's syscall and the kernel that audits it. Put the RECORDED
band here beside the wall of **`no sensor`** on every phase-1 report and you have the whole thesis of
phase 2 in one comparison:

> The observability ladder runs **backwards** to the isolation ladder. Every stronger boundary above
> this one trades audit coverage away — a host sensor sees only the sentry's readout under gVisor, and
> nothing at all inside a Kata guest.

## How the mapping works

`auditd` records **syscalls**, not claims. The substrate
[`infra/substrates/chapter-1-audit/10-auditd.sh`](../../../../infra/substrates/chapter-1-audit/10-auditd.sh)
loads one **keyed** rule per attack fingerprint (`sbx_exec` for `execve`, `sbx_net` for `connect`,
`sbx_bpf`/`sbx_iouring`/`sbx_perf` for the kernel-surface syscalls, `sbx_open` for the credential
reads, plus watches on `/proc/kallsyms` and `/proc/modules`). After the attack run, `main.py` reads
each key with `ausearch -k` and marks the matching probe `LOGGED`. The keys and the probe→key map
(`PROBE_KEYS` in `main.py`) are two halves of one fact — change them together.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.1.1     # provisions chapter-01-audit, installs auditd, asserts it is watching
# then, from this directory:
uv run python -u main.py                  # runs on the box, brings the card home, writes results/2.1.1.json
```

The box is `chapter-01-audit` (a small VM, auditd only). It is torn down on exit, like every phase-1
box — a native rogue-agent run is only acceptable on a machine about to be destroyed.
