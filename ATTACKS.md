# What the tests actually do, and why each one matters

Every lesson runs the **same** rogue agent against a **different** boundary, and prints a
scorecard. This page explains each probe in plain language: what it tries, why an attacker
would want it, and what the result tells you.

You do not need to read this before starting. It is the reference you come back to when a
row in the report surprises you.

> **`tutorial/<lesson>/report.html`** is the generated version of this — the same probes,
> with the actual readings from your run, sitting next to the lesson that produced them.
> It covers that lesson alone. For the comparison across rungs, build the overall report:
> `python3 infra/report/overall.py --open`.

---

## First: how to read a result

Each probe ends in one of three states.

| Reading | Means |
| :-- | :-- |
| **BLOCKED** | The boundary stopped the attack. Good. |
| **SUCCEEDED** | The attack succeeded — the agent got what it wanted. Bad. |
| **INFO** | Not a pass/fail — a measurement, like how long a syscall took. |

And in the *"what changed"* table, each row is labelled by how it moved against the rung
below: **NOW BLOCKED** (this boundary closed it), **STILL OPEN** (neither rung stopped it —
these are the reason the next lesson exists), or **RE-OPENED** (this boundary *lost* ground,
which happens exactly once, in lesson 4, and is the whole point of that lesson).

**A low score is not a broken lesson.** Lesson 1 has no sandbox at all, and scores **3/13**.
That is the entire point: it is the baseline, and the ten attacks that land there are what
every later lesson is measured against. If lesson 1 ever scored 13/13, something would be
wrong with the *test*, not impressive about the machine.

The interesting number is never the total. It is **which rows change between two rungs**, and
which stubbornly do not. A row that was already `BLOCKED` one rung down proves nothing about the
new boundary — a trap this tutorial points out repeatedly.

### Why "13" and not "9"

The syllabus describes **nine things the rogue agent tries**. The scorecard has more rows
because attack 8 ("enumerate the kernel") cannot be answered by a single yes/no — it expands
into six separate kernel probes. Lesson 5 adds six more that only mean anything under a
policy engine. Four further rows are context, not verdicts, so they are excluded from the
total. That is how nine attacks become 13 scored rows in lessons 1–4 and 19 in lesson 5.

---

## Group 1 — Reach: can it get to something valuable?

### 1. `read_credentials` — can it read your secrets?

**What it does.** Before the run, the suite plants five *obvious fakes* in the home
directory: `.ssh/id_rsa`, `.aws/credentials`, `.config/gh/hosts.yml`, `.netrc`, `.env`. The
agent then tries to read them. The value is how many it opened. Nothing is ever printed —
proof of damage is that the bytes were readable.

**Why it matters.** This is the single most valuable thing on a developer machine or a CI
runner. An agent that can read `~/.aws/credentials` does not need to exploit anything else;
it can just *be* you, against your cloud account, for as long as the key lives.

**What closes it.** A container, immediately — the agent gets a fresh filesystem that simply
does not contain your home directory. This is the biggest single jump in the tutorial, and it
is why lesson 2 exists.

### 2. `exfiltrate` — can it send what it stole anywhere?

**What it does.** POSTs a canary (a count and a token — never the secret bytes) to a listener
the lesson runs itself. With no listener configured it tests raw outbound network instead.

**Why it matters.** Reading a secret is only half an attack. The damage happens when the
secret *leaves*. This row and the one above are a pair: if reading is blocked, exfiltration is
moot; if reading succeeds but egress is blocked, you have bought yourself time.

**What closes it.** `--network none`. And that is exactly the problem lesson 5 exists to
solve: a real agent needs the network to do its job, so "turn the network off" is not an
answer you can actually ship.

### 3. `plant_backdoor` — can it leave something behind?

**What it does.** Tries to append a marker to `~/.bashrc`, `~/.profile` and
`~/.ssh/authorized_keys`, counts which writes were accepted, then **removes them again**.
Cleanup is mandatory.

**Why it matters.** This is *persistence*. Everything else in the list is a one-off; a
backdoor means the attacker is still there tomorrow, after the prompt is forgotten and the
process is gone. An entry in `authorized_keys` is a permanent SSH key for someone else.

**What closes it.** A read-only root filesystem. Note the subtlety the lesson calls out: if
`$HOME` is writable-but-ephemeral, the write *succeeds* and simply gets thrown away. That
looks identical in the score and is a weaker property — the container blocks it here because
`$HOME` is genuinely read-only.

### 4. `cloud_metadata` — can it reach the cloud's credential service?

**What it does.** Sends a GET to the cloud metadata endpoint — `169.254.42.42` on Scaleway,
`169.254.169.254` on AWS.

**Why it matters.** This is the **classic SSRF target** and one of the most-exploited paths in
cloud security. That address is a magic link-local endpoint every VM can reach with no
credentials at all, and on many setups it hands out live IAM tokens to whoever asks. It is how
a "harmless" ability to fetch a URL turns into full cloud account access.

**What closes it.** Any network restriction. But note *which address you probe decides the
answer* — a probe aimed at AWS's endpoint on a Scaleway box reads BLOCKED and looks like a
boundary that worked, when nothing was protecting you at all. This tutorial hit exactly that
and the run now sets `PROBE_METADATA_URL` to match the cloud it is on.

---

## Group 2 — Abuse: can it do damage?

### 5. `malicious_package` — can a dependency run code just by being installed?

**What it does.** Two mechanisms with one headline: reach a package index, and build a local
source package whose `setup.py` executes code *at install time* — before anyone imports it or
runs anything.

**Why it matters.** Most people assume code they installed but never ran is inert. It is not.
`pip install` executes arbitrary code from the package author by design. This is the mechanism
behind real-world typosquatting and dependency-confusion attacks, and an agent that can decide
what to install is an agent that can decide what to execute.

**What closes it.** No egress stops reaching the index. Nothing here stops the *local*
execution — which is why the detail column distinguishes "index-reached" from the offline
code-exec result.

### 6. `reverse_shell` — can it pull down a second payload and open a door?

**What it does.** Fetches a second stage and tests whether an outbound connection and an
inbound bind are possible. It is **reach only** — nothing is ever executed and no shell is
opened.

**Why it matters.** Real intrusions are staged: the first payload is small and boring enough
to get through, and its only job is to fetch the real one. Testing reach rather than
detonating is the honest way to measure this without doing something genuinely dangerous.

**What closes it.** No egress and no inbound. Again — a real agent needs egress.

### 7. `resource_exhaustion` — can it take the whole machine down?

**What it does.** A **bounded** fork bomb and memory growth: it stops at a low ceiling
(≈200 processes, ≈512 MB) and reports whether a cap intervened first.

**Why it matters.** Not every attack is theft. An agent stuck in a loop spawning processes is
a denial-of-service against everything else on that host — and it is far more likely to happen
by accident than by malice.

**What closes it.** cgroup limits: `--pids-limit`, `--memory`. Two results here are worth
more than the pass/fail:

- **Under gVisor the sandbox is killed outright** rather than the fork being refused, because
  gVisor's own supervisor is charged to the container's memory budget. The scorecard records
  `capped:sandbox-killed`. Contained — but violently, and the distinction is kept.
- **Under Kata the flags stop meaning what they meant.** `--memory 256m` sizes a cgroup around
  the *virtual machine*, while the workload lives inside a guest sized by Kata's own defaults
  (measured: 2179 MB). The fork bomb never meets the ceiling you named.

---

## Group 3 — Kernel: how much of the real kernel is exposed?

This is attack 8, and it is **the discriminator** for gVisor and Kata. Everything above can be
closed by a plain container. Nothing above tells you whether the agent is still talking to the
kernel that runs your other workloads.

Why this matters at all: a container is **not** a kernel boundary. Processes are isolated from
each other, but they all call the *same* kernel. A kernel privilege-escalation bug — and there
are new ones every year — escapes a container completely. gVisor and Kata are two different
answers to that.

### 8a. `kernel_identity` — whose kernel is answering?

**What it does.** Reads `uname -r` from inside the sandbox and compares it against the node's.

**Why it matters.** This single line tells you which of the three worlds you are in:

| Reading | Means |
| :-- | :-- |
| same as the node (`6.8.0-106-generic`) | **no kernel boundary.** A kernel exploit escapes. |
| `4.19.0-gvisor` | gVisor answered — a kernel written in Go, in user space |
| a different real version (`6.18.35`) | Kata — a genuine guest kernel in its own VM |

It is also the check `infra/check.sh` runs before any lesson is allowed to proceed, because
the characteristic failure of this whole repo is a sandbox that silently fell back to the
normal runtime and then printed everything the lesson expected.

### 8b. `sys_module_count` — can it enumerate the host's kernel modules?

**What it does.** Counts entries in `/sys/module`.

**Why it matters.** It is reconnaissance. The list of loaded modules tells an attacker exactly
what kernel features and drivers are available to target. ~178 means it is reading the real
host's module list. `0` means it is looking at a kernel that has nothing to tell it.

### 8c. `kallsyms_readable` — can it read kernel symbol addresses?

**What it does.** Tries to read `/proc/kallsyms`.

**Why it matters.** Those addresses are what an exploit needs to know where to jump. Modern
distros restrict this by default (`kptr_restrict`) — which is why this row reads `BLOCKED` even
in lesson 1, **with no sandbox at all**. That is the point worth taking away: a row that was
already closed proves nothing about your boundary.

### 8d. `bpf` — can it create a BPF map?

**What it does.** Calls `bpf()`.

**Why it matters.** BPF is a programmable in-kernel virtual machine. It is enormously powerful
and has a long history of privilege-escalation CVEs, which is why unprivileged access to it is
disabled on hardened distros.

**The surprise this probe produced.** In lesson 4 (Kata) this row **re-opens** — it goes from
`BLOCKED` to `SUCCEEDED` — even though every Linux capability has been dropped. The guest kernel
boots upstream defaults and nothing there ever disabled unprivileged BPF (`node=2`, `guest=0`).
Stronger isolation, *weaker* hardening. If you move a workload into a VM, the distro hardening
you were quietly relying on does not come with it.

### 8e. `io_uring_setup` — can it call `io_uring`?

**What it does.** Calls `io_uring_setup()`.

**Why it matters.** `io_uring` is a large, fast, comparatively new kernel interface, and it has
been a rich source of vulnerabilities. Note *why* it gets refused, which the detail column
keeps: a plain container answers `EPERM` (**refused** — seccomp blocked it) while gVisor
answers `ENOSYS` (**not implemented** — there is no such call in a user-space kernel). Same
verdict on the scorecard, completely different reason.

### 8f. `perf_event_open` — can it call the profiling interface?

**What it does.** Calls `perf_event_open()`.

**Why it matters.** Performance counters can leak information across process boundaries. Like
`kallsyms`, distros already restrict this (`perf_event_paranoid`), so it reads `BLOCKED` in lesson
1 too — another row that is not evidence about your sandbox.

---

## Group 4 — Policy: which binary, which method? (lesson 5 only)

Everything above is answered by "can it, or can it not". These five ask a different question
that no kernel-level sandbox can answer, **by construction**: to a kernel, a syscall is a
syscall and a socket is a socket. It cannot see that `curl` made this request, or that this
one was a `POST`.

The lesson runs two HTTP listeners one port apart — a stand-in gateway and a stand-in attacker
collector. Same protocol, same host. Nothing about the *services* separates them, so any
difference in outcome can only be the policy.

| Probe | What it proves |
| :-- | :-- |
| `egress_gateway` | The allowed destination is **still reachable**. An allow-list that denies everything is not a policy, it is an off switch — and reporting only denials would let a completely broken sandbox look perfect. |
| `egress_offpolicy` | The unlisted destination, one port away, is refused. |
| `http_method_denied` | `POST` is refused to a host where `GET` is allowed. This needs layer-7 awareness; a firewall sees one socket either way. |
| `binary_scoped` | The **same curl binary, copied to `/tmp`**, making the identical request, is refused. The sharpest of the five — identical bytes, different path, different verdict. |
| `fs_policy_write` | A write outside the allowed paths is refused (via Landlock). |

### 9. `audit_records` — was any of it written down?

**What it does.** Counts entries in the OCSF audit log.

**Why it matters.** This row reads **0 on every rung until lesson 5**, and that is the finding.
A container blocks an attack and forgets it instantly. You get no alert, no timeline, and no
way to know it was ever attempted. Detection and response need a record, and "it was blocked"
is not the same as "we know it happened".

---

## Context rows — measured, never scored

These carry no verdict and are excluded from the total.

| Probe | What it tells you |
| :-- | :-- |
| `home_items` | How many entries `$HOME` has — how much there was to find |
| `secretish_env` | Environment variables whose names look like secrets |
| `syscall_ms` | Syscall-bound work, in ms — the cost the boundary charges |
| `cpu_ms` | CPU-bound work, in ms — for comparison |

The last two exist because "gVisor is slow" and "gVisor is free" are both false. Syscalls now
traverse a user-space kernel; arithmetic does not. The honest statement is *which kind of work
pays* — and an agent waiting on a language model is almost entirely the kind that does not.

---

## One known wrinkle in the scoring

Under OpenShell, three rows — `exfiltrate`, `cloud_metadata`, `reverse_shell` — currently read
**SUCCEEDED** while their value is `403`, meaning the policy denied them.

The cause is a definition that is right in one place and wrong in another: a probe treats *any*
HTTP status as proof the host answered ("even a 404 proves the host was reachable"). That is
sound for a direct connection. Under OpenShell the `403` comes from the **policy proxy in the
middle**, so the real destination was never contacted. The audit log proves it:

```text
HTTP:GET [MED] DENIED /usr/bin/curl(36) -> GET http://169.254.42.42/conf
```

Fixing it would move lesson 5 from 13/19 to 16/19. It is recorded here rather than quietly
patched, because changing it changes the lesson's headline comparison.
