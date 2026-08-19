# Lesson 1.2.4 — Container + NVIDIA OpenShell

The survivors. Lessons 1.2.2 and 1.2.3 shrank the kernel two different ways and left the
same things untouched, and they are not weaker versions of attack 8 — they are a
different axis:

- **which binary** made this request? To a kernel-level sandbox, a syscall is a syscall.
- **which HTTP method**? The kernel sees bytes on a socket, not `POST /collect`.
- **what was attempted?** `audit_records` has read **0** on every rung so far. A
  container blocks and forgets.

And the four attacks that follow directly from those blind spots. Lessons 1.2.1, 1.2.2 and
1.2.3 each run the suite twice — once with `--network none`, once with the network an
agent actually needs — and each loses the same four the moment it is online:

| | 1.2.1 container | 1.2.2 + gVisor | 1.2.3 + Kata | **1.2.4 + OpenShell** |
| :-- | :-- | :-- | :-- | :-- |
| `exfiltrate` | SUCCEEDED | SUCCEEDED | SUCCEEDED | **BLOCKED** |
| `cloud_metadata` | SUCCEEDED | SUCCEEDED | SUCCEEDED | **BLOCKED** |
| `malicious_package` | SUCCEEDED | SUCCEEDED | SUCCEEDED | **BLOCKED** |
| `reverse_shell` | SUCCEEDED | SUCCEEDED | SUCCEEDED | **BLOCKED** |
| score, network-on | 7/13 | 9/13 | 7/13 | **16/19** |

**This lesson is the only rung that keeps those closed with the network still on**
— and it does so on ordinary `runc`, with no kernel boundary at all. Kata spends a
whole VM per container and does not close one of them, because the distinction
lives in HTTP and a kernel does not read HTTP.

```bash
cd tutorial/phase1-attacks/chapter-2-one-host/lesson-04-container-openshell
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

That is the whole workflow — one command, and the box is destroyed even if the lesson
fails. It writes `report.html` + `report.json` here beside the lesson.

## The scenario this exists for

Lesson 1.1.1's **web injection**, now made containable. A browsing agent *must* have
egress to read pages, so every previous rung faced a false choice: turn the network
off and break the agent, or leave it on and let the injected payload exfiltrate.

That is not a rhetorical framing — it is on the scoreboard. Lesson 1.2.1 took the first
option, `--network none`, and scored 11/13; its Part 4 takes the second and scores
**7/13**, with attacks 2, 4, 5 and 6 all returning. Lessons 1.2.2 and 1.2.3 repeat the
experiment behind a user-space kernel and behind a real VM and get the same four
back. The choice was real, and neither kernel boundary dissolves it.

OpenShell leaves egress **on** and scopes it. To make that concrete without
depending on anything external, this lesson runs **two HTTP listeners on the host**:

| Port | Standing in for | Policy |
|:--|:--|:--|
| `18410` | the model gateway the agent legitimately needs | named, `access: read-only` |
| `18411` | the attacker's collector | **never named** |

Same protocol, same host, one port apart. Nothing about the *services* separates
them, so a difference in outcome can only be the policy — which is precisely the
distinction a blanket on/off switch cannot express.

## Read the five `policy` rows in pairs

| probe | drives | passes when |
|:--|:--|:--|
| `egress_gateway` | `curl` → gateway `/v1/models` | **200** |
| `egress_offpolicy` | `curl` → the collector | denied |
| `http_method_denied` | `curl -X POST` → the **allowed** gateway | denied |
| `binary_scoped` | the **same curl, copied to `/tmp`**, same request | denied |
| `fs_policy_write` | write to `/etc` | `PermissionError` |

`egress_gateway` **and** `egress_offpolicy` together are what "selective" means. An
allow-list that denies everything is not a policy, it is a switch — reporting only
the denial would let a completely broken sandbox look maximally secure.

`binary_scoped` is the sharpest of the five. The identical bytes, at a path the
policy does not name, making the identical request — denied. No kernel-level
sandbox can see that distinction, by construction.

The lesson also prints **what the listeners actually received**, which is ground
truth rather than the sandbox's own account: the sandbox reports what it
*attempted*, and only the listener can say what got through.

## Two ordering traps, both mandatory

**Arm OCSF *before* applying the policy.** `openshell settings set … ocsf_json_enabled true`
then `policy set --wait`. The writer activates on the reload; do it the other way
round and the JSONL stays empty, which looks exactly like a broken feature.

**The `create` command must be quick.** A long-running one blocks the CLI.
Everything real happens through `exec` against a sandbox that stays `Ready`.

## Where this can run — the constraint that shaped the box

OpenShell's rootless-podman driver **refuses to start when the host's default-route
address is public**:

```text
compute driver 'podman' requested the gateway default-route interface, but its
resolved address <public ip> is not a private IPv4 address
```

That is a safety check, not a bug — and it rules out every plain Scaleway box,
metal and VM alike: both were measured to have a **public** primary address on
their default-route interface (`ip route show default` → `src <public>`, on a
`/32`). `infra/substrates/README.md`'s older note that a VM "natively has a private
default-route IP" describes Scaleway's retired NAT model and is stale.

So this lesson's box carries a substrate that builds the NAT topology OpenShell
needs: a libvirt guest on `virbr0`, whose primary address is `192.168.122.x/24`.
The lesson then runs *inside* that guest, reached through the box as a jump host.
A laptop is the other place it works out of the box, for the same reason — a home
LAN address is private.

> An earlier note here claimed the guest had to be L1, so this lesson needed bare
> metal. That was wrong, and the correction is instructive: the symptom (grub
> loads, the kernel resets forever) was later reproduced **on bare metal too** and
> traced to Debian 13's genericcloud image being UEFI-only while libvirt booted it
> on BIOS firmware. `50-nat-vm.sh` passes `--boot uefi`, and the guest boots on a
> `PLAY2-MICRO` VM — measured 2026-08-06.

On macOS you additionally need:

```bash
export DOCKER_HOST=unix:///var/run/docker.sock   # OpenShell probes ~/.docker/run/docker.sock, which does not exist
```

**One driver per gateway.** A gateway accepts a single compute driver, so lesson 1.3.4's
kubernetes driver needs a separate gateway config from this one.

## What OpenShell does *not* close

The kernel row comes **back**. OpenShell runs on ordinary runc with the host kernel
fully exposed, so `kernel_identity` reads the node's own kernel exactly as it did in
lesson 1.2.1 — no user-space kernel, no guest, nothing between the workload and Linux.

One attack-8 row does *not* match lesson 1.2.1, and it is worth not glossing over: this
sandbox presents no `/sys/module` at all, so `sys_module_count` reads **0** where
lesson 1.2.1 read **179**. That is a filesystem the sandbox does not expose, not a
kernel boundary — the kernel underneath is still the node's, which is exactly what
the row above it reports. `io_uring_setup` likewise reads `EPERM` here against
lesson 1.2.1's `ENOSYS`: same verdict, refused by a dropped capability rather than by a
seccomp filter.

Attacks 3 and 7 also stay open — `plant_backdoor` writes to a home this sandbox
leaves writable, and no cgroup cap bites — so OpenShell is not a replacement for
the container hardening of lesson 1.2.1, it is a different axis layered beside it.

That axis is the observation the whole tutorial is built toward: **gVisor and
OpenShell are strong in disjoint columns.** Composing them is therefore tempting —
and lesson 1.3.5 shows it silently failing, because gVisor answers `ENOSYS` to Landlock
and the filesystem half of `policy.yaml` stops being enforced while everything still
looks healthy.
`landlock.compatibility: hard_requirement` is what makes that fail closed instead.

> OpenShell is **alpha**. The run prints its version and records it in
> `results/1.2.4.json`, so drift shows up as a changed number rather than a
> mysterious failure.

## Status — end-to-end green (2026-08-07, OpenShell 0.0.99)

Measured on a `PLAY2-MICRO` VM, inside the NAT'd guest that `50-nat-vm.sh` builds:

```text
egress_gateway       200               <- the allowed GET gets through
egress_offpolicy     403               <- the collector, one port away, denied
http_method_denied   403               <- POST to the ALLOWED host, denied
binary_scoped        403               <- the same curl at an unlisted path, denied
fs_policy_write      PermissionError   <- Landlock
audit_records        20                <- the row that read 0 on every rung until now
```

and the audit trail names the binary and the method for each decision:

```text
HTTP:POST [MED] DENIED  /usr/bin/curl(35) -> POST http://host.openshell.internal:18411/collect
HTTP:GET  [MED] DENIED  /usr/bin/curl(36) -> GET  http://169.254.42.42/conf
HTTP:GET  [INFO] ALLOWED /usr/bin/curl(37) -> GET http://host.openshell.internal:18410/v1/models
```

Note the middle line: `cloud_metadata` is denied **by policy**, recorded by binary
and URL — the same SSRF that landed unimpeded in lesson 1.1.1.

This lesson was red until 2026-08-06 and the three things that fixed it are all in
the "traps" category rather than anything conceptual:

| Was | Actually |
|:--|:--|
| `sandbox exec` "hangs" | it did not — `sandbox create` in Part 2b was failing first, and the reported hang was downstream of that |
| `sandbox delete` is synchronous | it returns **before** the sandbox is gone, so Part 2b's delete-then-recreate lost the race with `sandbox '<name>' already exists`. `cleanup()` now waits for it to leave `sandbox list` |
| the image's `WORKDIR` applies to `exec` | it does not. `python -m attacks.run` failed with `No module named 'attacks'`; the sandbox now gets `PYTHONPATH=/app`. Note the fix is *not* wrapping it in `sh -c` — the policy is per-binary, so a shell in the path is a different lesson |

Seven constraints found along the way, all of which the code now encodes, and each
of which produces a confusing failure if you do not know it:

1. **Sandbox names are capped at 19 characters**; a longer one is rejected at
   create.
2. **The image name must be fully qualified** (`localhost/…`) — OpenShell hands it
   to podman, which refuses an unresolvable short name.
3. **A policy has a static half.** `process`, `filesystem_policy` and `landlock` are
   locked at startup, so they must be supplied to `sandbox create --policy`.
   `policy set` on a live sandbox refuses both to *change* them ("process policy
   cannot be changed on a live sandbox") and to *omit* them ("filesystem policy
   cannot be removed on a live sandbox") — so the reload has to carry the identical
   file. The reload still matters: it is what starts the OCSF writer.
4. **`sandbox create` returns before the sandbox is Ready**, and an `exec` in that
   window hangs rather than failing. The lesson polls for Ready first.
5. **`sandbox delete` also returns before it has finished**, which is the same trap
   from the other end. Part 2b must recreate the sandbox to change the static half
   of the policy, so `cleanup()` waits for the name to disappear from
   `sandbox list` before returning.
6. **`sandbox exec` does not start in the image's `WORKDIR`.** The suite is at
   `/app/attacks`, so the sandbox is given `PYTHONPATH=/app` at create time.
7. **`openshell doctor check` is advisory, not a gate.** Under `podman-docker`
   emulation its Docker item fails on a template field podman does not implement
   (`can't evaluate field ServerVersion`) while the compute driver is healthy. Both
   `main.py` and `infra/substrates/chapter-2/40-openshell.sh` treat it as advisory — an
   earlier version of the substrate ran it under `set -e` and threw away a working
   box.
