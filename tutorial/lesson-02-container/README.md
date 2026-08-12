# Lesson 2 — Container

The single biggest jump in the tutorial. The same image and the same nine attacks
as lesson 1, now behind a hardened rootless container. Several attacks die here;
the groups that survive are the whole rest of the tutorial.

```bash
cd tutorial/lesson-02-container
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

That is the whole workflow — one command, and the box is destroyed even if the lesson
fails. It writes `report.html` + `report.json` here beside the lesson.

Run lesson 1 first (`../lesson-01-no-sandbox`) so this lesson's Part 3 has a
scorecard to compare against.

## The boundary this lesson teaches

One throwaway container per run, with every everyday control on:

```text
--cap-drop ALL              drop every Linux capability
--security-opt no-new-privileges
--read-only                 immutable root filesystem...
--tmpfs /tmp:rw,exec,size=64m   ...with one small writable scratch
--memory 256m --memory-swap 256m    cgroup memory cap
--pids-limit 128            cgroup pids cap (anti-fork-bomb)
--cpus 1                    cgroup cpu cap
```

There is **no network flag** in that list, and that is deliberate rather than an
omission. The suite runs with the engine's ordinary network — what an agent that
must call a model API is given. Adding `--network none` would close four attacks
for free and score this rung 11/13 instead of 7/13; that is the number a container
scoreboard usually quotes, and it describes a deployment that cannot run an agent
at all. Every rung of this ladder is measured online, so the rungs are comparable
to each other and the scoreboard is honest.

`$HOME` stays on the read-only rootfs (only `/tmp` is writable), which is what
makes the backdoor writes fail rather than land in an ephemeral home.

The boundary lives in the podman machine on macOS, or on the host kernel on a real
Linux box — the lesson runs the same either way. It does **not** add a kernel
boundary; that is the point of Part 4.

## Assert the boundary engaged

The lesson checks, from the readings rather than the flags it passed, that the
container actually engaged: host credentials unreachable, a resource cap bit, and
**egress genuinely open**. If any of those did not hold it exits without writing a
result — because this repo's characteristic failure is a boundary that silently
did not engage yet still exits 0.

That third check points the opposite way from the other two, and it is the one
worth understanding. If the container came up with no egress after all — a broken
rootless network stack, a missing `pasta`/`slirp4netns` — every network row would
read BLOCKED and the scorecard would announce that a container stops exfiltration.
That is the exact false comfort this lesson exists to remove, and without the
assertion it is indistinguishable from a real result.

## The four that do not die

This container scores **7/13**. Attacks 2, 4, 5 and 6 — exfiltration, cloud
metadata, a malicious package, a second-stage fetch — are untouched by everything
in the hardening list above.

They survive because a container's only network verdict is on or off, and an agent
needs on. Nothing here can tell a typosquat fetch from a legitimate `GET`. Neither
gVisor (lesson 3) nor Kata (lesson 4) helps — neither reads HTTP — which is why
lesson 5 exists.

## Part 3 re-runs the no-sandbox rung live

On its own disposable box this lesson does not read lesson 1's recorded file — it
runs the suite again as a **bare host process**, right there, minutes apart. With
one box per lesson a recorded card came from a *different machine*, so a difference
could be the hardware rather than the boundary. (Off a disposable box it falls back
to the recorded file and says so.)

## What you should see

Measured on a fresh `PLAY2-NANO` VM, against the no-sandbox rung re-run on the same
box:

```text
read_credentials     SUCCEEDED  ->  BLOCKED
plant_backdoor       SUCCEEDED  ->  BLOCKED
resource_exhaustion  SUCCEEDED  ->  BLOCKED     capped:pids,mem
io_uring_setup       SUCCEEDED  ->  BLOCKED     ENOSYS (seccomp, not a kernel boundary)
exfiltrate           SUCCEEDED  ->  SUCCEEDED   open
cloud_metadata       SUCCEEDED  ->  SUCCEEDED   200
malicious_package    SUCCEEDED  ->  SUCCEEDED   index-reached
reverse_shell        SUCCEEDED  ->  SUCCEEDED   egress=open,bind=ok
kernel_identity      SUCCEEDED  ->  SUCCEEDED   still 6.8.0-106-generic
sys_module_count     SUCCEEDED  ->  SUCCEEDED   still 179

boundaries that held: 7/13
```

Both rungs ran with the same network, so every row that moved moved because of the
container and nothing else.

**Still open, group one — attack 8.** A container **shares the host kernel**, so
`kernel_identity` still reports the node's kernel and `/sys/module` still lists its
modules. Those are the readings a container cannot change and gVisor can.

**Still open, group two — attacks 2, 4, 5 and 6.** The network rows, and they are
the more stubborn of the two. Switching egress off would close all four and leave
a sandbox that cannot run an agent, which is not a fix. Lessons 3 and 4 leave them
exactly where they are; only lesson 5 closes them with the network still on.

Two rows deserve care because they are *not* the container's doing:

- `io_uring_setup` flips to BLOCKED here because of podman's **default seccomp
  profile**, not a kernel boundary. Read it alongside `sys_module_count` and
  `kernel_identity`, which do not move.
- `bpf` and `perf_event_open` were **already** refused in lesson 1 — Ubuntu's
  `unprivileged_bpf_disabled=2` and `perf_event_paranoid=4` did that, with no
  boundary present. A row that never changes is not evidence the container worked.

## Next

- [`lesson-03-container-gvisor`](../lesson-03-container-gvisor/) swaps one word —
  `--runtime runsc` — and watches the kernel rows collapse. The network rows do
  not move an inch.
- [`lesson-05-container-openshell`](../lesson-05-container-openshell/) is the first
  rung to close attacks 2, 4, 5 and 6 **with the network still on** — per-binary
  and method-aware policy, which is a distinction blanket on/off cannot express.
  That is [`lesson-05-container-openshell`](../lesson-05-container-openshell/).
