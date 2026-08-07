# Lesson 2 — Container

The single biggest jump in the tutorial. The same image and the same nine attacks
as lesson 1, now behind a hardened rootless container. Most attacks die here; the
three that survive are the whole rest of the tutorial.

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

The network is **not** in that list, because this lesson treats it as a variable
rather than a constant. The same container runs the suite twice:

```text
egress-off    --network none          the number a container scoreboard usually quotes
network-on    the ordinary network    what an agent that must call a model API has
```

Everything else is byte-identical between the two runs, so any row that differs
differs because of the network and nothing else.

`$HOME` stays on the read-only rootfs (only `/tmp` is writable), which is what
makes the backdoor writes fail rather than land in an ephemeral home.

The boundary lives in the podman machine on macOS, or on the host kernel on a real
Linux box — the lesson runs the same either way. It does **not** add a kernel
boundary; that is the point of Part 5.

## Assert the boundary engaged

The lesson checks, from the readings rather than the flags it passed, that the
container actually engaged: host credentials unreachable, egress denied, a
resource cap bit. If any of those did not hold it exits without writing a result —
because this repo's characteristic failure is a boundary that silently did not
engage yet still exits 0.

## Part 4 is the one that matters

Measured on a Scaleway VM, this container scores **11/13 with egress off and 7/13
with the network on**. The four that reopen are attacks 2, 4, 5 and 6 —
exfiltration, cloud metadata, a malicious package, a second-stage fetch.

They do not reopen because the container got weaker. The hardening is identical;
only the network changed. They reopen because a container's only network verdict
is on or off, and an agent needs on. Neither gVisor (lesson 3) nor Kata (lesson 4)
helps here — neither reads HTTP — which is why lesson 5 exists.

The 11/13 figure is the one usually quoted for containers, and it describes a
deployment that cannot run an agent.

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
read_credentials     REACHED  ->  BLOCKED
exfiltrate           REACHED  ->  BLOCKED
plant_backdoor       REACHED  ->  BLOCKED
cloud_metadata       REACHED  ->  BLOCKED     169.254.42.42 unreachable with no network
malicious_package    REACHED  ->  BLOCKED
reverse_shell        REACHED  ->  BLOCKED
resource_exhaustion  REACHED  ->  BLOCKED     capped:pids,mem
io_uring_setup       REACHED  ->  BLOCKED
kernel_identity      REACHED  ->  REACHED     still 6.8.0-106-generic
sys_module_count     REACHED  ->  REACHED     still ~180

boundaries that held: 11/13
```

**Still open — attack 8.** A container **shares the host kernel**, so
`kernel_identity` still reports the node's kernel and `/sys/module` still lists its
modules. Those are the readings a container cannot change and gVisor can.

Two rows deserve care because they are *not* the container's doing:

- `io_uring_setup` flips to BLOCKED here because of podman's **default seccomp
  profile**, not a kernel boundary. Read it alongside `sys_module_count` and
  `kernel_identity`, which do not move.
- `bpf` and `perf_event_open` were **already** refused in lesson 1 — Ubuntu's
  `unprivileged_bpf_disabled=2` and `perf_event_paranoid=4` did that, with no
  boundary present. A row that never changes is not evidence the container worked.

## Next

- [`lesson-03-container-gvisor`](../lesson-03-container-gvisor/) swaps one word —
  `--runtime runsc` — and watches the kernel rows collapse.
- Egress is fully **off** here; a real agent needs the model gateway, and once any
  egress is allowed a plain container cannot tell a good request from a bad one.
  That is [`lesson-05-container-openshell`](../lesson-05-container-openshell/).
