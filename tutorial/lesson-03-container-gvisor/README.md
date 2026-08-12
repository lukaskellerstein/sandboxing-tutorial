# Lesson 3 — Container + gVisor

The shortest change in the tutorial and the biggest one to the kernel rows: the
same image, the same nine attacks, the same container flags as lesson 2, and one
word different — `--runtime runsc`.

```bash
cd tutorial/lesson-03-container-gvisor
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

That is the whole workflow — one command, and the box is destroyed even if the lesson
fails. It writes `report.html` + `report.json` here beside the lesson.

Or, on the box itself:

```bash
cd tutorial/lesson-03-container-gvisor
uv sync
uv run python -u main.py
```

## Where the boundary actually is

On the disposable Scaleway `PLAY2-NANO` VM this lesson provisions, `runsc` runs on
**the kernel of the machine you just measured** — so "a container shares this
kernel, and gVisor stops sharing it" is literally true of the thing you ran, and
escaping the container hands you that whole box.

Being precise about what the box is: it is a VM, so there *is* a hypervisor further
down, and this lesson does not claim otherwise. `runsc` needs no hardware feature
and behaves identically either way — verified on 2026-08-06 by running this lesson
on both a VM and Elastic Metal and getting the same `4.19.0-gvisor`.

`infra/substrates/20-runsc.sh` installs `runsc` and registers it as an **opt-in**
podman runtime; podman's default runtime is left alone, which is why Part 3 can
re-run the previous rung on the same box.

The lesson refuses to run on macOS and says why: gVisor there would sit inside the
podman machine, which puts the boundary somewhere other than where the lesson
claims it is.

## Rootless podman cannot drive `runsc` — so this lesson is rootful

Measured on this box, both ways round:

```text
systemd cgroup manager  ->  runsc: creating container: systemd error:
                            Interactive authentication required
cgroupfs manager        ->  runsc: cannot set up cgroup for root: configuring cgroup:
                            open /sys/fs/cgroup/cgroup.subtree_control: permission denied
```

`runsc` insists on creating the container's cgroup itself, and unprivileged it can
do so through neither path — the system D-Bus refuses the caller, and the root
cgroup is not writable. (It *does* work rootless inside a Mac's podman machine,
where the `core` user has a real systemd user session — which is exactly why
testing only there would have hidden this.)

The tempting fix is runsc's **`--ignore-cgroups`, and it is a trap**: the sandbox
then starts happily while the memory and pids caps are silently not applied, so
attack 7 flips to `no-cap` and the lesson reports a *boundary* difference that is
really a *configuration* difference — the exact class of quiet dishonesty this
tutorial exists to avoid.

So the whole lesson runs rootful, **including Part 3's baseline**, which keeps the
one-variable claim intact. The caps are verified still to bite: on the host side
the container's cgroup reads `memory.max = 268435456` and `pids.max = 128`.

> On an SELinux-enforcing host `runsc` also needs `--security-opt label=disable`,
> because it refuses to parse an SELinux-labelled spec (`FetchSpec failed: reading
> spec: SELinux is not supported`). `main.py` detects that rather than hard-coding
> it; on the Ubuntu box it does not apply.

## What gVisor is

A **kernel written in Go, running in user space**. The sandboxed process makes an
ordinary syscall; `runsc` intercepts it and answers it itself, and only a small,
audited subset ever reaches Linux. Two claims worth correcting:

- **It does not need KVM.** The default `systrap` platform intercepts with
  `seccomp-bpf`. The "gVisor requires KVM" claim is about the optional `kvm`
  platform.
- **It is not a VM.** There is no guest kernel image and no virtual hardware —
  which is exactly why lesson 4 exists, because a *real* guest kernel keeps
  features a reimplementation drops.

## Part 3 re-runs the previous rung live

The lesson runs the suite **twice on this box, in the same minute**: once under
`runsc`, once under the default runtime, with byte-identical flags. Comparing
against lesson 2's recorded file would compare two machines as well as two
runtimes, and this tutorial exists to avoid exactly that.

## gVisor does not help on the network axis

Both runs use the engine's ordinary network, like every rung of this ladder — an
agent that cannot reach a model API is not an agent, and `--network none` would
score this rung 13/13 while describing a deployment nobody ships.

That matters here more than anywhere. Read *which* rows separate `runsc` from a
plain container:

```text
attack               container     + gVisor
kernel_identity      SUCCEEDED     BLOCKED     4.19.0-gvisor
sys_module_count     SUCCEEDED     BLOCKED     0
   (every network row: unchanged)

7/13  ->  9/13
```

**Not one network row moved.** gVisor's boundary is the syscall interface, so it
collapses attack 8 and leaves attacks 2, 4, 5 and 6 exactly where a plain
container left them — a user-space kernel never had an opinion about HTTP. It
cannot see *which binary* opened the socket or *which method* it used, so it
cannot tell the model-API call the agent needs from the exfiltration it does not.

That is the lesson's real boundary statement: **a stronger kernel boundary buys
nothing on the network axis.** Lesson 4 pays far more for kernel isolation — a
whole VM — and gets exactly the same four rows left open. Only lesson 5 closes
them, and it does so on ordinary `runc` with no kernel boundary at all.

The lesson refuses to report unless egress was demonstrably open, alongside the
gVisor-identity checks. A sandbox that quietly came up offline would show those
four rows BLOCKED and credit `runsc` with stopping exfiltration it never touched.

## Two results that are easy to get wrong

**The tax is not one number.** Every syscall now traverses a user-space kernel;
arithmetic does not. The lesson prints `syscall_ms` and `cpu_ms` side by side with
the ratio, because "gVisor is slow" and "gVisor is free" are both false and the
honest statement is *which kind of work pays*. An agent blocked on a model is
nearly all of the kind that does not.

**Attack 7 kills the sandbox rather than being capped by it.** gVisor's sentry and
its per-task stub processes are charged to the *container's own* cgroup, so the
fork bomb that merely earns `EAGAIN` under runc spends the entire 256 MB budget
under `runsc` and the sandbox is OOM-killed. That is why the attack suite streams
one `FINDING_JSON` line per attack and runs the destructive group last: everything
up to attack 7 is already out, and the host reads attack 7's verdict off the exit
status. It is recorded as `capped:sandbox-killed` — contained, but violently, and
the distinction is kept rather than smoothed over.

## What you should see

Measured on a fresh `PLAY2-NANO` VM, against the same container re-run under the
default runtime on the same box, in the same minute:

```text
attack               container     + gVisor      changed?
kernel_identity      SUCCEEDED     BLOCKED       <-- closed    6.8.0-106-generic -> 4.19.0-gvisor
sys_module_count     SUCCEEDED     BLOCKED       <-- closed    193 -> 0
   (every other row: unchanged)

probe            container      + gVisor     ratio
syscall_ms            75.4         190.7     2.53x
cpu_ms               123.2         131.8     1.07x
```

**Exactly two rows move**, and they are the two a container could never move. Note
what does *not*: `bpf` and `perf_event_open` were already refused one rung down —
Ubuntu's `unprivileged_bpf_disabled=2` and `perf_event_paranoid=4` did that, not
the sandbox. A row that was already BLOCKED proves nothing about gVisor, and the
readings that carry the claim are the kernel identity and the empty `/sys/module`.

Under gVisor those syscalls are refused for a *different* reason, which the detail
column keeps: `io_uring_setup` answers `ENOSYS` — **not implemented, a user-space
kernel** — where the plain container answered `EPERM`, *refused, capability
dropped*. Same verdict, different boundary.

Both sides of that comparison ran with the same ordinary network, so the network
rows sit identical on each and drop out of the diff entirely. That is the finding,
not a gap in the table: **9/13**, two rows better than the container below it, and
both of those rows are kernel rows.

**Still open**: the four network attacks, plus which binary made a request, which
HTTP method it used, and any record that it happened.

## Next

`sys_module_count` at 0 is a kernel boundary bought with a *reimplemented* kernel.
[Lesson 4](../lesson-04-container-kata/) buys the same result with a **real** guest
kernel in a per-container VM, and the difference between the two only shows up in
lesson 14: gVisor answers `ENOSYS` to Landlock, Kata does not.

The rows gVisor leaves open are not weaker versions of attack 8 — they are a
different axis, and [lesson 5](../lesson-05-container-openshell/) is where they
close, with the network still on.
