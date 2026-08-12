# Lesson 7 — Kubernetes with gVisor

The shortest lesson in the tutorial, deliberately. Lesson 3 installed `runsc` and
passed `--runtime runsc` by hand. Here the identical boundary is one field:

```yaml
spec:
  runtimeClassName: gvisor
```

Everything else — the `securityContext`, the limits, the NetworkPolicy, the image,
the attack suite — is byte-identical to lesson 6. That is what makes Part 3 a
measurement of the *runtime* rather than of two different pods.

```bash
cd tutorial/lesson-07-k8s-gvisor
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

## What a RuntimeClass actually is

A named pointer to a runtime the **node** has installed. Two halves have to line up,
and [`infra/substrates/70-k8s-gvisor.sh`](../../infra/substrates/70-k8s-gvisor.sh)
does both:

1. containerd learns the runtime. k3s **regenerates** its containerd config on every
   start, so editing `config.toml` directly is undone by the next restart; the
   supported seam is a template beside it that extends k3s's own base:

   ```toml
   {{ template "base" . }}

   [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
     runtime_type = "io.containerd.runsc.v1"
   ```

2. a `RuntimeClass` object names it, and its `handler` must equal that containerd
   runtime name **exactly**.

> [!note]
> **k3s does not auto-detect `runsc`.** Its automatic alternative-runtime detection
> covers crun, the NVIDIA runtimes and the wasm shims — not gVisor and not Kata.
>
> The CRI plugin was also **renamed** in containerd 2.0: `io.containerd.grpc.v1.cri`
> became `io.containerd.cri.v1.runtime`, and the config version went from 2 to 3. The
> substrate reads the plugin name off the config k3s just generated rather than
> hardcoding it, so it keeps working on either side of that change.

## gVisor does not need KVM

A widespread claim, and wrong. gVisor's default **systrap** platform intercepts
syscalls with `seccomp-bpf` in user space — no hardware virtualisation, which is why
this lesson runs happily on the same 4 GB `PLAY2-NANO` as lessons 1–3 and 6. The
`ptrace` and `kvm` platforms exist; neither is the default.

That is also the cleanest way to see the difference from lesson 8: Kata needs
`/dev/kvm` because it boots a *real* kernel. gVisor writes one.

## Assert it engaged — from the kernel, never from the field

A pod that names a RuntimeClass the node cannot honour does not silently fall back;
it fails outright. But a *misconfigured* runtime — a handler pointing at the wrong
binary, a shim that fell back — is exactly the silent success this repo exists to
catch: the suite runs, every row looks plausible, and the kernel rows quietly report
the node's kernel while the lesson claims a user-space one.

So the lesson exits without writing a result unless the sandbox reports its own
kernel *and* that kernel says `gvisor`.

## Part 3b — what a missing RuntimeClass looks like

Worth seeing once, because it is how you learn the field is real rather than
decorative. The lesson asks for a class nothing registered and prints the cluster's
own words:

```text
Error from server (Forbidden): error when creating "STDIN":
pods "agent-missing-rtclass" is forbidden: pod rejected:
RuntimeClass "gvisor-not-installed" not found
```

Rejected outright, by the API server, before anything was scheduled — there **is** a
RuntimeClass admission check, and an unknown name comes back `Forbidden`. That is the
*good* case: you find out in the same second you asked, not from a pod stuck in a
waiting state.

It is also exactly why Part 2 asserts the **kernel** rather than the field. This
failure mode is loud; the dangerous one is silent. A RuntimeClass that *exists* but
whose handler is misconfigured is admitted happily, and only the sandbox's own answer
to "whose kernel are you" can tell you it never engaged.

It asks for a name that does not exist rather than deleting the working `gvisor`
class, so there is no chance of breaking the boundary halfway through its own lesson.

## Attack 7 may kill the sandbox, and that is the result

Under `runsc` the sentry and its per-task stub processes are charged to the
container's own cgroup, so the fork bomb and the memory allocation exhaust the 256Mi
budget faster than they do on runc. Lesson 3 recorded exactly this
(`capped:sandbox-killed`, exit 137).

When the pod dies mid-suite the streamed findings still survive — the suite prints
each finding as it is produced, precisely so a box that does not live to the end
still yields everything up to that point — and the `resource_exhaustion` row is
merged back in from the kubelet's termination reason. It is only credited as
contained when that reason is `OOMKilled`; anything else reports `n/a` rather than
inventing a boundary.

## What you should see

Measured on a fresh `PLAY2-NANO` VM, k3s `v1.36.3+k3s1`, gVisor
`release-20260803.0`, node kernel `6.8.0-106-generic` (2026-08-08).
**`boundaries that held: 16/19`**, against lesson 6's 14/19.

The same pod, with and without the one field:

```text
attack               pod (runc)    pod (gvisor)  changed?
---------------------------------------------------------
read_credentials     BLOCKED       BLOCKED
exfiltrate           BLOCKED       BLOCKED
plant_backdoor       BLOCKED       BLOCKED
cloud_metadata       BLOCKED       BLOCKED
k8s_sa_token         BLOCKED       BLOCKED
kernel_identity      SUCCEEDED     BLOCKED       <-- closed
sys_module_count     SUCCEEDED     BLOCKED       <-- closed
kallsyms_readable    BLOCKED       BLOCKED
bpf                  BLOCKED       BLOCKED
io_uring_setup       BLOCKED       BLOCKED
perf_event_open      BLOCKED       BLOCKED
egress_gateway       BLOCKED       BLOCKED
egress_offpolicy     BLOCKED       BLOCKED
http_method_denied   SUCCEEDED     SUCCEEDED
binary_scoped        SUCCEEDED     SUCCEEDED
fs_policy_write      SUCCEEDED     SUCCEEDED
malicious_package    BLOCKED       BLOCKED
reverse_shell        BLOCKED       BLOCKED
resource_exhaustion  BLOCKED       BLOCKED

probe           pod (runc)  pod (gvisor)     ratio
------------------------------------------------
syscall_ms            69.8         175.2     2.51x
cpu_ms               127.7         125.2     0.98x
```

**Exactly two rows moved, and both are kernel rows.** Not one network row moved. That
is the entire lesson: gVisor's boundary is the syscall interface, and it has never had
an opinion about HTTP.

The kernel readings themselves:

```text
kernel_identity    4.19.0-gvisor   BLOCKED   node runs 6.8.0-106-generic
sys_module_count   0               BLOCKED
io_uring_setup     ENOSYS          BLOCKED   not implemented — a user-space kernel
perf_event_open    ENODEV          BLOCKED   no such device in this sandbox
bpf                EINVAL          BLOCKED   refused — rejected a valid request
```

`/sys/module` goes from **216 entries to 0**, and the kernel simply is not the node's.

**The cost, honestly: 2.51× on syscalls, 0.98× on CPU.** Read those together or you
will draw the wrong conclusion. "gVisor is slow" and "gVisor is free" are both false;
which *kind* of work you do decides. A syscall-heavy agent pays real money here, a
compute-heavy one pays nothing measurable.

Attack 7 kills the sandbox under both runtimes on this rung (`OOMKilled` at the 256Mi
limit), so both cards are partial and the `resource_exhaustion` row is merged back in
from the kubelet — see above.

## What is still open

The kernel column is closed. The network column is **exactly where lesson 6 left
it** — and that is the lesson.

gVisor's boundary is the syscall interface. It has no idea which binary made a
request or which HTTP method it used, and it keeps no record of either. So attacks
2, 4, 5, 6 and 9 read the same as they did one rung down, and no amount of kernel
isolation will change that.

## Next

- [`lesson-08-k8s-kata`](../lesson-08-k8s-kata/) reaches the same kernel result by a
  completely different route — a real guest kernel in a per-pod VM — and **keeps
  Landlock**, which gVisor drops. That difference decides lesson 14's composition
  experiment.
- [`lesson-09-k8s-openshell`](../lesson-09-k8s-openshell/) is the rung that closes
  what this one leaves open.
