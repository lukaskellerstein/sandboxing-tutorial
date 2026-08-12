# Lesson 10 — the same agent, the same pod, on OpenShift

Chapter 3 ended with a hardened Pod on k3s. This lesson submits the closest thing to that
manifest on OpenShift and runs the identical attack suite, so chapter 4 starts from a
**measured** baseline rather than an assumption.

```bash
../../infra/openshift-sno/install.sh    # the shared chapter-4 cluster, once
cd tutorial/lesson-10-openshift-pod
./run.sh
```

## Two things are different, and neither is a security control

**The suite arrives as a ConfigMap, not an image.** Chapter 3 built
`sandboxing-tutorial/agent:v1` with podman and side-loaded it into the node's containerd.
Neither half works here: RHCOS has no podman to build with, and pushing to the internal
registry needs the `*.apps` route this cluster deliberately does not have. So the same
`attacks/` package is read off disk and mounted in.

That is a delivery change, not a measurement change — and it has to be, or the ladder
stops being a ladder. If the suite drifted, every rung would be answering a slightly
different question.

**The lesson runs on your machine.** Chapters 1–3 rsync the repo onto the box and run
there. RHCOS is an immutable image with no package manager and no uv, so the driver runs
locally against `oc` and the boundary stays on the node — which is where it always was.

The pod image is Red Hat's UBI9 `python-312` rather than `python:3.12-slim`, because the
suite shells out to the real `/usr/bin/curl` and a `-slim` Debian image ships without it.
A probe reporting *"curl absent — attack NOT measured"* is missing tooling masquerading
as a boundary.

## The one omission that matters

There is **no `runAsUser`** in this pod spec. Lesson 6 pinned uid 1000; on OpenShift that
is exactly what gets a manifest refused, because the project has its own UID range and
admission assigns from it.

The omission is the OpenShift-correct spelling of the same intent — and
[`lesson-11-openshift-scc`](../lesson-11-openshift-scc/) is entirely about why.

## What you should see

Measured on single-node OpenShift 4.18.49, `EM-B112X-SSD` bare metal (2026-08-10).
**`boundaries that held: 7/13`**.

```text
[reach]
  read_credentials   0                              BLOCKED
  exfiltrate         open                           SUCCEEDED
  plant_backdoor     3                              SUCCEEDED ~/.bashrc,~/.profile,~/.ssh/authorized_keys
  cloud_metadata     000                            BLOCKED   no route — egress denied
  k8s_sa_token       absent                         BLOCKED   automountServiceAccountToken: false
[abuse]
  malicious_package  index-reached                  SUCCEEDED
  reverse_shell      egress=open,bind=ok            SUCCEEDED
[kernel]
  kernel_identity    5.14.0-427.138.1.el9_4.x86_64  SUCCEEDED the SAME kernel as the node
  sys_module_count   216                            SUCCEEDED
  kallsyms_readable  False                          BLOCKED
  bpf                EPERM                          BLOCKED
  io_uring_setup     ENOSYS                         BLOCKED
  perf_event_open    EPERM                          BLOCKED
```

Two rows deserve care, because neither is this rung's doing:

- **`plant_backdoor` reads SUCCEEDED**, unlike lesson 6. `$HOME` is `/tmp` here — the
  ConfigMap mount needs a writable home — so the backdoor lands in an emptyDir. "It was
  ephemeral" is not containment: the write was permitted, and the scorecard says so.
  Lesson 6 kept `$HOME` on the read-only rootfs and scored BLOCKED.
- **`io_uring_setup ENOSYS`** is RHEL 9's seccomp profile, not a kernel boundary. The
  suite's canned detail text says "a user-space kernel", which is right on the gVisor rung
  and misleading here. Read it alongside `kernel_identity` and `sys_module_count`, which
  do not move.

**There is no NetworkPolicy on this rung**, which is why attacks 2, 5 and 6 read SUCCEEDED
where lesson 6 blocked them. That is deliberate: this lesson is the OpenShift baseline,
and stacking a scoped egress policy on top would confuse "what OpenShift gives you by
default" with "what you can configure". Lesson 6 already measured the NetworkPolicy story.

## What is still open

`kernel_identity` is the node's: a pod on OpenShift is still namespaces and cgroups on
the node's kernel, exactly as on k3s. **OpenShift adds admission, not isolation.**

- admission → [`lesson-11-openshift-scc`](../lesson-11-openshift-scc/)
- the kernel column → [`lesson-12-openshift-kata`](../lesson-12-openshift-kata/)
