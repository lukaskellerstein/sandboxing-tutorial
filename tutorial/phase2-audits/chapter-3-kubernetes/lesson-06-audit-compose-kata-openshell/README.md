# Lesson 2.3.6 — Auditing OpenShell over Kata

**This is [2.3.4](../lesson-04-audit-k8s-openshell/) with one field changed:**
`runtimeClassName: kata-qemu`, selected through OpenShell's driver-config overlay exactly as
[1.3.6](../../../phase1-attacks/chapter-3-kubernetes/lesson-06-compose-kata-openshell/) selects it.
Same policy file, same suite, same two sensors, same cluster, minutes apart — so anything that moves,
moved because of Kata.

## The finding

**The host sensor's column collapses to zero. The L7 trail does not move at all.**

| sensor | 2.3.4 (runc) | 2.3.6 (Kata) |
| :-- | --: | --: |
| Tetragon (host eBPF) | 7 attacks | **0** |
| OCSF (OpenShell's L7 trail) | 8 attacks | **8** |

Tetragon attributed **0** events to the Kata sandbox — against **116** it attributed to *other*
containers on the same node in the same seconds. That second number is the guard that makes the zero
a finding rather than a broken sensor: an eBPF probe that never attached and one that cannot see
through a guest kernel produce the same empty column, so the lesson refuses to report unless the
sensor is shown recording other containers meanwhile. (Only the **zero** is a measurement of this
boundary; the other-container count is a liveness figure and moves run to run.)

This is [2.2.3](../../chapter-2-one-host/lesson-03-audit-container-kata/)'s result composed onto the
cluster: **a stronger isolation boundary hides more.** Under Kata the workload's syscalls cross a
guest kernel inside a VM and never reach the node kernel Tetragon's probe is attached to.

## What survives, and what it costs

OCSF survives because **it is not a syscall sensor**. It is an L7 proxy in the *gateway*, sitting on
the network path — and a VM boundary does not cut the network path. That makes it the one sensor that
has seen every rung of this ladder: runc (2.2.4, 2.3.4), gVisor (2.3.5), and now a guest kernel.

The price is printed in its column: **it sees network attacks and nothing else.** Everything local —
the credentials read, the backdoor written, the kernel probed — is dark at this rung to every sensor
available on the host.

Stated as a rule:

> A boundary strong enough to hide the workload from the host hides it from the host's **auditor**
> too, so every layer you add below the policy engine has to be paid for with a sensor above or
> inside it.

Recovering the local column needs a sensor **inside the guest**, which under Kubernetes means a
privileged pod holding the guest's init context — the sidecar 2.2.3 could not stand up under nerdctl
(the audit netlink is initial-namespace-only) and which **2.3.3 exists to build**. This leaf names
that as its disjoint blind spot rather than standing the sidecar up a second time.

## On the suite this runs

1.3.6 runs only `kernel,policy` — enough for its claim, which is that Landlock survives the guest
boundary. This leaf runs the **full suite**, because the audit question needs attacks the two sensors
can disagree about: with only those two groups there would be no network attack for OCSF to catch and
the collapse of the host column would have nothing to be measured against.

One containment row therefore differs from 2.3.4 and it is a real Kata property, not an artifact:
`resource_exhaustion` reads `no-cap:pids>=200,mem>=512MB` here — the guest VM brings its own resource
ceiling, above the one the pod spec sets on runc. Containment is 17/19 either way.

## Assertions

Kata is asserted from the pod spec **and** from inside: `runtimeClassName` proves the overlay landed,
and a guest kernel that *differs* from the node's proves the shim did not silently fall back to runc.
On k3s the strings differ (`6.18.35` vs `6.8.0-106-generic`); chapter 4's OpenShift rung cannot use
that test, because Red Hat builds the guest kernel from the same base, and reads DMI instead.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.6     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or the whole chapter on one box: `cd infra && ./chapter-03-audit.sh`.

OpenShell is **alpha**; the version is printed at the top of the run and recorded in the scorecard.
