# `infra/` — one predefined box per lesson

Every lesson in this tutorial runs on **its own disposable Scaleway box**, brought
up by one command and destroyed by another. That is not convenience: the rogue
agent writes a backdoor, installs a package that executes code at install time, and
exhausts resources. Those are real side effects, and they are only acceptable on a
machine that is deleted minutes later.

```bash
cd infra
./up.sh --list                          # which lessons have a box definition
./up.sh   lesson-03-container-gvisor    # provision + substrates + assert the boundary
./run.sh  lesson-03-container-gvisor    # run the lesson there, fetch results/
./ssh.sh  lesson-03-container-gvisor    # a shell on it
./down.sh lesson-03-container-gvisor    # destroy it
./down.sh --all                         # destroy everything, then sweep for orphans
```

## What each lesson gets

Defined in [`terraform/lessons.json`](terraform/lessons.json), which is the **only**
place the mapping lives — Terraform reads it with `jsondecode()`, `lib.sh` reads the
same bytes with `jq`. It is JSON rather than `.tfvars` for exactly that reason: a
generated second copy is how the two drift apart, and a drifted table provisions one
box while the lesson believes it got another.

| Lesson | Box | Root vol | €/hr | Why that box |
|:--|:--|:--|--:|:--|
| 1 no-sandbox | `PLAY2-NANO` VM | 20 GB | 0.028 | the bare box *is* the lesson |
| 2 container | `PLAY2-NANO` VM | 20 GB | 0.028 | rootless podman on this VM's own kernel |
| 3 gvisor | `PLAY2-NANO` VM | 20 GB | 0.028 | `runsc` is user-space; no hardware feature needed |
| 4 kata | `PLAY2-MICRO` VM | **40 GB** | 0.055 | needs `/dev/kvm` **and** `/dev/vhost-vsock`, which this VM has |
| 5 openshell | `PLAY2-MICRO` VM | 40 GB | 0.055 | OpenShell refuses a public default-route IP, so the box builds a NAT'd guest |

**VM, not bare metal — and that was measured rather than assumed.** Lessons 1–3 used
to take Elastic Metal on the argument that only metal makes "a container shares
*this* kernel" literally true. Tested on 2026-08-06, lesson 1's scorecard is
row-for-row identical on a VM, gVisor still reports `4.19.0-gvisor`, and Kata still
boots guest kernel `6.18.35` because a Scaleway VM exposes `/dev/kvm` and
`/dev/vhost-vsock`. The full measurement is in `syllabus.md` § *Verified on this
hardware*.

What metal cost was never the money — it was a default `ELASTIC_METAL` quota of
**2** (four metal lessons could not be up at once), per-offer stock, and a 10–15
minute OS install per box against under a minute for a VM.

The honest price of the switch: on a VM there **is** a hypervisor underneath, so
"nothing beneath this kernel" is false. Escaping the container still gives you the
whole machine, which is the claim lessons 1–3 actually make. Chapter 4's OpenShift
box remains genuine bare metal, and the Terraform module still builds one —
`"kind": "baremetal"` in `lessons.json` is all it takes.

## Prerequisites

- A **Scaleway account** with `scw init` done (project, zone, credentials). The
  Terraform provider reads the same `~/.config/scw/config.yaml`, so there is
  nothing else to configure and no key in this repo.
- **Terraform** ≥ 1.9.
- An **SSH key registered as a Scaleway IAM key**. The scripts default to a
  *throwaway* keypair, deliberately — every box here runs hostile code, so the
  credential that reaches it should be disposable too:

  ```bash
  mkdir -p ~/.config/sandboxing-tutorial && chmod 700 ~/.config/sandboxing-tutorial
  ssh-keygen -t ed25519 -N '' -f ~/.config/sandboxing-tutorial/id_ed25519
  scw iam ssh-key create name=sandboxing-tutorial \
      public-key="$(cat ~/.config/sandboxing-tutorial/id_ed25519.pub)"
  ```

  Override with `SANDBOXING_TUTORIAL_SSH_KEY` / `…_SSH_KEY_NAME`. **No private key
  ever enters this repo**, and `infra/.state/` and `terraform.tfstate` are gitignored
  because they name live, billable resources.
- `jq` and `rsync` locally.

## Cost

Roughly **€0.19/hr** with all five boxes up at once, and a lesson occupies its box
for well under an hour — so the whole chapter is well under a euro, *provided
`down.sh` runs*. `up.sh` prints the running rate, read live from the Scaleway
catalogue rather than from a hardcoded table that can quietly go stale.

`down.sh` finishes by sweeping the zone, because the failure mode that costs real
money is a box you forgot rather than a box you meant to keep. It checks three
things, not one: `sbx-*` servers, **detached volumes**, and **unattached flexible
IPs**. The last two outlive a badly-deleted server and keep billing while the
server list reads empty — which looks exactly like "all clear".

## Traps that cost time once

| Trap | Symptom | Fix |
|:--|:--|:--|
| **Default root volume is 8 GB** | `tar: ... No space left on device` unpacking `kata-static` | size it per lesson in `lessons.json`; Kata needs 40 GB. Metal's big local SSD is why this never showed up before |
| **A VM logs in as `root`** | lesson 2 claims "rootless" while running as root | Terraform's cloud-init creates the unprivileged `agent` user. Elastic Metal logs in as `ubuntu` |
| **cloud-init is not done when sshd answers** | the `agent` user does not exist yet; `Permission denied (publickey)` | `up.sh` waits on `cloud-init status --wait` before touching the box |
| **Two infra commands at once** | one silently destroys the other's box | every apply names the *whole* set, so `lib.sh` serialises them behind a lock |
| **Client MTU blackhole** | ssh hangs at "banner exchange" while `ping` is perfect | `sudo ifconfig <default-if> mtu 1400` on your workstation (revert with `1500`) |
| **Host key churn** | MITM warnings after a rebuild | expected — we cause every rebuild, so the scripts use `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null` |

## `check.sh` asserts from the inside

`up.sh` finishes by running [`check.sh`](check.sh), which asks each sandbox **whose
kernel answered** rather than trusting the flag that was passed. This repo's
characteristic failure is a lesson that intends to run under gVisor, silently falls
back to `runc`, exits 0, and prints everything the lesson expects. Setup time is
the only place that failure is cheap to catch.

The checker has to survive that standard itself. Two bugs found in it on 2026-08-06
are worth knowing about, because both are easy to reintroduce:

- `$(… | grep -c Connected || echo 0)` reports the OpenShell gateway **healthy when
  it is down** — `grep -c` prints `0` *and* exits 1, so the capture is `"0\n0"`,
  which is not equal to `"0"`. Match on the pipeline with `grep -q` instead.
- lesson 5's NAT-guest assertion must be asked of the **host**, via `box_ssh_host`.
  By the time it runs, `up.sh` has re-pointed the lesson at the guest, and the guest
  has no libvirt — so the obvious `box_ssh` can never pass.

## Layout

```text
infra/
├── terraform/
│   ├── lessons.json          the per-lesson box definitions — the only mapping
│   ├── main.tf · variables.tf · outputs.tf · versions.tf
│   └── modules/lesson-box/   vm | baremetal, root volume, cloud-init user
├── lib.sh                    shared helpers (sourced, never executed)
├── up.sh · run.sh · ssh.sh · down.sh · check.sh
├── substrates/               one script per boundary, run ON the box
└── images/agent/             the one image every lesson runs
```
