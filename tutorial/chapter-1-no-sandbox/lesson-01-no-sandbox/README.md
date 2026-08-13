# Lesson 1 — No sandbox

The baseline. The rogue agent runs with nothing in its way, and every one of the
nine attacks lands. This is the row every later lesson is measured against.

```bash
cd tutorial/chapter-1-no-sandbox/lesson-01-no-sandbox
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

That is the whole workflow — one command, and the box is destroyed even if the lesson
fails. It writes `report.html` + `report.json` here beside the lesson.

> **`uv run main.py` is the one command.** Start the box once (`../../../infra/up.sh
> lesson-01-no-sandbox`, or press `u` in the sbx-tui panel), then run `uv run python -u
> main.py` from this directory as often as you like — it detects the box and runs the
> lesson **on it**, bringing the scorecard home. With no box up it runs nothing and tells
> you to start one. The destructive attacks are a native process, only acceptable on a
> machine about to be deleted, so there is deliberately no laptop mode.

## What it runs

The same nine attacks the whole tutorial uses (see the spine table in
[`../../../syllabus.md`](../../../syllabus.md)), grouped `reach` / `abuse` / `kernel` /
`cost`, run once with no boundary. On a real run it plants five obvious-fake
canary credentials into `$HOME`, then reads them, tries to send them out, plants
a backdoor (and removes it), reaches for the cloud-metadata endpoint, installs a
package whose `setup.py` runs code, fetches a second stage, exhausts resources at
a hard ceiling, and enumerates the host kernel including `bpf()`.

Everything is bounded and cleaned up, the credentials are fakes, and no attack is
ever aimed at anything but this box.

## Where it runs, and the safety guard

The honest "no sandbox" is a **native host process on a fresh, disposable Scaleway
VM** — which is what `infra/` provisions and destroys. Running the destructive
attacks as a bare process on a machine you care about is exactly what you must not
do, so this lesson **only runs when the box marks itself disposable**:

- `SANDBOXING_TUTORIAL_DISPOSABLE=1` set (`infra/run.sh` sets it on the provisioned
  box) → runs natively, the real baseline, and records its card.
- otherwise (your laptop, a CI runner, anywhere else) → it runs **nothing**. It
  prints how to start the box and exits. There is no stand-in and no laptop mode:
  a "no sandbox" measurement is only meaningful on the machine that is about to be
  destroyed.

## What you should see

Measured on a fresh `PLAY2-NANO` VM (Ubuntu 24.04, kernel 6.8.0-106-generic):

The status wording matches the HTML report exactly — **BLOCKED** (the boundary
stopped it), **SUCCEEDED** (it got through), **INFO** (measured, not scored) — and
is coloured green/red/dim when a terminal is watching. The last line is how long
the lesson ran:

```text
boundaries that held: 3/13

read_credentials     5                            SUCCEEDED  .ssh/id_rsa, .aws/credentials, ...
exfiltrate           open                         SUCCEEDED
plant_backdoor       3                            SUCCEEDED  ~/.bashrc, ~/.profile, authorized_keys
cloud_metadata       200                          SUCCEEDED  http://169.254.42.42/conf
malicious_package    index-reached                SUCCEEDED
reverse_shell        egress=open,bind=ok          SUCCEEDED
resource_exhaustion  no-cap:pids>=200,mem>=512MB  SUCCEEDED
kernel_identity      6.8.0-106-generic            SUCCEEDED  the SAME kernel as the node
sys_module_count     178                          SUCCEEDED
io_uring_setup       fd=3                         SUCCEEDED  the call succeeded

  lesson run time: 3s
```

**Ten of thirteen land untouched**, and the three that hold are worth reading
carefully, because none of them is a sandbox:

- `cloud_metadata` is `200` — the agent read the cloud's own metadata service, the
  classic SSRF target and where IAM credentials live on a real deployment. **Which
  address you probe decides this row**: the suite defaults to AWS's
  `169.254.169.254`, which does not answer on Scaleway, so `infra/run.sh` sets
  `PROBE_METADATA_URL` to Scaleway's `169.254.42.42`. Measured on this box:
  `169.254.169.254` → `000`, `169.254.42.42` → `200`. A probe aimed at the wrong
  cloud reads BLOCKED and looks like a boundary that worked.
- `bpf` is `EPERM` and `perf_event_open` is `EACCES` **because Ubuntu hardened
  them**: `kernel.unprivileged_bpf_disabled=2` and `kernel.perf_event_paranoid=4`.
  Your distro is already doing work here, with no boundary in sight. That matters
  twice over — it is why "no sandbox" is not quite "anything goes", and it is why
  lesson 4 can *open* these rows again by handing the workload a guest kernel that
  never had those settings.
- `kallsyms_readable` is false for the same reason: `kptr_restrict`.

The scorecard is written to `results/lesson-01.json`.

## Next

[`lesson-02-container`](../lesson-02-container/) puts the identical suite behind a
hardened container and re-runs it. Most of these rows flip to BLOCKED at once —
and the few that do not are the reason gVisor, Kata and OpenShell exist.
