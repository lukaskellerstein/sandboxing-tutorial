---
description: "Step 4: Testing — define DoD, test, fix and repeat until passing"
---

# Step 4: Testing

**Every code change must be tested before reporting completion. No exceptions.**

## 4a. Define your Definition of Done

Before testing, **write out your DoD checklist in the conversation** so the user
can see what you intend to verify. Example:

> **Definition of Done for this lesson:**
>
> - [ ] `./run.sh` provisions the box, the lesson runs on it, the box is destroyed
> - [ ] `check.sh`'s boundary assertions passed — read from inside, not from the flag
> - [ ] The lesson printed its expected sections and wrote `results/<lesson>.json`
> - [ ] `report.html` + `report.json` exist in the lesson's folder
> - [ ] The probe results differ from the previous rung in the way the lesson claims
> - [ ] The README's step-by-step matches what the run actually printed
> - [ ] **Independently verified** that no server, volume or IP is left in the account

## 4b. Test — one lesson, one box, every time

**Provision → run → validate → investigate on failure → destroy.** Per lesson, no
steps skipped, no exceptions. There is no repo-wide test suite; running the lesson
on its own disposable box *is* the test.

That whole cycle is one command, and it destroys the box even when the lesson fails:

```bash
cd tutorial/<chapter>/<lesson>
./run.sh                 # provision -> run -> destroy
./run.sh --keep          # ...leave the box up, for investigating a failure
```

> [!danger]
> **Never "quickly test" a lesson by running `main.py` locally.** It writes
> `results/<lesson>.json` from whatever machine you are on, silently replacing a
> real measurement with a laptop stand-in — and the next comparison is then a
> laptop against a VM, which is precisely the dishonesty this repo exists to
> avoid. It has already happened once. If you do it by accident, say so and
> re-run `./run.sh` to restore the card.

**Capture the full output.** Redirect the whole run to a file and grep the file for
display; never pipe the run itself through `grep`. A filtered pipeline throws away
the traceback body, and a failure you cannot diagnose costs another full provision
to reproduce. That has also already happened once.

**On failure, investigate before re-running.** A lesson that passes on the second
attempt with unchanged code is not fixed, it is intermittent — say so rather than
reporting the green run. Use `./run.sh --keep` to hold the box, then `infra/ssh.sh
<lesson>` to inspect it, and destroy it with `infra/down.sh <lesson>` when done.

What to actually check, beyond "it exited 0":

- **The boundary did what the lesson says.** This is the characteristic failure
  here and it exits cleanly: a lesson that *intends* to run under gVisor but
  silently fell back to `runc` looks exactly like a passing run. Assert the
  runtime — `podman inspect <ctr> | jq '.[].HostConfig.Runtime'`, the pod's
  `runtimeClassName`, `uname -r` or `dmesg` read from *inside* the sandbox —
  never infer it from the flag you passed.
- **The probe results.** The ladder only teaches anything if each rung is
  measured the same way as the one before. Compare against the previous lesson's
  numbers; a rung that reports identical results to the rung below it is either
  broken or the lesson's claim is wrong.
- **The console output.** Lessons teach by printing; if section headers and
  progress lines are missing or wrong, the lesson is broken even though the code
  ran.
- **The reports exist.** `report.html` and `report.json` in the lesson's own
  folder, plus `results/<lesson>.json`. If the lesson ran but no report appeared,
  the run is not done — the render step is part of the lesson, not a nicety.
- **The README matches the run.** If you changed behaviour, the step-by-step and
  any sample output in `README.md` are now stale.
- **The box is gone — verified against the account, not against the script.**
  `./run.sh` prints `destroyed, billing stopped` *before* the API has finished, so
  its own output is not proof. Ask the account:

  ```bash
  scw instance server list zone=fr-par-1     # servers
  scw block volume list zone=fr-par-1        # sbs root volumes — EVERY lesson's; see below
  scw instance volume list zone=fr-par-1     # l_ssd/b_ssd only, for a local-volume lesson
  scw instance ip list zone=fr-par-1         # a flexible IP outlives a badly-deleted server
  ```

  All four must be empty. Checking only the server list is how an orphaned volume
  bills quietly for a month.

  > [!danger]
  > **`scw instance volume list` cannot see this repo's root volumes.** `lib.sh`
  > defaults `root_volume_type` to `sbs`, and an sbs volume lives in the **Block**
  > API — `instance volume list` returns `0` for it, which reads exactly like an
  > all-clear. On 2026-08-13 that gap hid a 20 GB volume detached since 2026-08-08,
  > billing ~€0.06/day. **`scw block volume list` is the query that finds them**;
  > a detached one has `references: []`.

  Never delete a cluster, volume or image this repo did not create. Block volumes
  carry no `sbx-` prefix to attribute them by — their name comes from the image
  (`Ubuntu 24.04 Noble Numbat_sbs_volume_0`) — so `down.sh` reports them with a
  ready-to-paste `delete` line and leaves the judgement to you.

**Dashboard / UI checks** — some lessons surface results in a web UI (an MLflow
or Langfuse instance, a cluster dashboard). There is **no repo-wide dev server**;
the URL is whatever the lesson under test brings up, and its README states it.
When one is involved:

1. Confirm the service is actually up first (`podman compose ps`, or curl it).
2. Drive it with `mcp__playwright-sandboxing-tutorial__browser_navigate`, and
   verify the change is visible **and** functional — take a snapshot, don't just
   assert the page loaded.
3. **Close the browser when done.**

> The browser opens on its own desktop/space and is closed automatically at
> session end by `.claude/hooks/`. That is a safety net, not a substitute for
> closing it yourself when the test is finished.

**Every code change** — repo-wide lint / format / type check:

```bash
nvim-tools --json --all
```

Your change must not add findings, measured against the baseline you took in the
Understand step. How to read the output (including `gated-off`), and why this
never replaces running the lesson: [`machine-tools.md`](machine-tools.md).

> Expect `types` to report `gated-off` until the first lesson leaf exists —
> `pyrightconfig.json` is not written yet, by design. See
> [`01-project-config.md`](01-project-config.md).

**Non-testable changes** (docs, config, IaC only): explicitly state why no
runtime test is needed.

## 4c. Fix and repeat

If a test fails: fix the issue, then retest. Repeat until all DoD items pass. If
you hit a problem you repeatedly cannot resolve, ask the user for help rather
than reporting partial success.

## 4d. Never report completion without testing

If you write code and stop without verifying it works, you have failed. Testing
is YOUR responsibility — the user should never need to ask you to test.

This matters more here than in most repos, for two reasons. The output is
teaching material: a learner who hits a broken lesson has no way to tell your bug
from their own mistake, and will assume it is theirs. And the subject is
security: a lesson that *appears* to demonstrate an isolation boundary while
silently running without one teaches the reader something false and dangerous.
"The code looks right" is not a test.
