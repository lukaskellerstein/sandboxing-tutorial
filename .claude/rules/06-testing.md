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
> - [ ] `uv sync` resolves without error in the leaf
> - [ ] `uv run python main.py` completes and prints the expected sections
> - [ ] The probe results differ from the previous rung in the way the lesson claims
> - [ ] The README's step-by-step matches what the run actually printed
> - [ ] Containers/pods the run created are cleaned up

## 4b. Test

**Lesson / Python changes** — run the affected lesson end-to-end. There is no
repo-wide test suite; running it *is* the test.

```bash
cd tutorial/<lesson>
uv sync
uv run python main.py
```

Before that, confirm the environment is actually up — a lesson failing because
the container engine is stopped is not a lesson bug:

```bash
podman machine list && podman ps      # podman is the preferred engine
docker ps                             # only for lessons that require Docker
kubectl config current-context        # k8s lessons — CHECK THIS BEFORE APPLYING
kubectl get runtimeclass              # is runsc / kata actually registered?
```

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
- **The README matches the run.** If you changed behaviour, the step-by-step and
  any sample output in `README.md` are now stale.
- **Clean up.** Remove containers and pods the run created. Never delete a
  cluster, a volume, or an image this repo did not build.

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
