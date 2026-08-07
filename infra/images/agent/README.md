# The agent image

The one image every lesson shares. It carries the **attack suite** and, later, the
**agent driver**; a lesson supplies only the boundary it runs this image under.
Building it once and running it behind different boundaries is what makes two rungs
of the ladder directly comparable — the box changes, the workload does not.

```bash
./build.sh                       # build sandboxing-tutorial/agent:latest (podman)
CONTAINER_ENGINE=docker ./build.sh
./build.sh --tag myrepo/agent:dev

# smoke-test the script driver in a throwaway container:
podman run --rm -e PROBE_GROUPS=kernel,cost sandboxing-tutorial/agent:latest
```

## Two drivers, one suite

The entrypoint dispatches on `DRIVER`:

- `DRIVER=script` (default) — runs the nine attacks from a fixed script.
  Deterministic, no model in the loop. This is what proves the environments: a
  scorecard cell flipping between two rungs is unambiguously the boundary, never a
  model phrasing an attack differently.
- `DRIVER=agent` — steers a real agent into running the same attacks via prompt
  injection. **Phase 2, not built yet** — the environments are proven with the
  script driver first, by design.

Both print human output to **stderr** and machine lines to **stdout**: one
`FINDING_JSON {...}` per attack as it completes, then a final
`SCORECARD_JSON {...}` with the whole card (and, under the agent driver, one
`AGENT_JSON {...}`). That discipline is what lets a lesson run this behind any
boundary and parse the result the same way.

### Why the per-attack lines exist

A sandbox can die *during* the suite, and on one rung it reliably does. Attack 7's
fork bomb OOM-kills a **gVisor** sandbox at limits a plain container merely answers
`EAGAIN` to — gVisor's sentry and its per-task stub processes live inside the
container's own cgroup, so the fork bomb spends the workload's memory budget.
Measured on `--memory 256m --pids-limit 128`: `runc` reports `capped:pids,mem` and
exits 0; `runsc` exits 137 with nothing on stdout.

A card printed only at the end is therefore a card that is *lost* — including
attack 8's kernel readings, which are the entire reason the gVisor lesson exists.
So each finding goes out the moment it is produced, and the destructive `abuse`
group runs **last** (`attacks.suite._RUN_ORDER`), which costs a dying box only
attack 7's own row. The host reads that last row off the **exit status**, which is
the only place it is still legible.

The host-side parser (`scorecard.py` in each lesson leaf) will only assemble a
partial card when asked explicitly, and marks it `complete = False` — a short card
must never pass as a whole one.

## The nine attacks

Source is in [`attacks/`](attacks/): `suite.py` (the attacks), `report.py` (the
scorecard shape), `run.py` (the script driver). Grouped for reporting:

| Group | Attacks |
| :-- | :-- |
| `reach` | 1 read credentials · 2 exfiltrate · 3 plant backdoor · 4 cloud metadata |
| `abuse` | 5 malicious package · 6 second stage + reverse shell · 7 resource exhaustion |
| `kernel` | 8 enumerate the host kernel, call `bpf()` / `io_uring` |
| `policy` | per-binary + method-aware egress (`GET` allowed, `POST` denied) + Landlock — only meaningful under OpenShell |
| `cost` | the price of the boundary (syscall, cpu; min-of-3) |

`evidence` (attack 9 — was any of it recorded?) is measured by the lesson from the
runtime's logs, because in-box code cannot see its own audit trail.

Two rules keep it safe to actually run: every destructive attack is **bounded and
cleaned up** (the backdoor line is removed, the fork test is reaped, memory is
capped at a few hundred MB), and there is **never a real reverse shell or payload
execution** — attack 6 proves reach, never detonation. Credentials are obvious
fakes; the listener, index and second-stage host are configured via `PROBE_*`
environment variables and are always ours.

## Configuration

| Variable | Used by | Meaning |
| :-- | :-- | :-- |
| `PROBE_GROUPS` | driver | comma-separated groups (default: `reach,abuse,kernel,cost`) |
| `PLANT_FAKE_SECRETS=1` | lesson 1 | plant fake canary credentials into `$HOME` first |
| `PROBE_EXFIL_URL` | attack 2 | where stolen data would go (our listener); unset ⇒ raw-egress test |
| `PROBE_METADATA_URL` | attack 4 | cloud-metadata endpoint |
| `PROBE_INDEX_URL` | attack 5 | a package index to reach (default: PyPI) |
| `PROBE_STAGE_URL` | attack 6 | the second-stage host (our server) |
| `PROBE_GATEWAY_URL` / `PROBE_OFFPOLICY_URL` | policy | a host the allow-list should permit / deny |

## Notes

- Built natively on the box: x86_64 on the Scaleway hosts, arm64 on a Mac podman
  machine for local smoke tests. The attack suite is arch-aware (syscall numbers
  differ), so both are correct.
- The image preamble (a real non-root `sandbox` user, `HOME=/sandbox`, iproute2)
  is what lets the same image also run under OpenShell later without a rebuild.
