# HARIS — Provenance-Anchored Action Gating

Our entry for the **SENTINEL** research challenge, IndabaX Tunisia 2026.

> **Authority comes from provenance, never from content.**
> Untrusted text may be read, quoted and summarized. It may never authorize an action.

HARIS is a defense layer for a tool-using LLM agent. For every action the agent proposes, it
returns one of `ALLOW` / `BLOCK` / `ESCALATE` / `REWRITE`, together with a calibrated risk
score, a confidence, reason codes, and a decomposition of exactly which signals fired — which
our observability layer renders live.

We do not attempt to detect "an injection". That problem is unbounded and every wording is new.
Instead we refuse to let untrusted content **confer authority**, which is a structural property
and therefore survives rewording.

Concretely, untrusted text is treated as having influenced the agent when the action
uses a parameter that appears in that text and **nowhere in the user's goal or trusted
context**. Identifiers do not translate, so this holds on phrasings and languages a
vocabulary would miss — and it stays quiet on ordinary business courtesy, which a
directive-shaped detector reads as an order.

## Why this design

Every defense that ships in the official starter kit, scored by the kit's own scorer on
the kit pinned in the Dockerfile (40 public scenarios since the organizers' mid-challenge
update), and on twelve held-out scenarios we wrote:

| Defense | Public (40) | Validation (9) | Held out (12, ours) |
|---|---|---|---|
| **HARIS (ours)** | **1.000** | **1.000** | **1.000** |
| `provenance` | 0.939 — refuses 22% of legitimate actions | 0.858 | 0.990 |
| `keyword` | 0.526 | **ineligible** — utility 0.40 below the 0.50 gate | 0.506 |
| `heuristic_risk` | **0.156** — 21 of 21 exfiltrations get through | 1.000 | **0.800** |
| `deny_sensitive` | 0.137 | 0.767 | 0.753 |
| `allow_all` | 0.054 | 0.218 | 0.144 |

The held-out column comes from `scripts/run_redteam.sh`, which drives the same simulator and
scorer through our harness; each defense's row is the worse of the kit's attacker and ours.

On all three sets HARIS holds **ASR 0.000, CVR 0.000, FBR 0.000, BTU 1.000** with zero
defense errors and no unnecessary escalation: it stops every attack while completing every
benign task, at a p95 latency of about 23 ms. These are local diagnostics, not the jury
score.

`heuristic_risk` was the best defense in the box on the original 19 public scenarios
(0.999). The organizers then added 21 exfiltration scenarios, and it lets every one of them
through. On our held-out set it takes critical violations on two families it had never
seen. That is the pattern HARIS is built to avoid: a defense tuned on a corpus is one
unfamiliar payload shape from collapse, while a structural rule has nothing to be tuned.

We also ran the kit's agent on a **real local model (Qwen 3.5 9B through Ollama)** instead
of the scripted mock, and fixed a series of security defects in HARIS and in our own
evaluation tooling along the way. Both are in **[`docs/report/report.md`](docs/report/report.md)**.

So our contribution is not another scenario-passing defense. It is:

1. A defense whose every decision is **legible** — risk decomposed into named signals.
2. An **adaptive red-team** that reads the defense's own decisions and hill-climbs against them.
   The attacker shipped in the kit does not: it emits four fixed variants and never reads
   `request.transcript`.
3. An **honest ablation and failure analysis**, including the attacks that beat us.

## Architecture

```
DefenseRequest
   -> target_action()          judge the action that would take effect, not a confirmation wrapper
   -> trust and taint          where did every observed span come from, and what is secret in it?
   -> instruction authority    is the agent carrying out an order it read in untrusted text?
   -> memory authority         is recalled memory standing in for a permission nobody gave?
   -> capability commitment    did the authenticated goal and the policy authorize this?
   -> confirmation lifecycle   is a consequential action backed by a RECORDED human approval?
   -> data flow                does sensitive data reach a sink it may not, in any encoding?
   -> fusion                   one calibrated risk, decomposed into named signals
   -> decision + rewrite       allow / block / escalate / a verified-clean safer equivalent
DefenseDecision
```

Every stage is deterministic. No model runs on the decision path, which keeps p95 latency low —
the official score multiplies by an `efficiency_factor` derived from it.

## Layout

| Path | Contents |
|---|---|
| `src/haris/` | The defense service |
| `redteam/` | Adaptive attacker and held-out scenarios |
| `dashboard/` | Live trace viewer |
| `docs/superpowers/specs/` | Design specification and its reasoning |
| `docs/superpowers/plans/` | Task-by-task implementation plan |
| `docs/team/` | Workstream briefs |
| `docs/report/` | Evaluation and security report, evidence tables, Responsible-AI statement |

## Quick start

Python **3.12** is required (`>=3.12,<3.13`).

```bash
uv sync --python 3.12 --all-extras
uv run --python 3.12 pytest -v
uv run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080
```

`--all-extras` is not optional. The contract types come from the organizers' kit, which is
not on PyPI and therefore cannot sit in `dependencies` (see `pyproject.toml`); the test
runner is an extra too. Without the flag `uv sync` installs the four base dependencies,
stops, and the next line fails with `No module named 'sentinel'`.

Then, from the official starter kit directory:

```bash
uv run sentinel eval public --defense-url http://127.0.0.1:8080
```

To check that a **fresh clone** of this repository actually works end to end -- not just
this working tree, which has had months of `.venv` and cache state to hide a broken
reproduction step -- clone into a scratch directory and run the whole quick start there:

```bash
scripts/verify_clean_clone.sh                              # local clone, offline
scripts/verify_clean_clone.sh https://github.com/<org>/<repo>.git   # a pushed remote
scripts/verify_clean_clone.sh "" /path/to/Sentinel_Starter_Kit       # + one real scenario
```

A local clone only ever sees committed state, which is the point: it is exactly what a judge's
`git clone` would see, uncommitted work and all its untested fixes included or not.

### In Docker

```bash
scripts/run_container.sh                                        # build, run, verify
HARIS_URL=http://127.0.0.1:8080 scripts/run_eval.sh <kit> public  # score the container
```

Use the script rather than a bare `docker run`. It publishes on `127.0.0.1` only (a bare
`-p 8080:8080` exposes the defense to your whole network), and it verifies from the host
that the container can make a real decision before returning.

That second check exists because a container can report `healthy` while nothing can reach
it: its HEALTHCHECK runs inside the container, and never crosses the host-to-container port
forward. On Docker Desktop for Windows we lost that forward once, and the evaluation that
followed produced 91 `DefenseUnavailable` errors and an official score of 0.080 without
failing. `run_eval.sh` now refuses to start against a target that cannot decide, and
rejects any run in which a decision failed to reach the defense.

### HARIS and the trace viewer together

```bash
docker compose up -d --build                                       # HARIS :8080, viewer :8090
HARIS_URL=http://127.0.0.1:8080 scripts/run_eval.sh <kit> public   # score it
docker compose down                                                # stop both
```

Open the viewer at <http://127.0.0.1:8090>. The two containers share the HARIS reasoning
journal through `<kit>/artifacts/haris/`, so runs scored against the container show *why*
each decision was made, not only what it was. `KIT_DIR` points at the kit and defaults to a
sibling folder named `Sentinel_Starter_Kit`; both ports are published on `127.0.0.1` only.
The viewer image holds only the viewer, not the kit or the decision code.

Through Docker Desktop's file sharing, the viewer's first listing of a large artifacts
folder takes about two minutes, since every trace is read once. The container starts it in
the background and the page says "Loading runs…" until it is done; after that a listing
takes under a second.

Only one HARIS can hold port 8080: stop a container from `run_container.sh` first
(`docker rm -f haris`).

**On Windows, run the `scripts/*.sh` commands from Git Bash.** In PowerShell, `bash` is
the WSL launcher, not Git Bash. Use
`& "C:\Program Files\Git\bin\bash.exe" scripts/run_eval.sh ...` on one line.

## Red-team

```bash
scripts/run_redteam.sh /path/to/Sentinel_Starter_Kit
```

Twelve held-out scenarios we wrote -- three domains, eight attack families, four hard
negatives -- plus an adaptive attacker that reads the defense's own decisions from
`request.transcript`, which the attacker shipped in the kit does not. It always opens with
the scenario's own payload and escalates only once that is stopped.

```bash
scripts/run_ablation.sh        /path/to/Sentinel_Starter_Kit public   # baseline ladder, published split
scripts/run_ablation_stages.sh /path/to/Sentinel_Starter_Kit          # HARIS minus one stage at a time
```

Every script serves this checkout on a free port, refuses to start unless it makes a real
decision, and refuses to report a run in which a decision never reached the defense.

The report: [`docs/report/report.md`](docs/report/report.md). The evidence tables behind it:
[`docs/report/findings.md`](docs/report/findings.md). What HARIS protects against, where it
fails, and when it asks a human: [`docs/report/responsible-ai.md`](docs/report/responsible-ai.md).

## Trace viewer

The observability layer joins two sources. The simulator's artifact says *what happened*; it
keeps only decision, risk score, confidence and reason codes, and no trust level ever reaches
it. HARIS writes its own journal alongside, which says *why*. They join on `(run_id, step_id)`.

```bash
scripts/run_dashboard.sh /path/to/Sentinel_Starter_Kit    # http://127.0.0.1:8090
```

Four linked panels: the step spine, the risk decomposition read from the recorded signals, the
trust chain, and the data flow from a sensitive value to the destination that was refused.
Move through steps with `J` and `K`; jump to the first intervention with `B`.

A trace recorded by any other defense still renders, just without the decomposition.

## Demo

The shot plan for the video demonstration is
[`docs/report/video-plan.md`](docs/report/video-plan.md): four scenarios, the exact commands,
the decisions and reason codes each one actually produced, and the narration keyed to the
panels of the trace viewer. It includes the failure we show on camera.

See `CLAUDE.md` for the full contract, the environment traps, and the command reference.
