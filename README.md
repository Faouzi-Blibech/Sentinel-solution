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

## Why this design

We measured every defense that ships in the official starter kit before designing anything,
and HARIS is scored the same way:

| Defense | Public (19) | Validation (9) |
|---|---|---|
| **HARIS (ours)** | **1.000** | **0.995** |
| `heuristic_risk` | 0.999 | 1.000 |
| `provenance` | 0.988 | 0.858 |
| `keyword` | 0.398 | **ineligible** — utility 0.40 below the 0.50 gate |
| `allow_all` | 0.131 | — |

On both splits HARIS holds **ASR 0.000, CVR 0.000, FBR 0.000, BTU 1.000, DFI 1.000**
with zero defense errors: it stops every attack while completing every benign task.
These are local diagnostics, not the jury score.

Two things follow. The published scenario library is **already solved** by a defense every team
was handed, so optimizing against it proves nothing. And `keyword` failing the *utility* gate is
a measured demonstration that keyword matching does not merely miss attacks — it destroys the
agent's usefulness.

So our contribution is not another scenario-passing defense. It is:

1. A defense whose every decision is **legible** — risk decomposed into named signals.
2. An **adaptive red-team** that reads the defense's own decisions and hill-climbs against them.
   The attacker shipped in the kit does not: it emits four fixed variants and never reads
   `request.transcript`.
3. An **honest ablation and failure analysis**, including the attacks that beat us.

## Architecture

```
DefenseRequest
   -> 1. Trust resolution     where did every observed span come from?
   -> 2. Plan commitment      did the authenticated goal authorize this capability?
   -> 3. Data-flow check      does sensitive data reach an external sink, in any encoding?
   -> 4. Risk fusion          calibrated probability, decomposed into signals
   -> 5. Decision + rewrite   allow / block / escalate / substitute something safer
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
| `docs/report/` | Technical report |

## Quick start

Python **3.12** is required (`>=3.12,<3.13`).

```bash
uv sync --python 3.12
uv run --python 3.12 pytest -v
uv run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080
```

Then, from the official starter kit directory:

```bash
uv run sentinel eval public --defense-url http://127.0.0.1:8080
```

## Red-team

```bash
scripts/run_redteam.sh /path/to/Sentinel_Starter_Kit
```

Five held-out scenarios we wrote, plus an adaptive attacker that reads the defense's own
decisions from `request.transcript` -- which the attacker shipped in the kit does not.

On that held-out set the shipped `heuristic_risk` defense falls from **0.999 to 0.812**
with a critical violation, while HARIS holds at **ASR 0.000**. The breach is a directive
carried inside a record-shaped payload: invisible to a defense keyed on
instruction-shaped language, plainly untrusted to one keyed on provenance.

Full results and limitations, including what our red-team does *not* establish:
`docs/report/findings.md`.

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

See `CLAUDE.md` for the full contract, the environment traps, and the command reference.
