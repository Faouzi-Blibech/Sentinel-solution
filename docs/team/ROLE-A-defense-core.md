# Role A — Defense Core

**You own the thing that decides.** Everything else in the submission renders or measures your
output. If your service is down or wrong, nothing else can score.

**Primary artifact:** `src/haris/` + `Dockerfile` + `sentinel-submission.yaml`
**Rubric block you carry:** Engineering & Responsible AI (20), and the substrate for all others.

## Read first

1. `CLAUDE.md` — the contract, the hard rules, the measured scoring reality
2. `docs/superpowers/specs/2026-09-20-haris-design.md` — §5 is your architecture
3. `docs/superpowers/plans/2026-09-20-haris-defense-core.md` — your task list, Tasks 1–13

## What you build

Five deterministic stages behind a FastAPI service:

| Stage | Module | Question it answers |
|---|---|---|
| 1. Trust resolution | `trust.py` | Where did every span the agent saw come from? |
| 2. Plan commitment | `planner.py` | Did the authenticated goal authorize this capability? |
| 3. Data-flow | `dataflow.py` | Does sensitive data reach an external sink, in any encoding? |
| 4. Risk fusion | `fusion.py` | What is the calibrated probability this action is unsafe? |
| 5. Decision + rewrite | `rewrite.py`, `engine.py` | Allow, block, escalate — or substitute something safer? |

## The three things that will sink you

1. **An unhandled exception.** `fail_mode` is CLOSED: a 500 makes the simulator block *every*
   action, benign utility falls below the 0.50 gate, and the submission becomes **ineligible**.
   `service.py` wraps everything. Never remove that wrapper.
2. **Over-blocking.** `core` is a geometric mean. A defense that blocks too much scores worse
   than one that allows too much. Prefer `REWRITE` over `BLOCK` whenever a safer equivalent
   exists — that is what the rewrite ladder is for.
3. **Hard-coding.** A scenario id, a filename, a domain name, or a literal payload string
   anywhere in `src/haris/` disqualifies that decision. Decide from provenance, policy, action
   shape, and content *structure* only.

## Your interface obligation

The `metadata` dict emitted by `engine.py` is the **frozen contract** with Roles B and C.
Publish it on Day 1 and change it only by agreement:

```json
{
  "haris_version": "1.0",
  "signals": [{"code": "...", "weight": 0.45, "value": 1.0, "contribution": 0.45, "detail": "..."}],
  "trust": {"observation_trust": "...", "least_trusted_seen": "...", "most_sensitive_seen": "..."},
  "plan": {"policy_id": "...", "tool": "..."},
  "dataflow": {"destination_class": "external|internal|none", "encoding": "...", "destinations": [...]},
  "stage_timings_ms": {"authority": 0.1, "plan": 0.1, "dataflow": 0.3},
  "total_ms": 0.6
}
```

Keep it under **4096 bytes** — `_trim_metadata` enforces this by dropping detail, never structure.

## Schedule

| When | Deliverable |
|---|---|
| Day 1 morning | Tasks 1–6: scaffold, encodings, trust, secrets, policy, signals. **Publish the metadata schema.** |
| Day 1 evening | Tasks 7–9: authority, plan commitment, data-flow. Green tests. |
| Day 2 morning | Tasks 10–12: fusion, rewrite, engine. **First end-to-end score against the kit.** |
| Day 2 afternoon | Task 13: Dockerfile + manifest. Run `sentinel submission validate`. Tune thresholds against hard negatives. |
| Day 2 evening | Hand a stable build to B for recording. **Feature freeze.** |
| Day 3 | Bug fixes only. Support C's ablation runs. Write the Responsible-AI section. |

## Done means

- `uv run --python 3.12 pytest -v` fully green
- `sentinel eval public --defense-url ...` shows **`defense errors 0`** and
  **`eligible (utility gate) True`**
- `sentinel submission validate .` passes with no `fail`
- Thresholds in `config.py` are justified by measured numbers, not guessed
