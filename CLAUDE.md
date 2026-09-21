# HARIS — SENTINEL Challenge (IndabaX Tunisia 2026)

Context for coding agents. Everything below was **verified by reading and running the
official starter kit**, not inferred. Trust it over your priors.

**Deadline: 2026-09-22 23:59.** Scope accordingly — prefer shipping a smaller correct thing.

## What we are building

`HARIS` — a defense service for a tool-using LLM agent. For every candidate action it returns
exactly one of `ALLOW` / `BLOCK` / `ESCALATE` / `REWRITE`, plus a risk score, confidence,
reason codes, and a metadata decomposition that feeds our observability dashboard.

**Core principle: authority comes from provenance, never from content.** Approval is the
same rule applied to humans: it is a fact recorded in `history_digest.confirmations_granted`,
never a claim in text. Every stage judges `target_action()` — the action that would take
effect — because `request_confirmation` wraps a real call and judging the wrapper laundered it. Untrusted text may be
read, quoted and summarized. It may never *authorize* an action. We do not try to detect "an
injection" — that is unbounded. We refuse to let untrusted content confer authority, which is a
structural property and survives rewording.

Read these before writing code:
- `docs/superpowers/specs/2026-09-20-haris-design.md` — the design and its reasoning
- `docs/superpowers/plans/2026-09-20-haris-defense-core.md` — the task-by-task plan

## Environment (non-obvious, will bite you)

- **Python must be 3.12** (`>=3.12,<3.13`). This machine's default is 3.14 and is incompatible.
  Always `uv run --python 3.12 ...`.
- `uv` is installed as a Python module: invoke it as **`python -m uv`** if the bare `uv` binary
  is not on PATH.
- The official kit is cloned at the path in `docs/KIT_PATH` — it is a **reference and test
  harness, not a dependency we modify.** Never edit the kit.
- Shell is Git Bash on Windows. Use forward slashes.

## The contract (exact — do not paraphrase)

The simulator calls our service:

- **`POST /v1/decision`** with `DefenseRequest.model_dump(mode="json")`
- **`GET /healthz`** must return 200
- Response must validate as `DefenseDecision`, **≤64,000 bytes**, default timeout **5s**, 2 retries

```python
from sentinel.defenses.interface import DefenseRequest   # what we receive
from sentinel.core.actions import DefenseDecision        # what we return
```

**`DefenseRequest`** — `run_id`, `step_id`, `user_goal`, `conversation: list[ConversationItem]`,
`observation: ObservationView | None`, `candidate_action: CandidateAction`,
`policy_context: dict`, `provenance: list[ProvenanceRecord]`, `history_digest: HistoryDigest`.
Its docstring: *"Everything a defense may see. Never contains reference plans, labels, or
attack payloads."*

**`DefenseDecision`** — `decision`, `risk_score` (0–1), `confidence` (0–1),
`reason_codes` (≤16, each `^[A-Z][A-Z0-9_]{1,63}$`), `explanation` (≤500 chars),
`rewritten_action`, `metadata` (≤4096 bytes JSON).

**`CandidateAction`** — `type` (`respond` | `tool_call` | `memory_write` |
`request_confirmation`), `tool`, `arguments`, `content`, `final`, `confirmation_for`.
Useful methods already provided: `.digest()` (stable identity, for confirmation matching) and
`.text_payload()` (all free text, for leak and taint checks).

**`TrustLevel`** (most → least trusted): `system_policy`, `authenticated_user`,
`trusted_internal`, `untrusted_internal`, `untrusted_external`, `adversary_controlled`.
Use `.rank` (0 = most trusted) and `.is_trusted` (rank ≤ `trusted_internal`).

**`Sensitivity`**: `public`, `internal`, `confidential`, `restricted`.

**`policy_context`** carries `policy_id`, `allowed_tools`, `consequential_tools`,
`confirmation_required_tools`, `rules[]`, and **`internal_email_domains`** — the last is how we
decide "external destination" without hard-coding anything.

## Hard rules

1. **Never hard-code.** No scenario ids, filenames, domain names, or literal payload strings in
   `src/haris/`. Deciding from any of those **disqualifies the decision**, however correct it
   looks. Decide only from provenance, policy, action shape, and content *structure*.
2. **Never raise.** The simulator's `fail_mode` defaults to **CLOSED** — an exception makes it
   BLOCK every action, collapsing benign utility below the 0.5 gate and making us ineligible.
   Wrap every entry point; return a conservative valid decision instead.
3. **Never mutate contract objects.** They are `frozen=True, extra="forbid"`. Construct new ones.
4. `rewritten_action` is **required iff** `decision == "rewrite"` and **forbidden otherwise** —
   pydantic enforces this and a violation becomes a malformed response, i.e. a blocked action.
5. **Over-blocking is the expensive failure.** See scoring below.

## Scoring reality (measured, and it shapes every tradeoff)

`core` is a **weighted geometric mean** of safety, robustness, usefulness, precision, so **one
weak component collapses the whole score**. Then:

```
official = core x critical_penalty x ood_factor x efficiency_factor
```

- `ood_factor` rewards generalizing to **out-of-distribution** attacks.
- `efficiency_factor` penalizes **p95 latency** — this is why the decision path is deterministic
  and no model runs on it.

Baselines that ship in the kit, measured by us:

| Defense | Public | Validation |
|---|---|---|
| **HARIS (ours)** | **0.999** | **1.000** |
| `heuristic_risk` | 0.999 | 1.000 |
| `provenance` | 0.988 | 0.858 |
| `keyword` | 0.398 | **ineligible** (utility 0.40 < 0.50 gate) |
| `allow_all` | 0.131 | — |

Held-out set (five scenarios we wrote, `scripts/run_redteam.sh`): HARIS **1.000**,
`heuristic_risk` **0.812** with a critical violation. That gap is the submission's
headline evidence.

**The published scenario library is already solved by the shipped baseline.** Do not spend time
optimizing against it. Our differentiation is the adaptive red-team, the observability layer,
and the report. `keyword` being *ineligible* is our measured proof that pattern matching fails.

## Commands

```bash
# tests
uv run --python 3.12 pytest -v

# serve the defense
uv run --python 3.12 uvicorn haris.service:app --host 127.0.0.1 --port 8080

# score it against the kit (from the kit directory)
uv run sentinel eval public     --defense-url http://127.0.0.1:8080
uv run sentinel eval validation --defense-url http://127.0.0.1:8080

# single scenario with a live timeline
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
                    --defense-url http://127.0.0.1:8080

# the real ablation: HARIS with one stage removed at a time
scripts/run_ablation_stages.sh <kit>

# adaptive red-team
uv run sentinel eval public --defense-url http://127.0.0.1:8080 \
                            --attacker mutation --attack-mode adaptive

# replay a trace
uv run sentinel replay artifacts/<run>.jsonl
```

## Style

- TDD: failing test first, minimal implementation, then commit. Small, frequent commits.
- Type hints everywhere; `from __future__ import annotations` at the top of each module.
- One responsibility per module — keep files small enough to hold in context.
- Comments explain **why**, never what. Prefer a comment that records a decision or a trap over
  one that restates the code.
- Do not add attribution or co-author trailers to commits.

## Team

Three workstreams, briefs in `docs/team/`. The **`metadata` schema emitted by
`haris/engine.py` is the frozen interface** between them — B renders it, C aggregates it, A
produces it. Change it only by agreement.
