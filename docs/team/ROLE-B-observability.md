# Role B — Observability & Video

**You carry the largest single block of points: 40 of 100.** More than the report. More than
novelty and engineering combined. This is not the junior seat — treat it as the headline
deliverable.

**Primary artifacts:** `dashboard/` + the 5–10 minute video
**Rubric block:** Video & Observability (40)

## What the judges actually score

Straight from the specification book — build to these four words:

| Criterion | What it means concretely |
|---|---|
| **Robustness** | The attack genuinely reaches the defense and is shown failing — not staged, not edited around. |
| **Legibility** | The trace makes the decision clear: risk score, confidence, reason codes, and what happened next. |
| **Utility** | A benign task still completes normally, **on camera**. |
| **Precision** | The defense does not block or escalate needlessly. |

The brief is explicit: *"Judges watch the trace, not a leaderboard — an honest failure shown and
explained scores higher than a hidden one."* Put a real failure in the video.

## Stack

**FastAPI + one static HTML/JS page.** No npm, no build step, no framework.

Not Streamlit: its rerun-on-interaction model fights timeline UIs, and a default Streamlit theme
reads as templated, which costs Creativity & Novelty points. A single hand-built page tailing a
JSONL file is more reliable on demo day and looks deliberate.

## Data you consume

Run artifacts are JSONL at `artifacts/<run>/<scenario>-<defense>-s0.jsonl`, one `Event` per line:

```
event_id, run_id, step_id, seq, type, timestamp, actor, payload, provenance_refs, policy
```

`EventType`: `user_message`, `retrieval_result`, `memory_read`, `memory_write`, `tool_request`,
`tool_result`, `model_output`, `defense_decision`, `human_confirmation`, `policy_violation`,
`task_success`, `task_failure`.

`Actor`: `user`, `agent`, `defense`, `tool_gateway`, `human_simulator`, `evaluator`.

The rich part lives on `defense_decision` events, in the `metadata` dict Role A emits — signals
with weights and contributions, trust levels, data-flow destination and encoding, stage timings.
**Read that schema from `docs/team/ROLE-A-defense-core.md` and build against a recorded fixture
trace so you never wait on A.**

## The four panels

1. **Timeline** — every event in sequence, colour-coded by the four outcomes. Clicking an event
   drives the other three panels.
2. **Provenance & trust** — nodes coloured by the six trust levels. The injected content must be
   visibly hostile the moment it enters, and **stay** that colour when it is recalled from
   memory. That single visual carries the memory-poisoning story with no narration.
3. **Risk decomposition** — a horizontal bar splitting `risk_score` into its contributing
   signals, read straight from `metadata.signals`. This is the difference between a score that
   is *asserted* and one that is *explained*. It is the highest-value panel; build it first.
4. **Data-flow** — the path from a sensitive source to the attempted external sink, with the
   block point marked and the encoding named (`base64`, `reversed`, …).

## Why your demo cannot be called staged

`LogicalClock` in the kit makes artifacts **byte-identical across reruns of the same seed**.
Say so on camera and show the same digest twice. It pre-empts the obvious jury objection.

## Video structure (5–10 min)

1. **0:00–1:00** — The problem in one concrete sentence, and the architecture in one diagram.
2. **1:00–2:30** — *Utility first.* A benign task runs end to end and succeeds. Judges need to
   see the agent still works before they care that it is safe.
3. **2:30–5:00** — The attack. Show the injected content arriving, its trust label, the
   defense's decision, the risk decomposition, and the secure outcome.
4. **5:00–6:30** — A hard negative: legitimate work full of scary words that we **allow**.
   This is where precision is won.
5. **6:30–8:00** — **An honest failure.** Something our own red-team broke, with an explanation
   of why. The brief rewards this explicitly.
6. **8:00–9:00** — Ablation: the same attack against `heuristic_risk`, then against HARIS.

Narrate or caption throughout — judges must see *why*, not just the result.

## Schedule

| When | Deliverable |
|---|---|
| Day 1 | Record fixture traces from baseline runs. Build the JSONL loader and the timeline panel. |
| Day 2 morning | Risk-decomposition panel against A's real metadata. |
| Day 2 afternoon | Provenance and data-flow panels. Make it legible at 1080p — judges watch a video, not your monitor. |
| Day 2 evening | Full dry-run recording against A's frozen build. Find the problems now. |
| Day 3 morning | Final recording with narration. |
| Day 3 afternoon | Edit, caption, export. **Done by 18:00** — leave buffer before the 23:59 deadline. |

## Done means

- The dashboard loads any run artifact without code changes
- Every panel is readable in a 1080p screen recording
- The video shows: benign success, an attack blocked, a hard negative allowed, and an honest
  failure — in that order
- Nothing in the recording is a mock-up
