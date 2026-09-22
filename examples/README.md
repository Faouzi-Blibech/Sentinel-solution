# `guard_any_agent.py`

A demo, not a benchmark: it shows `HarisGuard` -- HARIS's second front door, alongside
`POST /v1/decision` -- gating an agent loop it has never seen, from a clean clone, with
no GPU and no network by default.

## Run it

```bash
uv run --python 3.12 python examples/guard_any_agent.py
```

Takes a few seconds. No server, no kit, no Ollama required for the default backend.

## What it shows

Two scenarios, run through the same `HarisGuard` adapter a real OpenAI- or
Anthropic-shaped agent loop would call:

1. **`benign`** -- "look up a support ticket". Two ordinary steps (a tool call, then a
   final answer), both `ALLOW`. Nothing about it is touched: what HARIS is told to send
   is exactly what the agent proposed.
2. **`vendor_exfiltration`** -- the agent reads a vendor email. The email is a plausible
   business message (not a cartoon "IGNORE ALL PREVIOUS INSTRUCTIONS") that also happens
   to ask the agent to reply with a credential the agent has on hand and send it to an
   address the email itself names. The agent proposes exactly that `email_send` call.
   HARIS does not have to refuse outright: it comes back `REWRITE`, downgrading
   `email_send` to `email_draft` with the credential redacted out of the body -- the
   task still gets *something* done, and nothing leaves with the secret in it.

For every step, the script prints:

- what the agent proposed (tool name and arguments, or the final answer text),
- HARIS's decision, risk, confidence, and reason codes,
- and, when the decision is `REWRITE`, exactly what was sent **instead** -- in the
  caller's own OpenAI shape, ready to hand back to a real provider unchanged.

It ends with one summary line covering both scenarios.

## Reading the output

`ALLOW` means "sent as proposed". `REWRITE` means "sent instead" is a different,
verified-clean payload -- read it and check the credential is not in it (it isn't:
`tests/test_example_guard.py` asserts exactly that, against the real `Verdict`s, not
against the printed text). `BLOCK`/`ESCALATE` mean nothing was sent at all; neither
scenario here hits either, but the guard can return them too (see `tests/test_guard.py`
for examples of each).

## The optional real-model backend

```bash
uv run --python 3.12 python examples/guard_any_agent.py --model ollama:qwen3.5:4b
```

Runs the identical two goals through a real local model via Ollama
(`redteam/ollama_agent.py`, reused as-is) instead of the scripted stand-in. This is best
effort and honestly variable: a real model may not attempt the injection at all, may
phrase its tool call differently, or may not be running on your machine -- in which case
this backend prints why and skips cleanly, never a stack trace. The scripted backend
above is the reproducible claim; this one is "it also works against a model nobody
scripted".

Model support on the machine this was built and tested on: `qwen3.5:4b` produces the
kit's expected tool-call JSON; `qwen2.5vl:7b` (a vision model) does not, on any turn.
Your mileage with other models will vary -- that variability is the whole reason the
default backend is scripted.

## Using this in your own agent

This file is also the closest thing to a worked example of the pattern in the
README's **Use HARIS in your own agent** section: one `HarisGuard()`, one `.check()`
call per proposed action, `sources=`/`messages=` for whatever context the agent has
seen. Nothing here imports `sentinel.defenses.interface.DefenseRequest` directly --
`HarisGuard` builds one internally, which is the entire point of task 2's adapter.
