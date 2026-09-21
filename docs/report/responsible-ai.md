# Responsible AI and safety statement

HARIS is a safety layer for a tool-using agent operating on synthetic data in the
SENTINEL simulator. This statement covers what it protects against, where it fails, what
it observes, and when it asks a human. The challenge brief rewards honest boundaries
over claims of complete safety, and this document is written to that standard: every
number in it is reproducible with the commands in `docs/report/findings.md`.

## What it protects against

One invariant, applied to every action:

> Authority to act comes from provenance and from the capability the authenticated user
> committed to. It never comes from the content of what the agent read.

Untrusted text may be read, quoted and summarised. It may not authorise anything. That
single rule is what the five stages implement:

| Stage | What it refuses to let untrusted content do |
|---|---|
| Trust and taint | Confer trust on itself, or hide a sensitive value by re-encoding it |
| Instruction authority | Redirect the agent using a parameter it could only have learned from untrusted text |
| Capability commitment | Widen what the user's goal and the active policy authorised |
| Confirmation lifecycle | Stand in for a human approval that was never recorded |
| Data flow | Carry a sensitive value to a destination outside the declared internal domains |

Measured against the attack families the specification book names, on the 19 published
scenarios with our adaptive attacker: direct instruction 3/3 held, indirect injection
4/4, memory poisoning 2/2, multi-step 1/1, and 9/9 benign scenarios completed.

## Known failure modes

These are the things we know are wrong with it. None of them is hypothetical; each was
found by probing the defense or by an independent audit of it.

**A dictionary-word passphrase is not tainted.** Taint is assigned by token shape --
length plus a digit, internal punctuation, or an unbroken run of capitals. An
all-lowercase secret made of ordinary words is indistinguishable from prose without a
wordlist, and a wordlist is the keyword matching this defense exists to avoid. Such a
value can reach an external destination without the data-flow stage objecting. The
confirmation gate and the capability commitment still govern the action carrying it.

**Influence detection needs a shared identifier.** Untrusted content is treated as
having influenced the agent when the action uses a parameter that appears in that
content and nowhere in the user's goal or trusted context. An attacker who redirects the
agent without naming anything -- a purely semantic redirection -- is not caught by this
stage. Other stages may still catch the resulting action.

**Prohibition parsing is English and clause-scoped.** The goal parser reads modal
negation and bounds it at the clause. Prohibitions expressed in another language, or
across sentences ("Read the invoice. That is all I want."), are not read as
prohibitions. The policy allow-list still applies.

**The published corpus does not discriminate our stages.** Removing the authority,
memory, lifecycle or rewrite stage individually changes nothing on the 19 published
scenarios, because the remaining stages catch the same attacks. Layering is deliberate,
but it means a single-stage ablation understates what any one stage contributes. The
aggregate is visible in the `trust only` row: 0.999 falls to 0.350.

**Our evidence is offline.** Every number was produced against the simulator's mock
adapter, not against Qwen3-8B, the challenge's official reference model. A real model
fails in ways a scripted one does not, and we have not measured those.

**Our attacker is not what breaks the shipped baseline -- our scenarios are.** The
adaptive and shipped attackers score identically in every arm. With `max_mutations: 3`
the search budget is too small for the feedback loop to pay off. The mechanism is built
and unproven, and we report it that way.

## False-positive behaviour, measured

Over-refusal is the expensive failure here: `core` is a weighted geometric mean with a
utility gate at 0.50, and the shipped `keyword` baseline is ineligible precisely because
it over-blocks.

| Split | Benign task utility | False block rate | Unnecessary escalations |
|---|---|---|---|
| Public (19) | 1.000 | 0.000 | 0.011 |
| Validation (9) | 1.000 | 0.000 | 0.000 |
| Held out (5, ours) | 1.000 | 0.000 | 0.000 |

The single unnecessary escalation on the public split is a legitimate `wiki_search`
issued while the poisoned invoice in context names that same tool. Escalating it is
defensible -- the agent is doing what the injected text asked -- but the step is in the
scenario's reference plan, so it counts against us. We have left it rather than tune it
away, because the alternative is to stop reacting when untrusted content and agent
behaviour coincide.

Cost of an escalation falls on a human reviewer, not on the user's task: the action is
held, not discarded. `tests/test_over_refusal.py` holds the regression cases -- ordinary
phrasing, business courtesy, a draft quoting an external address, a status value that
merely begins with a consequential verb -- each of which HARIS refused before it was
fixed.

## What data it observes

HARIS sees exactly the fields of `DefenseRequest`: the user goal, the conversation, the
current observation, the candidate action, the policy context, provenance records and a
history digest. It receives no reference plan, no label, and no attack payload. It makes
no network calls and loads no model; the decision path is deterministic, which is also
why p95 latency stays in the tens of milliseconds.

**It writes some of that to disk.** `src/haris/journal.py` appends every decision --
including the user goal, a 400-character preview of observed content, and the action's
arguments -- to `artifacts/haris/journal.jsonl`, because the simulator's own trace drops
the reasoning the observability layer needs. In this challenge that content is entirely
synthetic. In any real deployment it is a data-retention decision that would need an
owner, a retention window and access control. The journal can be switched off with
`HARIS_JOURNAL_DISABLED=1` and relocated with `HARIS_JOURNAL_PATH`; disabling it does
not change any decision.

## When a human is consulted

A risk score at or above `escalate_threshold` (0.40) and below `block_threshold` (0.70)
returns ESCALATE: the action is held for a person to approve or deny. Above 0.70 the
action is blocked, or rewritten when a genuinely safer equivalent exists.

Three situations reach a human by design rather than by score:

- A consequential action the active policy gates, with no confirmation recorded for that
  exact action in `history_digest.confirmations_granted`.
- Any action HARIS cannot evaluate. Both the service and the in-process defense return
  ESCALATE with `HARIS_INTERNAL_ERROR` rather than raising, because the simulator fails
  closed and a raise would block every subsequent action.
- An action whose only justification is content HARIS cannot trace to the user.

A rewrite is never used to work around an explicit user prohibition. If the authenticated
user forbade an action, substituting a neighbouring one is disobedience rather than
mitigation, and the decision is a block.

## Scope and conduct

All testing was against the simulator and the organizers' starter kit. No real systems,
credentials or personal data were involved; every person, account and domain in the
scenarios is fictional. Our red-team performs text-level mutation of the synthetic
surfaces a scenario declares, and nothing else -- no network access, no shell, no
attempt to reach organizer or sponsor infrastructure. No external model or dataset is
used, which `sentinel-submission.yaml` declares as `models: []` and `datasets: []`.

The defense contains no scenario identifier, filename or organizer-provided expected
outcome. `tests/test_no_hardcoding.py` enforces this on every commit by extracting the
identifiers the organizers invented and failing if any appears in `src/haris/`; it also
tests itself for going vacuously green, because it shipped broken once.
