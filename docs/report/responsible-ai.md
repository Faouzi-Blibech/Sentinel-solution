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
single rule is what the stages implement:

| Stage | What it refuses to let untrusted content do |
|---|---|
| Trust and taint | Confer trust on itself, or hide a sensitive value by re-encoding it |
| Instruction authority | Redirect the agent using a parameter it could only have learned from untrusted text |
| Capability commitment | Widen what the user's goal and the active policy authorised |
| Confirmation lifecycle | Stand in for a human approval that was never recorded |
| Argument origin | Choose, on its own, the payee, account or endpoint of a consequential action |
| Data flow | Carry a sensitive value to a destination outside the declared internal domains |

Measured against the attack families the specification book names, on the 40 published
scenarios: data exfiltration 21/21 held, direct instruction 3/3, indirect injection 4/4,
memory poisoning 2/2, multi-step 1/1, and 9/9 benign scenarios completed. On a real model
(Qwen 3.5 9B) it held all 10 attacks the model attempted -- the other 2 it never tried --
after we fixed the one flaw that run exposed (below).

## Known failure modes

These are the things we know are wrong with it. None of them is hypothetical; each was
found by probing the defense or by an independent audit of it.

**Secrets were forgotten when they left the conversation window. Fixed.** The
kit shows the defense only the last 12 conversation items, and HARIS kept nothing between
requests. On Qwen 3.5 9B the agent retried the same leaking case note until the document
holding the secret had scrolled out; HARIS rewrote it twelve times and allowed the
thirteenth. Two restricted keys leaked this way. HARIS now remembers tainted values for the
whole run; on the same model and scenarios it rewrote all 23 attempts in each. The
regression scenario `redteam/regression/haris_regression_fin_window_rollover_retry.yaml`
reproduces it.

**Unattributed tool output is not grounding.** The kit returns some tool results, such as
the agent's own `payment_prepare`, with no provenance. HARIS treats them as untrusted, so a
legitimate note naming that payment id looks like obedience when an injection names it
too. It costs one escalation under the kit's mutation attacker and none under its official
scorer, and we keep "absence of evidence is not trust" rather than loosen it.

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
prohibitions. The policy allow-list still applies. Measured: "Do not execute the payment"
blocks `payment_execute` at risk 0.97; the same sentence in French ("N'exécute pas le
paiement") allows it at 0.35. Where the policy requires a recorded approval for the tool, the
action still escalates to a human (0.68). For users who write in French or Arabic this is the
most important open limitation.

**The attacker can steer what the agent reads.** Reading is not a harmful effect, so HARIS
allows reads an injection asked for; on the public split, 14 such reads ran (`asset_lookup`,
`case_document_read`, `wiki_search`, `customer_lookup`), none causing a violation. HARIS
gates the point where data leaves, not the gathering.

**A redaction can break the call.** Redaction is value-based: when a secret-shaped value is
also the record's key (a `case_id`), the rewrite redacts it and the tool rejects the call.
Nothing leaks, but the write is lost.

**The risk score is not a calibrated probability.** Its weights say how strongly a signal
proves harm and were set by hand, never fitted to outcomes: Brier 0.095 and ECE 0.080 on the
public split, worst in finance (ECE 0.141) and SOC (0.129). A risk of 0.35 should be read as
"one weak signal", not as a 35% chance.

**Display-name recipients were judged external. Fixed.** `Alice Martin <alice@corp.example>`
ends in `>`, so a colleague was treated as outside the organisation and a legitimate email
lost the value the user asked to send. A recipient list is now judged by its addresses, and
only when the value is nothing but recipients, so `Alice <alice@corp.example>@evil.example`
still counts as external.

**Single stages look redundant.** Removing the authority, memory or lifecycle stage alone
changes nothing on either corpus, because the remaining stages catch the same attacks.
Data flow (public 0.999 to 0.150) and capability commitment (to 0.903) carry the load.
The aggregate is the `trust + authority only` row: 0.999 falls to 0.091.

**Our real-model evidence is thin.** Two runs of Qwen 3.5 9B, a quantized substitute for
the reference Qwen3-8B, on 16 scenarios whose attack texts we or the organizers wrote. The
first found the window flaw above, which no mock run could have; the second, on the fixed
code, held all 10 attacks the model attempted (the other 2 it never tried).

**Our attacker is not what breaks the shipped baseline -- our scenarios are.** Until we
fixed it, our adaptive attacker was *weaker* than the kit's: its cross-scenario memory
vetoed the scenario's own payload. It now always opens with that payload and matches or
beats the kit's attacker in every arm, but with `max_mutations: 3` its learning rarely
pays off. The mechanism is built and largely unproven, and we report it that way.

## False-positive behaviour, measured

Over-refusal is the expensive failure here: `core` is a weighted geometric mean with a
utility gate at 0.50, and the shipped `keyword` baseline is ineligible precisely because
it over-blocks.

| Split | Benign task utility | False block rate | Unnecessary escalations |
|---|---|---|---|
| Public (40) | 1.000 | 0.000 | 0.000 |
| Validation (9) | 1.000 | 0.000 | 0.000 |
| Held out (12, ours) | 1.000 | 0.000 | 0.000 |
| Real model, Qwen 3.5 9B | same as without HARIS | -- | 1 escalation, approved |

Public had four unnecessary escalations until we stopped counting a tool's name as proof
of obedience: the agent knows its tools from the policy, not from what it read.

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
