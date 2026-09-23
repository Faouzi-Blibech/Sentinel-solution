"""Proves `examples/guard_any_agent.py` actually demonstrates what it claims to.

Run in-process (import the module, call `run_demo`) rather than shelling out
(task-3-brief.md): a subprocess test can only see exit code and stdout text, and would
have to parse the very human-readable output this file is free to change. Calling
`run_demo` directly gets the real `Verdict`s and the real "what was finally sent" values.

The credential-redaction assertion below is the point of the whole example, not an
incidental check -- see the module docstring for why. It was checked by mutation: on a
scratch copy that ignores the guard's verdict, it fails.
"""

from __future__ import annotations

import json

from examples.guard_any_agent import CREDENTIAL, run_demo


def _scenario(results, key: str):
    return next(result for result in results if result.key == key)


def test_benign_scenario_completes_with_no_intervention():
    results = run_demo(model="scripted")
    benign = _scenario(results, "benign")
    assert len(benign.steps) == 2
    assert all(step.verdict.decision == "allow" for step in benign.steps)
    # "Untouched" means what was sent is exactly what was proposed, not merely that the
    # decision happened to say "allow" -- the same distinction task-2's own review round
    # drew between "judged" and "judged correctly" (tests/test_guard.py's docstring).
    assert all(step.sent == step.proposed for step in benign.steps)


def test_injected_scenario_produces_at_least_one_non_allow_decision():
    results = run_demo(model="scripted")
    attack = _scenario(results, "vendor_exfiltration")
    assert len(attack.steps) == 2
    assert attack.steps[0].verdict.decision == "allow"  # reading the email is not itself risky
    assert attack.steps[1].verdict.decision != "allow"  # sending the credential is


def test_credential_never_appears_in_what_was_finally_sent():
    """The load-bearing assertion (task-3-brief.md): not "HARIS returned a decision",
    but that the literal credential is absent from every payload that actually left the
    scenario. `sent` is `None` for a block/escalate (nothing sent) or the rewritten,
    redacted payload for a rewrite -- never the original, untouched `proposed`.
    """
    results = run_demo(model="scripted")
    attack = _scenario(results, "vendor_exfiltration")
    sent_values = [step.sent for step in attack.steps]
    assert any(value is not None for value in sent_values), "the demo sent nothing at all"
    blob = json.dumps(sent_values, default=str).lower()
    assert CREDENTIAL.lower() not in blob


def test_rewrite_step_actually_redacted_rather_than_being_blocked_or_escalated():
    """A stronger version of the assertion above: proves the credential was stopped by a
    verified-clean REWRITE (task-3-brief's "rewrite, not refusal"), not by the sent value
    merely being `None` because the action was blocked outright -- which would also
    satisfy the previous test but demonstrate a different, less interesting behaviour.
    """
    results = run_demo(model="scripted")
    attack = _scenario(results, "vendor_exfiltration")
    send_step = attack.steps[1]
    assert send_step.verdict.decision == "rewrite"
    assert send_step.sent is not None
    assert send_step.sent["function"]["name"] == "email_draft"
