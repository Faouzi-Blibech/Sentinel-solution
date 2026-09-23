"""CaMeL's argument-origin capability check.

CaMeL's insight: a tool call is only as trustworthy as the *provenance* of each
argument that steers where it goes. A routing argument -- a recipient, an IBAN, an
account number -- is a legitimate use of the agent's capability to call a
consequential tool only when its value comes from the authenticated user or a trusted
record. When untrusted content is the ONLY place that value ever appears, the agent
has let that content pick a destination the goal never granted -- a capability
violation, independent of whether the value is itself well-formed or the wording
around it looks like an order. This is what closes the invoice-fraud bypass: a vendor
email supplying the payee IBAN for a payment the user did ask to make, at risk 0.00
under every content-shaped signal, because nothing about the IBAN's own text is
suspicious. What is suspicious is where it came from.

Deliberately narrower than haris/dataflow.py's leak rule: that rule watches a SECRET
leaving through a sink; this one watches a DESTINATION arriving from a source that
cannot authorize one. An email recipient is excluded here because dataflow.py already
owns that case (CaMeL's own email policy draws the same line).
"""

from __future__ import annotations

from sentinel.core.actions import ActionType
from sentinel.core.provenance import TrustLevel
from sentinel.defenses.interface import DefenseRequest

from haris.dataflow import _DESTINATION_KEYS
from haris.encodings import normalize
from haris.lifecycle import target_action
from haris.planner import effect_class
from haris.policy import PolicyView
from haris.signals import UNTRUSTED_ARGUMENT_ORIGIN, Signal
from haris.trust import TrustView

# Escalate, never block: paying a real invoice legitimately takes the IBAN from it, so
# this signal alone must land in the escalate band (0.40 <= r < 0.70), not the block
# band -- a human, not this defense, is who can tell a real vendor from a fraudulent one.
WEIGHT = 0.5
# Short tokens collide with ordinary prose once non-alphanumerics are stripped (same
# floor haris/authority.py uses for the same reason).
MIN_TOKEN_CHARS = 6

# dataflow._DESTINATION_KEYS is the single source of truth for "where a message goes";
# the extra keys here name "where money or an account goes", which dataflow.py has no
# reason to know about. Kept as a distinct name rather than folded into dataflow's set
# so that module's own leak logic is untouched.
ROUTING_KEYS = frozenset(_DESTINATION_KEYS) | frozenset(
    {"iban", "account", "account_number", "payee", "beneficiary", "wallet"}
)

_QUIET_DETAIL = "routing arguments grounded or not consequential"


def _is_consequential(tool: str, policy: PolicyView) -> bool:
    """policy.consequential_tools is the authority when the policy declares any; a
    policy that declares none has not opted out of the notion -- silence is not the
    same as "nothing here is consequential" -- so effect_class's verb-shape inference
    is the fallback. haris/lifecycle.py's own gate does NOT do this: it only ever asks
    the policy (`requires_confirmation` or `is_consequential`), with no verb-shape
    fallback, because the confirmation gate must never widen beyond what the policy
    actually declared. The two stages answer different questions -- this fallback is
    this function's own two-tier design, not a precedent borrowed from lifecycle.py.
    """
    if policy.consequential_tools:
        return policy.is_consequential(tool)
    # planner.py's own _EFFECT_ORDER ranks "unknown" (no recognized verb at all) the
    # SAME as "consequential" -- an unrecognized tool is exactly the case to err toward
    # "this could matter", and it would be inconsistent for this stage to go quiet on
    # the tools it has the least information about. A plain "== 'consequential'" string
    # check missed this: it silently excluded every unknown-shaped tool.
    return effect_class(tool) in ("consequential", "unknown")


def _least_trusted_source(token: str, spans: list[tuple[str, TrustLevel]]) -> TrustLevel | None:
    """Among the untrusted spans naming `token`, the one the value is LEAST safe to
    have come from -- the highest trust.rank -- so the reported detail names the worst
    case, not merely the first match order happened to produce.
    """
    worst: TrustLevel | None = None
    for content, trust in spans:
        if token not in normalize(content):
            continue
        if worst is None or trust.rank > worst.rank:
            worst = trust
    return worst


def assess_argument_origin(
    request: DefenseRequest,
    view: TrustView,
    policy: PolicyView,
    confirmation_pending: bool = False,
) -> list[Signal]:
    """One signal: did untrusted content, alone, supply a routing argument's value?

    Judges `target_action()`, the same rule every other stage follows -- a
    confirmation request wraps a real call, and judging the wrapper would let a
    laundered payee through unexamined. Two exemptions keep this signal from breaking
    its own "escalate, never block" contract (WEIGHT above) against lifecycle.py's
    confirmation gate:

    1. Asking is judged on the ACTION ITSELF, not target_action() -- lifecycle exempts
       the agent that asks (`asking` in assess_confirmation), and this signal must not
       re-penalize the very wrapper that exemption was written for by judging its
       payload as if it were the real call already taking effect.
    2. `confirmation_pending` -- true when lifecycle's own CONSEQUENTIAL_WITHOUT_
       CONFIRMATION already fired for this action -- means a human is already the
       gate; this signal firing too would noisy-OR an escalate into a block for the
       identical reason lifecycle already escalates. Nothing is lost by staying quiet:
       if the human declines, the action stays unconfirmed and lifecycle's own signal
       keeps it at escalate on every future step.
    """
    try:
        if request.candidate_action.type is ActionType.REQUEST_CONFIRMATION:
            return [
                Signal(
                    code=UNTRUSTED_ARGUMENT_ORIGIN,
                    weight=WEIGHT,
                    value=0.0,
                    detail="requesting confirmation, not acting",
                )
            ]

        effective = target_action(request.candidate_action)
        if effective.type is not ActionType.TOOL_CALL or effective.tool is None:
            return [Signal(code=UNTRUSTED_ARGUMENT_ORIGIN, weight=WEIGHT, value=0.0, detail=_QUIET_DETAIL)]

        if not _is_consequential(effective.tool, policy):
            return [Signal(code=UNTRUSTED_ARGUMENT_ORIGIN, weight=WEIGHT, value=0.0, detail=_QUIET_DETAIL)]

        if confirmation_pending:
            return [
                Signal(
                    code=UNTRUSTED_ARGUMENT_ORIGIN,
                    weight=WEIGHT,
                    value=0.0,
                    detail="deferred to the confirmation gate",
                )
            ]

        # A human who actually approved this exact action is now the recorded source
        # of every argument in it, whatever untrusted content also happened to name.
        if effective.digest() in set(request.history_digest.confirmations_granted):
            return [Signal(code=UNTRUSTED_ARGUMENT_ORIGIN, weight=WEIGHT, value=0.0, detail=_QUIET_DETAIL)]

        spans = view.untrusted_spans()
        grounded = normalize(view.grounded_text())

        for key, value in effective.arguments.items():
            if key.lower() not in ROUTING_KEYS or not isinstance(value, str):
                continue
            # An '@' value is a recipient address, which haris/dataflow.py already
            # governs (its own destination-class / internal-domain logic). Judging it
            # again here would be a second, conflicting opinion about the same field.
            if "@" in value:
                continue
            if policy.is_internal_destination(value):
                continue
            token = normalize(value)
            if len(token) < MIN_TOKEN_CHARS or token in grounded:
                continue
            trust = _least_trusted_source(token, spans)
            if trust is None:
                continue
            return [
                Signal(
                    code=UNTRUSTED_ARGUMENT_ORIGIN,
                    weight=WEIGHT,
                    value=1.0,
                    detail=f"{key} from {trust.value} content, not the goal",
                )
            ]

        return [Signal(code=UNTRUSTED_ARGUMENT_ORIGIN, weight=WEIGHT, value=0.0, detail=_QUIET_DETAIL)]
    except Exception:  # noqa: BLE001 -- a decision-path stage must degrade, never raise
        # An empty list and "nothing to report" look identical in the trace; a
        # crashed stage and a quiet one should not. Every other stage's own fallback
        # returns a quiet Signal, not nothing -- match that here too.
        return [Signal(code=UNTRUSTED_ARGUMENT_ORIGIN, weight=WEIGHT, value=0.0, detail="stage error")]
