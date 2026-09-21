"""Typed view over the simulator-supplied policy_context.

The policy arrives as SYSTEM_POLICY-trusted input and is the only source that may
widen what the agent is permitted to do.
"""

from __future__ import annotations

from typing import Any


def _frozen_strings(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        return frozenset()
    return frozenset(str(item) for item in value if isinstance(item, str))


def _rule_kinds(value: Any) -> frozenset[str]:
    """Which rule kinds the active policy declares.

    The simulator ships `rules` as {id, kind, severity, description}: enough to know a
    rule is in force, never enough to reveal an answer. We had been ignoring it.
    """
    if not isinstance(value, list):
        return frozenset()
    return frozenset(
        str(rule["kind"]) for rule in value if isinstance(rule, dict) and isinstance(rule.get("kind"), str)
    )


class PolicyView:
    def __init__(self, policy_context: dict[str, Any] | None) -> None:
        context = policy_context or {}
        self.policy_id: str = str(context.get("policy_id", "unknown"))
        self.allowed_tools = _frozen_strings(context.get("allowed_tools"))
        self.consequential_tools = _frozen_strings(context.get("consequential_tools"))
        self.confirmation_required_tools = _frozen_strings(context.get("confirmation_required_tools"))
        self.internal_domains = _frozen_strings(context.get("internal_email_domains"))
        self.rule_kinds = _rule_kinds(context.get("rules"))
        # The policy states whether approval is required at all. Inferring it from our
        # own idea of "consequential" would gate tools the organizers never gated.
        self.confirmation_gate_active = (
            "requires_confirmation" in self.rule_kinds or bool(self.confirmation_required_tools)
        )

    def is_allowed(self, tool: str | None) -> bool:
        return tool is not None and tool in self.allowed_tools

    def is_consequential(self, tool: str | None) -> bool:
        return tool is not None and tool in self.consequential_tools

    def requires_confirmation(self, tool: str | None) -> bool:
        return tool is not None and tool in self.confirmation_required_tools

    def is_internal_destination(self, value: str) -> bool:
        """True only when the destination provably sits inside a declared internal domain."""
        lowered = value.lower()
        return any(
            lowered.endswith("@" + domain) or lowered.endswith("." + domain) or lowered == domain
            for domain in (d.lower() for d in self.internal_domains)
        )
