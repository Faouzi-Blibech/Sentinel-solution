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


class PolicyView:
    def __init__(self, policy_context: dict[str, Any] | None) -> None:
        context = policy_context or {}
        self.policy_id: str = str(context.get("policy_id", "unknown"))
        self.allowed_tools = _frozen_strings(context.get("allowed_tools"))
        self.consequential_tools = _frozen_strings(context.get("consequential_tools"))
        self.confirmation_required_tools = _frozen_strings(context.get("confirmation_required_tools"))
        self.internal_domains = _frozen_strings(context.get("internal_email_domains"))

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
