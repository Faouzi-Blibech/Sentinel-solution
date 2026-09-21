"""Resolves trust and sensitivity for every span the agent has observed.

Authority comes from provenance, never from wording. Anything we cannot prove
trusted is treated as untrusted: absence of evidence is not evidence of trust.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinel.core.provenance import Sensitivity, TrustLevel, least_trusted, most_sensitive
from sentinel.defenses.interface import DefenseRequest


class TrustView:
    def __init__(self, request: DefenseRequest) -> None:
        self._request = request
        self._by_id = {record.id: record.provenance for record in request.provenance}

    def trust_of(self, provenance_ids: Iterable[str]) -> TrustLevel:
        ids = list(provenance_ids)
        if not ids:
            # Unattributed content cannot be shown trusted, so it gets no authority.
            return TrustLevel.UNTRUSTED_EXTERNAL
        levels: list[TrustLevel] = []
        for pid in ids:
            provenance = self._by_id.get(pid)
            if provenance is None:
                # An id we cannot resolve is the worst case, not a free pass.
                return TrustLevel.ADVERSARY_CONTROLLED
            levels.append(provenance.trust_level)
        return least_trusted(levels)

    def sensitivity_of(self, provenance_ids: Iterable[str]) -> Sensitivity:
        levels = [self._by_id[pid].sensitivity for pid in provenance_ids if pid in self._by_id]
        return most_sensitive(levels)

    def observation_trust(self) -> TrustLevel:
        observation = self._request.observation
        if observation is None:
            return TrustLevel.AUTHENTICATED_USER
        return self.trust_of(observation.provenance_ids)

    def untrusted_spans(self) -> list[tuple[str, TrustLevel]]:
        """Every span that cannot carry instruction authority."""
        spans: list[tuple[str, TrustLevel]] = []
        for item in self._request.conversation:
            trust = self.trust_of(item.provenance_ids)
            if not trust.is_trusted:
                spans.append((item.content, trust))
        observation = self._request.observation
        if observation is not None:
            trust = self.trust_of(observation.provenance_ids)
            if not trust.is_trusted:
                spans.append((observation.content, trust))
        return spans

    def grounded_text(self) -> str:
        """Everything the action could legitimately be about: the goal plus trusted context.

        An identifier the authenticated user named is not evidence of injection when it
        turns up in a vendor email too -- that email is *about* the invoice the user
        asked for. Only a parameter the agent could have learned nowhere but from
        untrusted content shows influence.
        """
        parts = [self._request.user_goal]
        for item in self._request.conversation:
            if self.trust_of(item.provenance_ids).is_trusted:
                parts.append(item.content)
        return "\n".join(parts)

    def memory_spans(self) -> list[tuple[str, TrustLevel]]:
        """Recalled memory, with the trust it inherited when it was written.

        The spec is explicit: an entry written after reading untrusted content stays
        untrusted when recalled later. It is evidence, never an instruction with
        authority of its own.
        """
        return [
            (item.content, self.trust_of(item.provenance_ids))
            for item in self._request.conversation
            if item.role == "memory"
        ]

    def ordinary_spans(self, minimum: Sensitivity = Sensitivity.CONFIDENTIAL) -> list[str]:
        """Everything the agent saw BELOW the sensitivity floor.

        A word that also appears in ordinary context is ordinary language; a value that
        appears only in the confidential document is what we are protecting.
        """
        spans: list[str] = []
        for item in self._request.conversation:
            if self.sensitivity_of(item.provenance_ids).rank < minimum.rank:
                spans.append(item.content)
        observation = self._request.observation
        if observation is not None and self.sensitivity_of(observation.provenance_ids).rank < minimum.rank:
            spans.append(observation.content)
        return spans

    def sensitive_spans(self, minimum: Sensitivity = Sensitivity.CONFIDENTIAL) -> list[str]:
        """Content the agent saw that sits at or above a sensitivity floor."""
        spans: list[str] = []
        for item in self._request.conversation:
            if self.sensitivity_of(item.provenance_ids).rank >= minimum.rank:
                spans.append(item.content)
        observation = self._request.observation
        if observation is not None and self.sensitivity_of(observation.provenance_ids).rank >= minimum.rank:
            spans.append(observation.content)
        return spans
