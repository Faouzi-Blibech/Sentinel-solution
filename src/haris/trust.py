"""Resolves trust and sensitivity for every span the agent has observed.

Authority comes from provenance, never from wording. Anything we cannot prove
trusted is treated as untrusted: absence of evidence is not evidence of trust.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
from typing import TypeVar

from sentinel.core.provenance import Sensitivity, TrustLevel, least_trusted, most_sensitive
from sentinel.defenses.interface import DefenseRequest

_T = TypeVar("_T")


class TrustView:
    def __init__(self, request: DefenseRequest) -> None:
        self._request = request
        self._by_id = {record.id: record.provenance for record in request.provenance}
        # Per-decision memo cache for values derived purely from this view -- e.g. which
        # tokens are tainted at a given Sensitivity floor (haris/recall.py). A TrustView
        # is built once per decide_detailed() call and never reused across requests
        # (DefenseRequest is frozen), so caching here cannot leak stale or cross-request
        # data the way a module-level cache would; it only stops several stages that ask
        # the identical question of the identical view from each paying for their own
        # regex pass over the conversation. Measured: 7 extract_tainted_values scans per
        # decision down to 2, on a full 12-item window.
        self._memo: dict[Hashable, object] = {}

    def memo(self, key: Hashable, compute: Callable[[], _T]) -> _T:
        """Compute `compute()` at most once per (this view, key) and cache the result."""
        if key not in self._memo:
            self._memo[key] = compute()
        return self._memo[key]  # type: ignore[return-value]

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
