"""Run-scoped taint memory.

`secrets.extract_tainted_values` derives secrets from `TrustView.sensitive_spans()`,
which only sees the conversation items in the request it was handed -- at most 12, the
kit's `runtime.max_conversation_items`. HARIS kept nothing between requests, so once the
document holding a secret scrolled out of that window, the value stopped being tainted
and a byte-identical write of it was allowed at risk 0.0 (reproduced by a
real model against a finance case-note scenario: it retried the write thirteen times and
HARIS caught twelve).

This module is the fix: a bounded, in-process memory of values this run has already
shown to be sensitive, keyed by `run_id`. `run_id` is read here purely as an opaque
partition key -- the same remember/recall logic executes no matter what it equals, and
no branch of this module's behaviour depends on which run it is. That is a different
thing from a scenario label reaching the decision *as content*, which is what
`tests/test_no_hardcoding.py`'s label-field check exists to catch; see the exemption
recorded there for the full argument.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Mapping

from sentinel.core.provenance import Sensitivity
from sentinel.defenses.interface import DefenseRequest

from haris.config import SETTINGS, Settings
from haris.secrets import extract_tainted_values
from haris.trust import TrustView


class TaintMemory:
    """Bounded per-run_id memory of tokens seen to be sensitive, and the highest
    `Sensitivity.rank` each was seen at.

    Two `OrderedDict` levels (run -> token -> rank) give least-recently-used eviction at
    both the run and the token level. `OrderedDict.move_to_end` is what makes "least
    recently used" mean insertion/touch order rather than a set's or a dict's hash
    order: `haris/dataflow.py` was once wrong in exactly this way -- a verdict flipped
    with PYTHONHASHSEED because it picked the "first" match out of a set -- and
    `tests/test_leak_hardening.py` exists to keep that fixed. This store must not
    reintroduce it, so no method here ever iterates a plain `set` or `dict` to decide
    eviction or touch order; only `OrderedDict`'s own deterministic order is used.

    Shared by a long-lived uvicorn process across concurrent requests, hence the lock.
    """

    def __init__(self, max_runs: int = 64, max_values_per_run: int = 256) -> None:
        self._max_runs = max_runs
        self._max_values_per_run = max_values_per_run
        self._runs: OrderedDict[str, OrderedDict[str, int]] = OrderedDict()
        self._lock = threading.Lock()

    def remember(self, run_id: str, values: Mapping[str, int]) -> None:
        """Raise the remembered rank of each token to at least `values[token]`.

        `values` may be built from a `set` (it is, at every call site: a set of
        normalized tokens paired with a fixed rank), so its iteration order is not
        trusted. Tokens are processed in sorted order instead, so which token ends up
        most-recently-used when several are remembered in one call -- and so which one
        would be evicted first afterwards -- never depends on PYTHONHASHSEED.
        """
        if not run_id or not values:
            return
        with self._lock:
            run = self._runs.setdefault(run_id, OrderedDict())
            self._runs.move_to_end(run_id)
            for token, rank in sorted(values.items()):
                if rank > run.get(token, -1):
                    run[token] = rank
                run.move_to_end(token)
                while len(run) > self._max_values_per_run:
                    run.popitem(last=False)  # evict the least recently touched token
            while len(self._runs) > self._max_runs:
                self._runs.popitem(last=False)  # evict the least recently touched run

    def recall(self, run_id: str, minimum_rank: int) -> set[str]:
        """Tokens remembered for this run at or above `minimum_rank`.

        A recall is also a touch, for both the run and every token it returns --
        "least recently used" means least recently remembered OR recalled, so a value
        the defense is still actively consulting is not the one dropped first.
        """
        if not run_id:
            return set()
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return set()
            self._runs.move_to_end(run_id)
            # `run.items()` is already deterministic (OrderedDict), unlike a set built
            # from it would be -- the hits are collected in that same stable order
            # before any are moved, so a multi-hit recall's resulting touch order is
            # reproducible too.
            hits = [token for token, rank in list(run.items()) if rank >= minimum_rank]
            for token in hits:
                run.move_to_end(token)
            return set(hits)

    def forget(self, run_id: str) -> None:
        with self._lock:
            self._runs.pop(run_id, None)

    def clear(self) -> None:
        with self._lock:
            self._runs.clear()


MEMORY = TaintMemory()

# Namespaced so this cannot collide with a key some other stage might one day memo onto
# the same TrustView for an unrelated purpose.
_CACHE_KEY = "haris.recall.extract_tainted_values"


def cached_extract(view: TrustView, minimum: Sensitivity) -> set[str]:
    """`secrets.extract_tainted_values`, memoized per (view, minimum) via `TrustView.memo`.

    `assess_dataflow`'s own visible-vs-recalled comparison, this function's CONFIDENTIAL
    and RESTRICTED derivation, and the engine's rewrite-path call all ask the identical
    question of the identical view within one decision. Before this cache each of those
    call sites paid for its own regex pass over the conversation -- 7 scans per decision
    on a full 12-item window, measured -- for an answer that cannot change mid-decision:
    `DefenseRequest` is frozen and `view` is constructed once per `decide_detailed` call.
    """
    return view.memo((_CACHE_KEY, minimum), lambda: extract_tainted_values(view, minimum))


def tainted_values(
    request: DefenseRequest,
    view: TrustView,
    minimum: Sensitivity = Sensitivity.CONFIDENTIAL,
    settings: Settings = SETTINGS,
) -> set[str]:
    """Values tainted by this request, plus what this run has already shown to be secret.

    Every caller that needs "what must not reach an untrusted sink" should call this
    instead of `secrets.extract_tainted_values` directly, so the memory step lives in
    exactly one place.
    """
    fresh = cached_extract(view, minimum)
    if not settings.taint_enabled or not request.run_id:
        # No identity to key memory on (or the ablation arm asking for the pre-fix
        # behaviour): inventing a key for an empty run_id would merge unrelated runs.
        return fresh
    try:
        # Remembered at each token's TRUE rank, derived independently of `minimum` --
        # not at whatever threshold this particular call happened to ask for. A value
        # that is actually restricted must out-rank a stale confidential memory of the
        # same token, and a confidential-only value must never be promoted to
        # restricted just because some caller's minimum was confidential. Both calls
        # are cache hits whenever `minimum` is already CONFIDENTIAL or RESTRICTED (the
        # only values any call site passes today), so this costs nothing extra.
        confidential = cached_extract(view, Sensitivity.CONFIDENTIAL)
        restricted = cached_extract(view, Sensitivity.RESTRICTED)
        MEMORY.remember(request.run_id, {token: Sensitivity.CONFIDENTIAL.rank for token in confidential})
        MEMORY.remember(request.run_id, {token: Sensitivity.RESTRICTED.rank for token in restricted})
        return fresh | MEMORY.recall(request.run_id, minimum.rank)
    except Exception:  # noqa: BLE001 -- a decision path must degrade, never raise
        return fresh
