"""Session-wide test isolation for `haris.recall.MEMORY`.

`MEMORY` is a module-level singleton (it has to be: the service is one long-lived
uvicorn process, and every request must see what earlier requests in the same run
remembered). Fifteen test files call `make_request`, whose default `run_id` is the
shared `"test-run"`, and nine call `decide()`, which remembers under it. Without a
suite-wide reset, every test after the first one to populate `"test-run"` runs against
a store some earlier, unrelated file already wrote into -- proven by running just
`test_leak_hardening.py` and `test_influence.py` together and finding five tokens still
tainted under `"test-run"` afterwards, with nothing in either file touching `MEMORY`.
`test_recall.py` had its own autouse fixture, but an autouse fixture is scoped to the
module that defines it: it protected that one file from itself and nothing else. A
defense whose most expensive failure mode is over-blocking (`test_over_refusal.py`)
must not have its answer depend on which other files pytest happened to run first.
"""

from __future__ import annotations

import pytest

from haris.recall import MEMORY


@pytest.fixture(autouse=True)
def _reset_taint_memory():
    MEMORY.clear()
    yield
    MEMORY.clear()
