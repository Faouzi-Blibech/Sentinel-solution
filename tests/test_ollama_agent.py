"""The real-model adapter may change how the agent runs, never what the agent is.

The kit's rule, from sentinel/models/hf_adapter.py: "What the agent *is* stays fixed --
same model, same tools, same system prompt, and no safety instructions added to it.
Hardening the agent moves work out of your defense, which is the part being judged."

An adapter that quietly added "never reveal credentials" to the system prompt, or showed
the model the reference plan, would inflate every number we report against a real model
and credit HARIS with work the agent did. These tests hold the adapter to the rule. They
stub the HTTP call, so they run without Ollama.
"""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest
from sentinel.agent.base import AgentContext
from sentinel.core.actions import ActionType
from sentinel.core.scenario import PlanStep
from sentinel.models.base import ModelError, TurnHints
from sentinel.models.hf_adapter import SYSTEM_PROMPT, tool_card

from redteam import ollama_agent
from redteam.ollama_agent import OllamaModelAdapter

def _real_tool_spec(name: str) -> dict[str, Any]:
    """A tool spec exactly as the simulator hands it to the agent.

    Built from the kit's own tool class rather than written by hand, so the fixture cannot
    drift from what `TurnHints.tools` really contains -- a hand-written one already did,
    by omitting the `consequential` field the kit's tool_card requires.
    """
    import sentinel.domains.enterprise.tools as enterprise

    for candidate in vars(enterprise).values():
        if isinstance(candidate, type) and getattr(candidate, "name", None) == name and hasattr(candidate, "spec"):
            return candidate().spec()
    raise LookupError(name)


TOOLS = [_real_tool_spec("email_read")]


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self, *_: Any) -> bytes:
        return self._body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Record what the adapter sends and answer with a well-formed action."""
    sent: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0) -> _Response:
        sent["body"] = json.loads(request.data)
        sent["url"] = request.full_url
        return _Response(
            {"message": {"content": '{"type": "tool_call", "tool": "email_read", "arguments": {"email_id": "EM-2001"}}'}}
        )

    monkeypatch.setattr(ollama_agent.urllib.request, "urlopen", fake_urlopen)
    return sent


def _context(*texts: str) -> AgentContext:
    from types import SimpleNamespace

    return SimpleNamespace(observations=[SimpleNamespace(kind="tool_result", text=t) for t in texts])  # type: ignore[return-value]


def _propose(adapter: OllamaModelAdapter, hints: TurnHints | None = None) -> Any:
    adapter.start_turn("Read the invoice email.", hints or TurnHints(tools=TOOLS))
    return adapter.propose(_context("an observation"))


def test_the_system_prompt_is_the_kits_verbatim(captured: dict[str, Any]) -> None:
    _propose(OllamaModelAdapter())
    messages = captured["body"]["messages"]
    assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}


def test_no_extra_instructions_reach_the_model(captured: dict[str, Any]) -> None:
    """Exactly one system message and one user message, as in the reference adapter."""
    _propose(OllamaModelAdapter())
    messages = captured["body"]["messages"]
    assert [m["role"] for m in messages] == ["system", "user"]


def test_tool_cards_are_built_by_the_kit(captured: dict[str, Any]) -> None:
    _propose(OllamaModelAdapter())
    user = captured["body"]["messages"][1]["content"]
    assert json.dumps([tool_card(t) for t in TOOLS]) in user


def test_the_reference_plan_is_never_shown_to_the_model(captured: dict[str, Any]) -> None:
    """The plan is a simulator affordance for the mock. A real agent that saw it would be
    solving a much easier problem, and every number we reported would be inflated."""
    plan = (
        PlanStep.model_validate(
            {"id": "secret_step", "action": "tool_call", "tool": "email_read", "args": {"email_id": "PLAN-ONLY-7731"}}
        ),
    )
    _propose(OllamaModelAdapter(), TurnHints(tools=TOOLS, reference_plan=plan))
    sent = json.dumps(captured["body"])
    assert "PLAN-ONLY-7731" not in sent
    assert "secret_step" not in sent


def test_decoding_is_greedy_and_seeded(captured: dict[str, Any]) -> None:
    """Mirrors the reference adapter's do_sample=False, so reruns are comparable."""
    _propose(OllamaModelAdapter(seed=11))
    options = captured["body"]["options"]
    assert options["temperature"] == 0
    assert options["seed"] == 11
    assert options["num_predict"] == ollama_agent.MAX_NEW_TOKENS


def test_thinking_is_off_by_default_like_the_reference(captured: dict[str, Any]) -> None:
    _propose(OllamaModelAdapter())
    assert captured["body"]["think"] is False


def test_output_is_parsed_by_the_kits_own_parser(captured: dict[str, Any]) -> None:
    action = _propose(OllamaModelAdapter())
    assert action.type is ActionType.TOOL_CALL
    assert action.tool == "email_read"


def test_an_unreachable_model_is_a_model_error_not_a_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    """The agent loop turns ModelError into a recorded termination; anything else would
    abort the whole run and lose every other scenario's result with it."""

    def down(*_: Any, **__: Any) -> Any:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(ollama_agent.urllib.request, "urlopen", down)
    with pytest.raises(ModelError):
        _propose(OllamaModelAdapter())


def test_the_adapter_is_not_part_of_the_defense() -> None:
    """The defense declares `models: []`. No model code may live in src/haris."""
    import pathlib

    source = pathlib.Path(__file__).resolve().parents[1] / "src" / "haris"
    offenders = [
        p.name for p in source.glob("*.py") if "ollama" in p.read_text(encoding="utf-8").lower()
    ]
    assert not offenders, f"model code reached the defense: {offenders}"


def test_the_context_window_holds_a_worst_case_prompt(captured: dict[str, Any]) -> None:
    """Ollama's VRAM-based default was 4,096 tokens against a measured 6,117-token worst
    case, and it drops the FRONT of an over-long prompt -- the system prompt. The window
    must be set explicitly and be large enough."""
    _propose(OllamaModelAdapter())
    num_ctx = captured["body"]["options"]["num_ctx"]
    assert num_ctx >= ollama_agent.WORST_CASE_PROMPT_TOKENS + ollama_agent.MAX_NEW_TOKENS


def test_a_window_too_small_for_the_prompt_is_refused() -> None:
    with pytest.raises(ValueError, match="system prompt"):
        OllamaModelAdapter(num_ctx=4096)


def test_the_models_own_sampling_penalties_are_neutralised(captured: dict[str, Any]) -> None:
    """The Modelfile ships presence_penalty 1.5, which reshapes logits even under greedy
    decoding. The reference adapter applies no penalty, so neither may we."""
    _propose(OllamaModelAdapter())
    options = captured["body"]["options"]
    assert options["presence_penalty"] == 0
    assert options["frequency_penalty"] == 0
    assert options["repeat_penalty"] == 1
