"""The kit's official Ollama agent, with the one fix its evidence depends on.

The kit now ships `sentinel.models.ollama_adapter.OllamaModelAdapter`, and every real-model
number we report is produced by it. This subclass changes how the request is *decoded*
and nothing about what the agent *is*: the prompt, the tool cards, the action parser and
its repair of `{"type": "<tool>"}` replies are all inherited from the kit unchanged, and
tests/test_ollama_agent.py asserts the messages are identical to the kit's.

What it adds, each measured on this machine before it was written:

* An explicit context window. The official adapter sends none, so Ollama falls back to a
  default sized from VRAM -- 4,096 tokens on an 8 GB GPU, and the kit's own docstring
  recommends a 6 GB card. A worst-case prompt (every tool in a domain plus the 12,000-char
  history window) is 6,117 tokens under the model's tokenizer, and Ollama drops the FRONT
  of an over-long prompt: the system prompt and the tool list. Unfixed, the agent silently
  stops being the reference agent partway through a scenario.
* Neutral decoding. Model files ship their own sampling defaults -- qwen3.5 carries
  presence_penalty 1.5 -- and overriding temperature alone leaves those reshaping greedy
  decoding. Every penalty is pinned to neutral.
* A fixed seed, so a rerun is as comparable as a quantized GPU runtime allows.
* A log of every reply the model got wrong and every one the parser rewrote, because the
  kit keeps 200 characters of an error and nothing of a repair.
* A host given in Ollama's own scheme-less form ("127.0.0.1:11434", "0.0.0.0") works.

Declared deviation from the official configuration: the model. The reference agent is
Qwen3-8B; runs here use whatever is installed locally (qwen3.5:9b), served quantized.

This is evaluation tooling. It lives outside src/haris on purpose: the defense declares
`models: []` and runs no model on its decision path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from sentinel.agent.base import AgentContext
from sentinel.core.actions import CandidateAction
from sentinel.models.base import ModelError
from sentinel.models.hf_adapter import parse_action
from sentinel.models.ollama_adapter import OllamaModelAdapter as OfficialOllamaAdapter

DEFAULT_MODEL = os.environ.get("HARIS_AGENT_MODEL", "qwen3.5:9b")
# Our own variable first. OLLAMA_HOST is Ollama's *server bind* setting and is documented
# without a scheme; the official adapter hands it to httpx as a URL unchanged.
DEFAULT_HOST = os.environ.get("HARIS_OLLAMA_URL") or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
AGENT_LOG = os.environ.get("HARIS_AGENT_LOG")

# Mirrors the kit adapter's defaults so the only differences are the ones listed above.
MAX_NEW_TOKENS = 768
MAX_CONTEXT_CHARS = 12_000
SEED = 7
WORST_CASE_PROMPT_TOKENS = 6_117
NUM_CTX = 16_384
NEUTRAL_DECODING = {
    "temperature": 0,
    "presence_penalty": 0,
    "frequency_penalty": 0,
    "repeat_penalty": 1,
}


def normalize_host(host: str) -> str:
    """Accept Ollama's own scheme-less host format as well as a URL."""
    host = host.strip().rstrip("/")
    if "://" not in host:
        host = "http://" + host
    scheme, rest = host.split("://", 1)
    # 0.0.0.0 is where the server listens, not an address a client can reach; Ollama's
    # own CLI makes the same substitution.
    if rest == "0.0.0.0" or rest.startswith("0.0.0.0:"):
        rest = "127.0.0.1" + rest[len("0.0.0.0") :]
    if scheme == "http" and ":" not in rest.split("/", 1)[0]:
        rest += ":11434"
    return f"{scheme}://{rest}"


class OllamaModelAdapter(OfficialOllamaAdapter):
    """The kit's Ollama agent with an explicit context window and neutral decoding."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str | None = None,
        max_new_tokens: int = MAX_NEW_TOKENS,
        max_context_chars: int = MAX_CONTEXT_CHARS,
        enable_thinking: bool = False,
        timeout_s: float = 600.0,
        transport: httpx.BaseTransport | None = None,
        *,
        seed: int = SEED,
        num_ctx: int = NUM_CTX,
        log_path: str | os.PathLike[str] | None = AGENT_LOG,
    ) -> None:
        if num_ctx < WORST_CASE_PROMPT_TOKENS + max_new_tokens:
            raise ValueError(
                f"num_ctx={num_ctx} cannot hold a worst-case prompt ({WORST_CASE_PROMPT_TOKENS} tokens) "
                f"plus {max_new_tokens} output tokens; Ollama would silently drop the system prompt"
            )
        super().__init__(
            model=model,
            host=normalize_host(host or DEFAULT_HOST),
            max_new_tokens=max_new_tokens,
            max_context_chars=max_context_chars,
            enable_thinking=enable_thinking,
            timeout_s=timeout_s,
            transport=transport,
        )
        self.model = model
        self._seed = seed
        self._num_ctx = num_ctx
        self._log = Path(log_path) if log_path else None

    def _payload(self, context: AgentContext) -> dict[str, Any]:
        """The official request, plus the options that keep the agent the reference agent."""
        return {
            "model": self._model,
            "messages": self._messages(context),
            "stream": False,
            "think": self._enable_thinking,
            "options": {
                **NEUTRAL_DECODING,
                "seed": self._seed,
                "num_predict": self._max_new_tokens,
                "num_ctx": self._num_ctx,
            },
        }

    def propose(self, context: AgentContext) -> CandidateAction:
        try:
            response = self._client.post("/api/chat", json=self._payload(context))
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # ValueError covers a non-JSON body. Anything that escapes as another type
            # aborts the kit's evaluate() and every other scenario's result with it.
            raise ModelError(f"could not get a reply from Ollama at {self._client.base_url}: {exc}") from exc
        if not isinstance(body, dict):
            raise ModelError("Ollama returned a non-object response")
        text = str((body.get("message") or {}).get("content", ""))
        known = {str(t["name"]) for t in self._tools}
        try:
            action = parse_action(text, known)
        except ModelError as error:
            self._record("invalid", text, str(error), None)
            raise
        # The kit's parser rewrites a {"type": "<tool>"} reply into the call it names.
        # Record when that happened, so an artifact can tell a model action from a
        # reconstructed one.
        try:
            parse_action(text)
        except ModelError as strict:
            self._record("repaired", text, str(strict), action)
        return action

    def _record(self, event: str, raw: str, error: str, action: CandidateAction | None) -> None:
        """Best effort: a logging failure must never become an agent failure."""
        if self._log is None:
            return
        try:
            self._log.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "event": event,
                "model": self.model,
                "goal": self._goal[:300],
                "raw": raw[:2000],
                "error": error[:500],
                "action": action.model_dump(mode="json") if action is not None else None,
            }
            with self._log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def factory(model: str = DEFAULT_MODEL, **kwargs: Any) -> Any:
    """A zero-argument factory, as RunConfig.model_factory expects."""

    def build() -> OllamaModelAdapter:
        return OllamaModelAdapter(model, **kwargs)

    return build
