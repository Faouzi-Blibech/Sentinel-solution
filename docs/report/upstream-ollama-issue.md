# Two small defects in `OllamaModelAdapter`

Filed against `github.com/Skan22/Sentinel_Starter_Kit`, commit `dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2`
(the pinned reference for this submission). Not filed by us -- this file is the ready-to-paste
issue body; filing it is left to whoever owns the GitHub account. Measurements below are
reproduced in `docs/report/report.md` §6, which has the fuller write-up and the raw trace.

Both defects live in `src/sentinel/models/ollama_adapter.py`, class `OllamaModelAdapter`. We
worked around both in our own evaluation tooling (`redteam/ollama_agent.py`, a subclass) rather
than patching the kit, per the challenge rules against editing it. This report is a gift, not a
complaint: the kit is the shared benchmark, and both fixes are two-line changes.

## 1. No context size is sent, so Ollama silently truncates the prompt

`OllamaModelAdapter.propose()` builds its request options as:

```python
"options": {"temperature": 0, "num_predict": self._max_new_tokens},
```

`num_ctx` is never set. Ollama then falls back to its own VRAM-based default -- **4,096
tokens on an 8 GB card**, per Ollama's own sizing table, and the kit's docstring in this same
file recommends running the quantized model on "about 5 GB" / a 6 GB card. We measured the
worst-case prompt this adapter can produce -- every tool card in a domain plus the full
12,000-character history window -- at **6,117 tokens** under the model's tokenizer, already
over that default before a single output token is generated.

Ollama does not error or warn when a chat request exceeds `num_ctx`. It truncates from the
**front** of the prompt, which for this adapter's message layout (`SYSTEM_PROMPT` then a
single user turn holding the tool list, goal and history) means the system prompt and the
tool schemas are what gets dropped first. An agent built this way is not making
tool-unaware or unconstrained decisions by choice -- it never received the constraints. On
an 8 GB card, every scenario whose prompt crosses ~4k tokens is silently running an agent
that never saw its own tool list, which is a different agent than the one the benchmark
intends to measure.

**Suggested patch**, sized so a worst-case prompt still fits with room for the reply:

```python
"options": {
    "temperature": 0,
    "num_predict": self._max_new_tokens,
    "num_ctx": 16_384,  # covers the worst-case prompt + max_new_tokens with headroom
},
```

## 2. `OLLAMA_HOST` is read as a URL, but Ollama's own format has none

```python
base_url=(host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/"),
```

This is handed straight to `httpx.Client(base_url=...)`, which needs a scheme. But
`OLLAMA_HOST` is Ollama's own server-bind environment variable, and Ollama documents and
emits it scheme-less -- `127.0.0.1:11434`, or `0.0.0.0` when bound to every interface. A
value taken directly from the environment as Ollama itself sets it (rather than hand-written
for this adapter) fails to construct a valid client, or silently resolves the host part
onto a default scheme's port that wasn't intended.

**Suggested patch**, normalizing before use:

```python
def _normalize_host(host: str) -> str:
    host = host.strip().rstrip("/")
    if "://" not in host:
        host = "http://" + host
    return host
```

and call it in `__init__` around the existing `host or os.environ.get("OLLAMA_HOST") or DEFAULT_HOST`
expression.

## What we did instead

`redteam/ollama_agent.py::OllamaModelAdapter` subclasses the kit's adapter unchanged in every
other respect -- same system prompt, tool cards, and action parser (asserted equal to the
kit's in `tests/test_ollama_agent.py`) -- and overrides only `_payload()` (adds `num_ctx`,
pinned to `16_384`, plus neutral decoding options so a model's own sampling defaults don't
reshape greedy decoding) and host handling (`normalize_host()`, which accepts both Ollama's
scheme-less form and a full URL). Every real-model number in `docs/report/report.md` §6 was
produced through this subclass.

## To file this

```bash
gh issue create \
  --repo Skan22/Sentinel_Starter_Kit \
  --title "OllamaModelAdapter: no num_ctx (silent prompt truncation) and OLLAMA_HOST read as a URL" \
  --body-file docs/report/upstream-ollama-issue.md
```
