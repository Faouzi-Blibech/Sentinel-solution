<!--
Internal note, not part of the posted issue body (kept out of the rendered text below so
`gh issue create --body-file` never sends it): filed against
github.com/Skan22/Sentinel_Starter_Kit, commit dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2 (the
pinned reference for this submission). Not filed by us -- this file is the ready-to-paste
issue body; filing it is left to whoever owns the GitHub account. Our fuller write-up and
raw trace live in our own report (docs/report/report.md §6), which the organizers cannot
see, so nothing below points a reader at it.
-->

Both defects live in `src/sentinel/models/ollama_adapter.py`, class `OllamaModelAdapter`. We
worked around both in our own evaluation tooling (a subclass) rather than patching the kit,
per the challenge rules against editing it. This report is a gift, not a complaint: the kit
is the shared benchmark, and both fixes are two-line changes.

## 1. No context size is sent, so Ollama silently truncates the prompt

`OllamaModelAdapter.propose()` builds its request options as:

```python
"options": {"temperature": 0, "num_predict": self._max_new_tokens},
```

`num_ctx` is never set -- read directly off this method, not inferred. Ollama's own current
documentation (https://docs.ollama.com/context-length) says the default it falls back to is
chosen from detected VRAM: 4k context under 24 GiB, 32k from 24-48 GiB, 256k at 48 GiB and
up. Both the 8 GB GPU we evaluated on and the ~5 GB / 6 GB card this same file's own
docstring recommends as the minimum sit well under that 24 GiB line, so either one lands in
the same 4k tier: a 4,096-token default. We measured the worst-case prompt this adapter can
produce -- every tool card in a domain plus the full 12,000-character history window -- at
6,117 tokens under the model's tokenizer (`redteam/ollama_agent.py:WORST_CASE_PROMPT_TOKENS`),
already past that 4k tier before a single output token is generated.

We have not captured a request/response pair showing truncation happen against this adapter,
so the rest of this section is inference, not something we observed directly. Multiple
independent reports describe Ollama dropping tokens from the front of an over-long prompt
and still returning 200 OK, unlike llama.cpp's own server, which rejects the request
outright. If that is what happens here, it would explain something worse than a shorter
memory: this adapter's message layout is `SYSTEM_PROMPT` followed by a single user turn
holding the tool list, goal and history, in that order -- so a front-eviction would take the
system prompt and tool schemas first, not the oldest conversation turns. We would be glad to
be corrected on the exact eviction order; either way, a prompt already ~2,000 tokens past the
applicable default seems worth checking regardless of which end it trims from.

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
scheme-less form and a full URL). Every real-model number in our own report was produced
through this subclass.

<!--
Internal note, not part of the posted issue body: to file this,

gh issue create \
  --repo Skan22/Sentinel_Starter_Kit \
  --title "OllamaModelAdapter: no num_ctx (silent prompt truncation) and OLLAMA_HOST read as a URL" \
  --body-file docs/report/upstream-ollama-issue.md
-->
