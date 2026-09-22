# Official starter kit

Clone of `github.com/Skan22/Sentinel_Starter_Kit`. It is a **reference and test harness, not a
dependency we modify.** Never edit it.

Clone it into the root of this checkout, next to `src/` and `tests/`:

```bash
git clone https://github.com/Skan22/Sentinel_Starter_Kit.git
cd Sentinel_Starter_Kit
uv sync --python 3.12
```

That location is not incidental: `tests/test_no_hardcoding.py::_kit_root` looks there
(among other places) so the disqualification audit -- the check guarding the one rule in
the spec book that disqualifies a decision -- runs by default instead of silently skipping.
`Sentinel_Starter_Kit/` inside the checkout is covered by `.gitignore`; it is a clone of
someone else's repository and must never be committed into ours.

Everything in `CLAUDE.md` marked "verified" was read from or executed against this clone.
