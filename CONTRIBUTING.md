# Contributing

Thanks for your interest in this lab. It is primarily a personal
portfolio + teaching project, but contributions that fit the scope are
welcome.

## What Fits the Scope

✅ **Good contributions:**

- New prompt-injection payloads for existing challenges, with a verdict
  table (`PWNED` / `blocked`) per defense × model.
- New defense layers (e.g. semantic similarity check, output filter,
  per-tool scoped allowlists), with cross-challenge measurements.
- A new challenge that maps cleanly onto an OWASP LLM Top 10 entry not yet
  covered (LLM03 training-data poisoning is intentionally out of scope —
  it requires model retraining, not agent attack).
- Bug fixes in `tests/` (runner, merger, summarizer) — the test harness
  must stay reproducible.
- Documentation improvements: clearer writeups, cross-references, better
  diagrams.

🚫 **Out of scope:**

- "Make the agent secure by default." It is **deliberately** vulnerable —
  defenses are opt-in via the `--defense` flag for measurement purposes.
- New tools that are not vulnerable in an instructive way (e.g. a
  well-sandboxed `calculator` tool adds nothing).
- Real exploits targeting specific commercial LLM products or services.
- Anything that requires network egress beyond `localhost` Ollama.

## Workflow

1. Open an issue first if your change touches `agent/defenses.py` or adds
   a new challenge directory — let's align on the design before you spend
   time on it.
2. Fork → branch → PR against `main`. Branch names: `feat/<short>`,
   `fix/<short>`, `docs/<short>`, `challenge/<NN-name>`.
3. Keep commits scoped. The convention used in this repo:
   `feat(area): short description`, `docs(week2): …`, `fix(runner): …`.

## Adding a New Payload

1. Edit the appropriate `challenges/<NN-…>/payloads.yaml`.
2. Use an `id` that follows the existing pattern: `<subcategory>-<NN>`
   (e.g. `urgency-03`, `format-04`).
3. Set all `models[*][defense]` entries to `TODO`.
4. Run the matrix:
   ```bash
   python -m tests.run_payloads challenges/<NN-…>/payloads.yaml \
     --models llama3.1:8b,qwen2.5:7b --defenses all --out-prefix results-weekN
   ```
5. Merge the verdicts back:
   ```bash
   python -m tests.merge_results --results results-weekN-llama3.1-8b.txt \
     --yaml challenges/<NN-…>/payloads.yaml --model llama3.1:8b
   python -m tests.merge_results --results results-weekN-qwen2.5-7b.txt \
     --yaml challenges/<NN-…>/payloads.yaml --model qwen2.5:7b
   ```
6. Summarise:
   ```bash
   python -m tests.summarize_results results-weekN-*.txt
   ```
7. Paste the matrix into the relevant `docs/results-weekN.md`.

## Adding a New Defense

1. Implement it in `agent/defenses.py` as a new branch in `check_input`
   (Layer 1/2) or `check_tool` (Layer 3+).
2. Add the defense name to `ALL_DEFENSES` in `tests/run_payloads.py` and
   to the `--defense` choices.
3. Update `agent/defenses.py` `stack` to compose it where appropriate.
4. Re-run the matrix on **every existing challenge** and add the column
   to the relevant `docs/results-week*.md` files. A new defense must be
   measured cross-challenge or it tells you nothing about its scope.

## Code Style

- Python 3.12, type hints where they aid clarity.
- `rich` for terminal output, never bare `print` for tables.
- No external network calls beyond `http://127.0.0.1:11434` (Ollama).
- Honeypot files (`challenges/*/fake-secrets/*`) must contain only
  `FLAG{…}` markers. See [SECURITY.md](SECURITY.md).

## Local Smoke Test Before PR

```bash
source venv/bin/activate
python -m tests.run_payloads challenges/01-rce-via-shell/payloads.yaml \
  --defense none --only direct-01
# Should produce a 1-row table, no crashes.
```

## License

By contributing you agree your changes are released under the same MIT
license as the rest of the repository.
