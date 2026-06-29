# Vulnerable AI Agent Lab

![Python](https://img.shields.io/badge/python-3.12-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-llama3.1%20%7C%20qwen2.5-black)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red)
![Status](https://img.shields.io/badge/status-week%203%20complete-brightgreen)
![Educational](https://img.shields.io/badge/use-educational%20only-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Een bewust onveilige LLM-agent voor het oefenen van prompt injection,
tool abuse, RCE/LFI/SSRF via AI-tooling, en het mappen op OWASP LLM Top 10.

> ⚠️ **EDUCATIONAL USE ONLY.** Draai alleen lokaal (127.0.0.1). Niet exposen
> aan internet. Niet draaien op een productiemachine. Zie [SECURITY.md](SECURITY.md).

> 🔗 **Sister lab:** [rag-poisoning-lab](https://github.com/B2TheEe/rag-poisoning-lab)
> covers the *indirect* variant (prompt injection via poisoned documents in a
> RAG vectorstore). This repo covers the *direct* variant.

## Status

| Week | Challenge                          | OWASP LLM   | Modellen testen        | Stack-blockrate (beste defense)        | Writeup                          |
|------|------------------------------------|-------------|------------------------|-----------------------------------------|----------------------------------|
| 1    | RCE via Direct Prompt Injection    | LLM01       | llama3.1:8b, qwen2.5:7b | **−85 %** (2/30 PWNED met regex+judge+allowlist) | [docs/results-week1.md](docs/results-week1.md) |
| 2    | LFI via File-Read Tool             | LLM06       | llama3.1:8b, qwen2.5:7b | **−100 %** (0/16 PWNED met regex+judge+path_allowlist) | [docs/results-week2.md](docs/results-week2.md) |
| 3    | SSRF via HTTP-Fetch Tool           | LLM01+LLM02 | llama3.1:8b, qwen2.5:7b | **−100 %** (0/16 PWNED met regex+judge+url_allowlist) | [docs/results-week3.md](docs/results-week3.md) |
| 4    | Indirect Injection via Web Browse  | LLM01       | —                       | —                                       | —                                |

**Hoofdinsight week 1→2→3:** dezelfde `allowlist`-defense gaat van −50 %
reductie (week 1, shell-tool) naar **0 % reductie** (week 2 file_read, week 3 http_fetch)
puur door wisseling van tool-context. Drie keer cijfermatig bevestigd:
defenses moeten **per-tool** ontworpen worden, niet per-app. Bonus week 3:
**tool-confusion** — een tool-passende defense zonder dekking op de andere
tools duwt het model gewoon naar een onverdedigde tool ([docs/results-week3.md §2](docs/results-week3.md)).

## Quick start

```bash
# 1. Ollama installeren (eenmalig)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
ollama pull qwen2.5:7b   # voor cross-model vergelijking

# 2. Python omgeving
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Interactieve REPL
python -m agent.main

# 4. Hele payload-matrix in één commando (week 3+):
python -m tests.run_payloads challenges/02-lfi-via-file-read/payloads.yaml \
  --models llama3.1:8b,qwen2.5:7b \
  --defenses all \
  --out-prefix results-week2
python -m tests.summarize_results results-week2-*.txt
```

## Challenges

| # | Naam | OWASP LLM | Difficulty | Status |
|---|------|-----------|------------|--------|
| 01 | RCE via Direct Prompt Injection | LLM01 | ⭐ | ✅ klaar |
| 02 | LFI via File-Read Tool | LLM06 | ⭐⭐ | ✅ klaar |
| 03 | SSRF via HTTP-Fetch Tool | LLM01+LLM02 | ⭐⭐ | ✅ klaar |
| 04 | Indirect Injection via Web Browse *(week 4)* | LLM01 | ⭐⭐⭐ | ⏳ gepland |
| 05 | Data Exfil via Markdown Rendering *(week 4)* | LLM02 | ⭐⭐ | ⏳ gepland |

## Defense Layers

| Layer | Naam            | Werkt op           | Geïntroduceerd |
|-------|-----------------|--------------------|----------------|
| 1     | `regex`         | user input         | week 1         |
| 2     | `judge`         | user input (LLM)   | week 1         |
| 3     | `allowlist`     | shell binary       | week 1         |
| 4     | `path_allowlist`| file_read path     | week 2         |
| 5     | `url_allowlist` | http_fetch URL     | week 3         |
| stack | alles samen     | input + tool       | week 1 (uitgebreid wk2+wk3) |

## Architectuur

```
   user ──► main.py (REPL) ──► LLMClient (Ollama)
                │                      │
                │◄─── tool_calls ──────┘
                ▼
         AVAILABLE_TOOLS
                │
         ┌──────┼─────────┐
         ▼      ▼         ▼
   execute_shell  read_file   (week 3: http_fetch)
         ▲           ▲
         │           │
   defenses: regex (L1) → judge (L2) → allowlist (L3) → path_allowlist (L4)
```

## Repo layout

```
agent/                  # LLM-client, tools, defenses, REPL
challenges/             # per challenge: README + payloads.yaml
  01-rce-via-shell/
  02-lfi-via-file-read/
tests/
  run_payloads.py       # bulk runner (single + matrix mode)
  merge_results.py      # txt → yaml verdicts terug-merge
  summarize_results.py  # PWNED-matrix print
docs/                   # weekly writeups + cross-challenge analyse
```

## Writeups

- [`docs/owasp-coverage.md`](docs/owasp-coverage.md) — OWASP LLM Top 10 (v2025)
  coverage-tabel per challenge, met cross-lab kompas naar zuster-repo.
- [`docs/blog-post-week3-tool-confusion.md`](docs/blog-post-week3-tool-confusion.md) —
  the week-3 tool-confusion finding (`url_allowlist` did not bypass; the model
  pivoted to `execute_shell`). English, ~450 words.
- [`docs/blog-post-week3-tool-confusion-nl.md`](docs/blog-post-week3-tool-confusion-nl.md) —
  Nederlandse versie van bovenstaand.

## Disclaimer

Dit project bestaat om defenders en pentesters te leren hoe agentische LLM-systemen
falen. Gebruik het niet tegen systemen waar je geen expliciete toestemming voor hebt.
