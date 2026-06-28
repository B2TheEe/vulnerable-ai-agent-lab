# Security Policy

## ⚠️ This Repository Is Intentionally Vulnerable

This project ships a **deliberately insecure LLM agent** for security
research, education, and portfolio demonstration. It contains:

- An LLM agent with a `shell` tool that executes arbitrary commands.
- A `read_file` tool with no sandboxing by default.
- Prompt-injection payloads targeting RCE, LFI, and (planned) SSRF.
- Fake "secrets" (clearly marked `FLAG{…}`) used as honeypots for LFI tests.

**Do not** treat unpatched behaviour in `agent/` or `challenges/` as a
vulnerability — that is the point of the lab.

## Safe Usage Rules

1. Run **only on localhost (127.0.0.1)** inside a personal dev machine or VM.
2. **Never** expose the agent to the public internet, a shared LAN, or any
   multi-tenant environment.
3. **Never** point the agent at a real Ollama instance hosting confidential
   model weights or system prompts you do not control.
4. Do **not** populate `challenges/*/fake-secrets/` with real credentials.
   The committed honeypot files contain only `FLAG{…}` markers — keep it
   that way.
5. Do **not** use this code or its techniques against systems, models, or
   services for which you do not have explicit written authorization.

## What Counts as a Real Security Issue

Report these via the channel below:

- Hard-coded real credentials accidentally committed to the repo.
- A defense layer (`agent/defenses.py`) that **claims** to block a class of
  payloads but silently fails to (i.e. a documentation/implementation
  mismatch that would mislead a learner).
- Supply-chain issues in `requirements.txt` (e.g. a typo-squatted package).
- Anything that could harm a user simply by cloning + running `pip install`
  in a clean venv (pre-install hooks, post-install scripts, etc.).

## What Does Not Count

These are **expected behaviour**, not vulnerabilities:

- The agent executes attacker-supplied shell commands under defense `none`.
- `read_file` returns honeypot `.env` contents under defense `none`.
- A new prompt-injection payload bypasses an existing defense — that is
  fresh research; open a PR with the payload + writeup instead.

## Reporting

For real issues (per the list above), open a **private security advisory**
on GitHub: https://github.com/B2TheEe/vulnerable-ai-agent-lab/security/advisories/new

Please do **not** file public issues for credential leaks — use the private
advisory flow so the secret can be rotated before disclosure.

## Scope

| In scope                                  | Out of scope                              |
|-------------------------------------------|-------------------------------------------|
| `agent/`, `tests/`, `requirements.txt`    | Any third-party LLM hosted by Ollama, Hugging Face, etc. |
| Defense logic in `agent/defenses.py`      | The OS or shell the user runs the agent on |
| Honeypot file contents under `challenges/*/fake-secrets/` | Vulnerabilities in Python, Ollama itself, or the underlying model weights |

## Responsible Use

If you publish payloads, blog posts, or videos derived from this lab,
please:

- Cite the repository.
- Make clear that the techniques are demonstrated against a **deliberately
  vulnerable target**.
- Do not republish payloads in a way that targets specific real-world
  products or vendors without their consent.
