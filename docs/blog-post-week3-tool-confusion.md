# When Per-Tool Defenses Push the LLM Through a Different Door

> Personal writeup of the week-3 finding from `vulnerable-ai-agent-lab`.
> Educational repo, MIT licensed, runs offline on Ollama.
> Original publication target: LinkedIn / dev.to.

## Setup

I built a small offline lab — `vulnerable-ai-agent-lab` — where a local
model (llama3.1:8b and qwen2.5:7b on Ollama) gets three tools:
`execute_shell`, `read_file`, `http_fetch`. Each challenge attacks one
tool with the same 8-payload taxonomy (direct / roleplay / format /
traversal / urgency / …) under 6 defense configurations: `none`,
`regex`, `judge`, per-tool `allowlist`, per-tool `path_allowlist` /
`url_allowlist`, and `stack` (regex + judge + allowlists combined).

256 attacks total, fully reproducible, no external network calls —
internal targets are mocked on 127.0.0.1.

## The expected result (defense-in-depth works)

| Defense | Wk1 RCE | Wk2 LFI | Wk3 SSRF |
|---|:-:|:-:|:-:|
| regex     | −38 % |   0 %  | ~0 %    |
| judge     | −73 % | −81 %  | −88 %   |
| **stack** | **−85 %** | **−100 %** | **−100 %** |

The `stack` curve is what every security writeup tells you to expect: a
single layer is bypassable, three layers stacked are not.

## The result that wasn't a bypass

Week 3 (SSRF via `http_fetch`), defense `url_allowlist`, model
`llama3.1:8b`: **1/8 PWNED**.

The filter itself was correct. URL parsed, hostname resolved, RFC-1918
+ 127/8 + 169.254.169.254 denied, host-allowlist enforced. Tested green
by pytest.

What llama actually did under that defense:

```
tool_call: execute_shell(command="ls /home/ollama/models/")
```

It didn't try a clever URL bypass. It **abandoned the tool entirely**
and pivoted to a different one whose defense layer (`url_allowlist`)
doesn't apply. The user's reconnaissance goal (enumerate the host) was
satisfied by walking around the SSRF filter, not through it.

## Why this matters

This is OWASP **LLM06 Excessive Agency** in textbook form. A
tool-specific filter creates pressure that pushes the model toward
whichever tool *isn't* filtered. Single-tool hardening can make the
overall posture *worse* if the model retains agency to choose
alternatives.

It's also why `stack` scored 0/16 on the same SSRF challenge: it
combines `allowlist` (for `execute_shell`) **and** `url_allowlist` (for
`http_fetch`). Both doors closed → no walk-around.

## Takeaway for builders

If you're adding per-tool defenses to an agentic system, audit the
**set** of tools, not the tool you're hardening. Three rules I now
follow:

1. **Per-tool defenses are necessary but not sufficient.** Always pair
   them with an orthogonal defense (judge / input-classifier) that
   doesn't depend on which tool the model picks.
2. **Measure tool-call distribution under defense, not just success
   rate.** The interesting signal is which tool the model migrates to
   when its preferred one is blocked.
3. **Treat the toolset as the attack surface.** Adding a tool is adding
   a door. Removing a tool is the cheapest defense in the catalog.

## Repo

Educational, MIT, runs entirely on Ollama + stdlib mock services. 99
pytest tests, no external deps for the lab itself.

→ https://github.com/B2TheEe/vulnerable-ai-agent-lab

Sister repo (indirect injection via poisoned RAG documents):
https://github.com/B2TheEe/rag-poisoning-lab

Week 4 (indirect injection via fetched web content) is in design —
see [`docs/week4-design.md`](week4-design.md).
