# OWASP LLM Top 10 Coverage — vulnerable-ai-agent-lab

Mapping van de 4 challenges in dit lab op OWASP LLM Top 10 (v2025).

> **Reading guide:** Symbool-betekenis in de Coverage-kolom.
> - 🟢 **Cijfermatig gedekt** — eigen meetdata (PWNED-tellingen, tabellen).
> - 🟡 **Narratief gedekt** — geraakt in writeup/payloads, geen aparte metric.
> - ⚪ **Niet gedekt** — buiten scope van dit lab (zie 'See instead').

| ID    | Categorie (v2025)                  | Coverage | Bewijs in repo                                                          | See instead                              |
|-------|------------------------------------|:--------:|-------------------------------------------------------------------------|------------------------------------------|
| LLM01 | Prompt Injection                   | 🟢       | Wk1-3 direct (256 attacks), wk4 indirect (96 attacks, in voortgang)     | —                                        |
| LLM02 | Sensitive Information Disclosure   | 🟢       | Wk2 LFI-challenge: `fake-secrets/.env`, `id_rsa`. Wk3 SSRF: IMDS-flag, admin-flag. | —                                |
| LLM03 | Supply Chain                       | ⚪       | Niet aangeraakt — model + tools komen van vertrouwde sources.            | Zou een aparte 'agent-supply-chain' lab vragen (vergiftigde MCP-server / tool-definitie). |
| LLM04 | Data and Model Poisoning           | ⚪       | n.v.t. — geen fine-tuning of RAG-corpus in dit lab.                      | **[rag-poisoning-lab](https://github.com/B2TheEe/rag-poisoning-lab)** (zuster-repo). |
| LLM05 | Improper Output Handling           | 🟡       | Wk4 sanitizer/judge raken dit (tool-output naar conversation).           | Klassiek "output naar SQL/HTML zonder escape" is buiten scope. |
| LLM06 | Excessive Agency                   | 🟢       | **Hoofdvondst wk3** — tool-confusion: model pivot naar `execute_shell` onder `url_allowlist`. Zie [`docs/blog-post-week3-tool-confusion.md`](blog-post-week3-tool-confusion.md). | — |
| LLM07 | System Prompt Leakage              | 🟡       | Geraakt door payloads die proberen system-prompt te exfiltreren (subcategorie 'roleplay'), geen aparte metric. | Aparte challenge mogelijk in week 5+. |
| LLM08 | Vector and Embedding Weaknesses    | ⚪       | n.v.t. — geen embeddings of vectorstore in dit lab.                      | **[rag-poisoning-lab](https://github.com/B2TheEe/rag-poisoning-lab)**. |
| LLM09 | Misinformation                     | ⚪       | n.v.t. — niet het focus-failure-mode van dit lab.                        | Eigen lab (hallucination-detection) mogelijk later. |
| LLM10 | Unbounded Consumption              | 🟡       | `http_fetch` heeft 5s timeout + 8KB response-cap (zie `agent/tools/http_fetch.py`). Geen actieve DoS-testing. | Apart load-test scenario nodig voor cijfers. |

## Hoofdthese die door dit lab cijfermatig hard is gemaakt

**Defense per trust-laag, niet per tool.** Per-tool defenses (LLM06)
voorkomen geen pivots naar onbeschermde tools. Defense-in-depth (`stack`
configuratie) blijft de enige werkende postuur — −85 % → −100 % over
weken 1-3, week 4 nog in voortgang.

Verzameld bewijs:

| Defense          | Wk1 RCE | Wk2 LFI | Wk3 SSRF |
|------------------|:-------:|:-------:|:--------:|
| `none`           |   0 %   |   0 %   |   0 %    |
| `regex`          | −38 %   |   0 %   |  ~0 %    |
| `judge`          | −73 %   | −81 %   | −88 %    |
| `stack`          | −85 %   | −100 %  | −100 %   |

## Wat dit lab **niet** dekt (eerlijk)

LLM03, LLM04, LLM08, LLM09 zijn buiten scope. Voor LLM04 en LLM08 dekt
de zuster-repo [`rag-poisoning-lab`](https://github.com/B2TheEe/rag-poisoning-lab)
het complementaire vlak — indirect prompt injection via gepoisonde
retrieval. Voor LLM03 en LLM09 bestaat nog geen B2TheEe-lab; mogelijke
toekomstige projecten.
