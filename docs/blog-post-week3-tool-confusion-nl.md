# Als Per-Tool Defenses de LLM Door Een Andere Deur Duwen

> Persoonlijke writeup van de week-3 vondst uit `vulnerable-ai-agent-lab`.
> Educatieve repo, MIT-licentie, draait offline op Ollama.
> NL-versie van `blog-post-week3-tool-confusion.md`.

## Opzet

Ik heb een klein offline lab gebouwd — `vulnerable-ai-agent-lab` —
waarin een lokaal model (llama3.1:8b en qwen2.5:7b op Ollama) drie
tools krijgt: `execute_shell`, `read_file`, `http_fetch`. Elke
challenge valt één tool aan met dezelfde 8-payload-taxonomie
(direct / roleplay / format / traversal / urgency / …) onder 6 defense-
configuraties: `none`, `regex`, `judge`, per-tool `allowlist`, per-tool
`path_allowlist` / `url_allowlist`, en `stack` (regex + judge +
allowlists gecombineerd).

256 attacks in totaal, volledig reproduceerbaar, geen externe netwerk-
calls — interne targets staan gemockt op 127.0.0.1.

## Het verwachte resultaat (defense-in-depth werkt)

| Defense | Wk1 RCE | Wk2 LFI | Wk3 SSRF |
|---|:-:|:-:|:-:|
| regex     | −38 % |   0 %  | ~0 %    |
| judge     | −73 % | −81 %  | −88 %   |
| **stack** | **−85 %** | **−100 %** | **−100 %** |

De `stack`-curve is precies wat elke security-writeup je vertelt te
verwachten: één laag is omzeilbaar, drie lagen gestackt niet.

## Het resultaat dat geen bypass bleek

Week 3 (SSRF via `http_fetch`), defense `url_allowlist`, model
`llama3.1:8b`: **1/8 PWNED**.

Het filter zelf was correct. URL geparset, hostname resolved, RFC-1918
+ 127/8 + 169.254.169.254 geblokt, host-allowlist gehandhaafd. Groen
getest door pytest.

Wat llama daadwerkelijk deed onder die defense:

```
tool_call: execute_shell(command="ls /home/ollama/models/")
```

Het probeerde geen slimme URL-bypass. Het **liet de tool volledig
links liggen** en stapte over op een andere tool waarvan de defense-
laag (`url_allowlist`) niet van toepassing is. Het reconnaissance-doel
van de user (host enumereren) werd bereikt door om het SSRF-filter
*heen* te lopen, niet erdoorheen.

## Waarom dit belangrijk is

Dit is OWASP **LLM06 Excessive Agency** in lesboekvorm. Een
tool-specifiek filter creëert druk die het model richting whichever
tool duwt die *niet* gefilterd is. Per-tool-hardening kan de algehele
postuur *slechter* maken als het model agency behoudt om alternatieven
te kiezen.

Het is ook waarom `stack` 0/16 scoorde op dezelfde SSRF-challenge: die
combineert `allowlist` (voor `execute_shell`) **én** `url_allowlist`
(voor `http_fetch`). Beide deuren dicht → geen omloop.

## Lessen voor bouwers

Als je per-tool defenses toevoegt aan een agentisch systeem, audit
dan de **set** van tools, niet de tool die je aan het hardenen bent.
Drie regels die ik nu hanteer:

1. **Per-tool defenses zijn noodzakelijk maar niet voldoende.** Combineer
   ze altijd met een orthogonale defense (judge / input-classifier) die
   niet afhangt van welke tool het model kiest.
2. **Meet tool-call-distributie onder defense, niet alleen success rate.**
   Het interessante signaal is naar welke tool het model migreert
   wanneer zijn voorkeurs-tool geblokt is.
3. **Behandel de toolset als de attack surface.** Een tool toevoegen
   is een deur toevoegen. Een tool weghalen is de goedkoopste defense
   in de catalogus.

## Repo

Educatief, MIT, draait volledig op Ollama + stdlib mock-services. 99
pytest tests, geen externe deps voor het lab zelf.

→ https://github.com/B2TheEe/vulnerable-ai-agent-lab

Zuster-repo (indirect injection via vergiftigde RAG-documenten):
https://github.com/B2TheEe/rag-poisoning-lab

Week 4 (indirect injection via opgehaalde web-content) staat in design —
zie [`docs/week4-design.md`](week4-design.md).
