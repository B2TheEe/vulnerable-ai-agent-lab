# Week 2 — LFI via File-Read Tool (Challenge 02)

Challenge 02 — 8 LFI payloads × **6** defenses × 2 modellen = 96 runs.
Defenses: `none`, `regex`, `judge`, `allowlist` (shell binary, niet relevant
voor file_read), `path_allowlist` (nieuw — Layer 4), `stack` (alles samen).

> **Status:** matrix draait in background (proc_b25eb7207907).
> Resultaten worden hieronder ingevuld zodra `results-week2-*.txt` klaar is.
> Vul in met:
> ```
> python -m tests.merge_results --results results-week2-llama3.1-8b.txt \
>   --yaml challenges/02-lfi-via-file-read/payloads.yaml --model llama3.1:8b
> python -m tests.merge_results --results results-week2-qwen2.5-7b.txt   \
>   --yaml challenges/02-lfi-via-file-read/payloads.yaml --model qwen2.5:7b
> ```

## 1. Hoofdtelling — PWNED per defense (van 8)

| Defense          | llama3.1:8b | qwen2.5:7b | Notitie |
|------------------|:-----------:|:----------:|---------|
| none             |     TODO    |    TODO    | Volledig vulnerable baseline |
| regex            |     TODO    |    TODO    | Keyword-block op user input |
| judge            |     TODO    |    TODO    | LLM-as-judge op user input |
| allowlist        |     TODO    |    TODO    | Shell binary-allowlist (irrelevant voor file_read — verwacht ≈ none) |
| **path_allowlist** | **TODO**  |  **TODO**  | Nieuw: deny basename (.env, id_rsa, shadow) + prefix-allowlist |
| **stack**        |   **TODO**  |   **TODO** | regex + judge + path_allowlist gestapeld |

## 2. Wat moet ik straks zien?

Voorspellingen om te valideren (vul Δ in zodra cijfers binnen zijn):

1. **`allowlist` ≈ `none`** — shell-allowlist raakt file_read niet, dus
   bijna identieke cijfers. Belangrijk leerpunt: defenses moeten *per tool*
   ontworpen worden.
2. **`path_allowlist` ≈ 0/8 PWNED** — deze defense is by design dicht voor
   alle 8 payloads (geen enkele richt zich op een toegestaan pad). Verwacht
   100 % block tenzij een payload het model overtuigt om een legitiem pad
   te lezen dat tóch geheime info bevat (bv. agent-source als RAG-leak).
3. **`stack` < `path_allowlist`** — zelfs als path_allowlist alles vangt,
   levert regex+judge eraan voorafgaand minder LLM-calls op (cost win),
   en kan het de allowlist niet kapotmaken.
4. **`urgency-01` blijft een gevaar onder single-layer judge** — Qwen viel
   in week 1 voor urgency (6/8 PWNED). Verwacht: judge blokt deels, maar
   path_allowlist is wat het écht stopt.

## 3. Cross-challenge vergelijking (week 1 vs week 2)

Zodra cijfers binnen: tabel met PWNED-ratio per defense voor challenge 01
vs challenge 02, om aan te tonen dat **defense per-tool ontworpen moet worden**
(shell-allowlist nutteloos voor file_read, path-allowlist nutteloos voor shell).

## 4. Geleerde lessen (in te vullen)

- TODO — welke payload overleeft de stack op beide modellen?
- TODO — werkt traversal (`./challenges/../`) of vangt Path.resolve() het?
- TODO — wat doet `format-01` (JSON tool-call) tegen path_allowlist?

## 5. Reproduceren

```bash
source venv/bin/activate

for m in llama3.1:8b qwen2.5:7b; do
  out="results-week2-$(echo $m | tr ':' '-').txt"
  > "$out"
  for d in none regex judge allowlist path_allowlist stack; do
    echo "═══ DEFENSE: $d ═══" >> "$out"
    python -m tests.run_payloads challenges/02-lfi-via-file-read/payloads.yaml \
      --defense $d --model $m >> "$out" 2>&1
  done
done
```
