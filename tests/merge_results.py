"""
Merge results-*.txt (rich tables) terug naar payloads.yaml.

Parsed elke "═══ DEFENSE: X ═══" sectie en zet per payload-id het verdict
in models[<model>][<defense>] = pwned | blocked.

Gebruik:
    python -m tests.merge_results \\
        --results results-llama3.1.txt \\
        --yaml challenges/01-rce-via-shell/payloads.yaml \\
        --model llama3.1:8b

Gebruikt ruamel.yaml zodat comments en multiline-strings in payloads.yaml
behouden blijven.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from ruamel.yaml import YAML

DEFENSE_HEADER = re.compile(r"═══ DEFENSE: (\w+) ═══")
# Match table rows zoals:  │ override-01  │ direct   │ ... │ 🟢 PWNED    │
ROW_RE = re.compile(r"^│\s*([a-z]+-\d+)\s*│.*│\s*(🟢 PWNED|🛡️\s*blocked)\s*│")


def parse_results(text: str) -> dict[str, dict[str, str]]:
    """Return {payload_id: {defense: verdict}}."""
    out: dict[str, dict[str, str]] = {}
    current_defense: str | None = None
    for line in text.splitlines():
        m = DEFENSE_HEADER.search(line)
        if m:
            current_defense = m.group(1)
            continue
        m = ROW_RE.match(line)
        if m and current_defense:
            pid, verdict = m.group(1), m.group(2)
            verdict_clean = "pwned" if "PWNED" in verdict else "blocked"
            out.setdefault(pid, {})[current_defense] = verdict_clean
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--yaml", type=Path, required=True)
    ap.add_argument("--model", required=True, help="e.g. llama3.1:8b")
    args = ap.parse_args()

    results = parse_results(args.results.read_text())
    if not results:
        print("⚠️  Geen rijen geparsed. Klopt het result-bestand?")
        return

    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=2, offset=0)
    data = yaml.load(args.yaml)

    updated, missing = 0, []
    for entry in data:
        pid = entry.get("id")
        if pid not in results:
            missing.append(pid)
            continue
        entry.setdefault("models", {})
        if entry["models"] is None:
            entry["models"] = {}
        entry["models"][args.model] = dict(sorted(results[pid].items()))
        updated += 1

    yaml.dump(data, args.yaml)

    print(f"✅  Updated {updated} entries in {args.yaml}")
    print(f"   Model:    {args.model}")
    print(f"   Defenses: {sorted({d for v in results.values() for d in v})}")
    if missing:
        print(f"⚠️  No results for: {missing}")
    extras = set(results) - {e['id'] for e in data}
    if extras:
        print(f"⚠️  Results without yaml entry: {sorted(extras)}")


if __name__ == "__main__":
    main()
