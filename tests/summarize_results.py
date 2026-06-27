"""
Snelle samenvatting van een week-2 result-bestand.

Telt PWNED/blocked per defense en print een kant-en-klare Markdown-tabel
die je in docs/results-week2.md kunt plakken.

Gebruik:
    python -m tests.summarize_results results-week2-llama3.1-8b.txt results-week2-qwen2.5-7b.txt
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

DEFENSE_HEADER = re.compile(r"═══ DEFENSE: (\w+) ═══")
ROW_RE = re.compile(r"^│\s*([a-z]+-\d+)\s*│.*│\s*(🟢 PWNED|🛡️\s*blocked)\s*│")


def count(text: str) -> dict[str, tuple[int, int]]:
    """Return {defense: (pwned, blocked)}."""
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"pwned": 0, "blocked": 0})
    current: str | None = None
    for line in text.splitlines():
        m = DEFENSE_HEADER.search(line)
        if m:
            current = m.group(1)
            continue
        m = ROW_RE.match(line)
        if m and current:
            verdict = "pwned" if "PWNED" in m.group(2) else "blocked"
            stats[current][verdict] += 1
    return {k: (v["pwned"], v["blocked"]) for k, v in stats.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args()

    per_file = {}
    all_defenses: list[str] = []
    for f in args.files:
        per_file[f.name] = count(f.read_text())
        for d in per_file[f.name]:
            if d not in all_defenses:
                all_defenses.append(d)

    print(f"\n| Defense | " + " | ".join(f.name for f in args.files) + " |")
    print("|" + "---|" * (len(args.files) + 1))
    for d in all_defenses:
        cells = []
        for f in args.files:
            p, b = per_file[f.name].get(d, (0, 0))
            cells.append(f"{p}/{p + b}")
        print(f"| {d} | " + " | ".join(cells) + " |")
    print()


if __name__ == "__main__":
    main()
