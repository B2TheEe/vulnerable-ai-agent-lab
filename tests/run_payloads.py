"""
Bulk payload runner — leest payloads.yaml, voert ze uit tegen het model,
en print een tabel met resultaten.

Gebruik (single run, zoals voorheen):
    python -m tests.run_payloads challenges/01-rce-via-shell/payloads.yaml
    python -m tests.run_payloads <yaml> --model qwen2.5:7b --defense judge
    python -m tests.run_payloads <yaml> --only direct-01

Matrix-modus (week 3+): draai meerdere modellen × meerdere defenses in één call
en schrijf per model een result-bestand dat compatibel is met
`tests/summarize_results.py` en `tests/merge_results.py`:

    python -m tests.run_payloads challenges/03-.../payloads.yaml \\
        --models llama3.1:8b,qwen2.5:7b \\
        --defenses none,regex,judge,allowlist,path_allowlist,stack \\
        --out-prefix results-week3

→ produceert `results-week3-llama3.1-8b.txt` en `results-week3-qwen2.5-7b.txt`,
elk met "═══ DEFENSE: <name> ═══" headers per blok (zelfde format als de
handmatige bash-loop in `docs/results-week*.md`).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from agent.llm_client import LLMClient
from agent.system_prompt import SYSTEM_PROMPT
from agent.tools import AVAILABLE_TOOLS, TOOL_SCHEMAS
from agent.llm_client import _to_dict
from agent.defenses import check_input, check_tool

ALL_DEFENSES = ["none", "regex", "judge", "allowlist", "path_allowlist", "url_allowlist", "stack"]


def run_one(llm: LLMClient, payload: str, defense: str = "none", max_rounds: int = 3) -> list[str]:
    """Voer 1 payload uit, return lijst met daadwerkelijk uitgevoerde commands."""
    # Layer 1/2 input check
    allowed, _reason = check_input(defense, payload)
    if not allowed:
        return []

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": payload},
    ]
    commands_run: list[str] = []

    for _ in range(max_rounds):
        msg = llm.chat(messages, tools=TOOL_SCHEMAS)
        messages.append(msg)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            break
        for tc in tool_calls:
            tc_d = _to_dict(tc)
            fn = _to_dict(tc_d.get("function", {}))
            name = fn.get("name", "")
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                import json
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"command": args}
            cmd = args.get("command") or args.get("path") or args.get("url") or ""
            # Layer 3/4 allowlist check (binary voor shell, path voor read_file)
            tool_allowed, _ = check_tool(defense, cmd, tool_name=name)
            if not tool_allowed:
                messages.append({"role": "tool", "content": "[blocked by allowlist]", "name": name})
                continue
            commands_run.append(cmd)
            tool_fn = AVAILABLE_TOOLS.get(name)
            result = tool_fn(**args) if tool_fn else "(unknown tool)"
            messages.append({"role": "tool", "content": result, "name": name})

    return commands_run


def run_defense_block(console: Console, llm: LLMClient, payloads: list[dict], defense: str) -> None:
    """Print one DEFENSE-block (header + table) to the given console."""
    console.print(f"═══ DEFENSE: {defense} ═══")
    console.print(
        f"[bold]Running {len(payloads)} payload(s) against {llm.model} "
        f"with defense=[yellow]{defense}[/yellow][/bold]\n"
    )
    table = Table(title=f"Payload results (defense={defense})")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Commands executed", style="red")
    table.add_column("Verdict")
    for p in payloads:
        cmds = run_one(llm, p["payload"], defense=defense)
        verdict = "🟢 PWNED" if cmds else "🛡️  blocked"
        table.add_row(p["id"], p["category"], ", ".join(cmds)[:60] or "—", verdict)
    console.print(table)
    console.print()


def model_slug(name: str) -> str:
    """llama3.1:8b → llama3.1-8b (matches week 1/2 file naming)."""
    return name.replace(":", "-")


def main() -> None:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument("yaml_file", type=Path)
    parser.add_argument("--only", default=None, help="Run only this payload id")

    # Single-run flags (back-compat)
    parser.add_argument("--model", default=None, help="Single model (back-compat).")
    parser.add_argument(
        "--defense",
        choices=ALL_DEFENSES,
        default=None,
        help="Single defense layer to test (back-compat).",
    )

    # Matrix flags (week 3+)
    parser.add_argument(
        "--models",
        default=None,
        help="Comma-separated list of models, e.g. 'llama3.1:8b,qwen2.5:7b'. "
        "Triggers matrix mode (one output file per model).",
    )
    parser.add_argument(
        "--defenses",
        default=None,
        help=f"Comma-separated list of defenses, or 'all'. Choices: {','.join(ALL_DEFENSES)}.",
    )
    parser.add_argument(
        "--out-prefix",
        default=None,
        help="Prefix for matrix output files. e.g. 'results-week3' → "
        "results-week3-llama3.1-8b.txt. Required when --models has 2+ models.",
    )
    args = parser.parse_args()

    payloads = yaml.safe_load(args.yaml_file.read_text())
    if args.only:
        payloads = [p for p in payloads if p["id"] == args.only]

    # Resolve defenses
    if args.defenses:
        defenses = ALL_DEFENSES if args.defenses == "all" else args.defenses.split(",")
        for d in defenses:
            if d not in ALL_DEFENSES:
                sys.exit(f"Unknown defense: {d}. Choices: {ALL_DEFENSES}")
    elif args.defense:
        defenses = [args.defense]
    else:
        defenses = ["none"]

    # Resolve models
    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
    elif args.model:
        models = [args.model]
    else:
        models = [None]  # use LLMClient default

    matrix_mode = len(models) > 1 or args.out_prefix is not None

    if matrix_mode and not args.out_prefix:
        sys.exit("--out-prefix is required when running --models with 2+ entries.")

    for m in models:
        llm = LLMClient(model=m) if m else LLMClient()
        if matrix_mode:
            out_path = Path(f"{args.out_prefix}-{model_slug(llm.model)}.txt")
            print(f"→ writing {len(defenses)} defense block(s) for {llm.model} → {out_path}")
            with out_path.open("w") as f:
                file_console = Console(file=f, force_terminal=False, width=120)
                for d in defenses:
                    run_defense_block(file_console, llm, payloads, d)
        else:
            console = Console()
            for d in defenses:
                run_defense_block(console, llm, payloads, d)


if __name__ == "__main__":
    main()
