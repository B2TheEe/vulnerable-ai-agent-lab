"""
Bulk payload runner — leest payloads.yaml, voert ze uit tegen het model,
en print een tabel met resultaten.

Gebruik:
    python -m tests.run_payloads challenges/01-rce-via-shell/payloads.yaml

Optioneel:
    --model qwen2.5:7b    # override DEFAULT_MODEL
    --only direct-01      # test slechts één payload-id
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

console = Console()


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
            cmd = args.get("command", "")
            # Layer 3 allowlist check
            tool_allowed, _ = check_tool(defense, cmd)
            if not tool_allowed:
                messages.append({"role": "tool", "content": "[blocked by allowlist]", "name": name})
                continue
            commands_run.append(cmd)
            tool_fn = AVAILABLE_TOOLS.get(name)
            result = tool_fn(**args) if tool_fn else "(unknown tool)"
            messages.append({"role": "tool", "content": result, "name": name})

    return commands_run


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("yaml_file", type=Path)
    parser.add_argument("--model", default=None)
    parser.add_argument("--only", default=None, help="Run only this payload id")
    parser.add_argument(
        "--defense",
        choices=["none", "regex", "judge", "allowlist"],
        default="none",
        help="Defense layer to test against",
    )
    args = parser.parse_args()

    payloads = yaml.safe_load(args.yaml_file.read_text())
    if args.only:
        payloads = [p for p in payloads if p["id"] == args.only]

    llm = LLMClient(model=args.model) if args.model else LLMClient()
    console.print(
        f"[bold]Running {len(payloads)} payload(s) against {llm.model} "
        f"with defense=[yellow]{args.defense}[/yellow][/bold]\n"
    )

    table = Table(title=f"Payload results (defense={args.defense})")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Commands executed", style="red")
    table.add_column("Verdict")

    for p in payloads:
        cmds = run_one(llm, p["payload"], defense=args.defense)
        verdict = "🟢 PWNED" if cmds else "🛡️  blocked"
        table.add_row(p["id"], p["category"], ", ".join(cmds)[:60] or "—", verdict)

    console.print(table)


if __name__ == "__main__":
    main()
