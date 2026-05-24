"""
REPL entry point. Run met:  python -m agent.main
Disclaimer: alleen lokaal draaien. Niet exposen.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from agent.llm_client import LLMClient, _to_dict
from agent.system_prompt import SYSTEM_PROMPT
from agent.tools import AVAILABLE_TOOLS, TOOL_SCHEMAS

console = Console()


def run_tool_call(tool_call) -> dict:
    tc = _to_dict(tool_call)
    fn_block = _to_dict(tc.get("function", {}))
    name = fn_block.get("name", "")
    args = fn_block.get("arguments", {}) or {}
    if isinstance(args, str):
        # sommige modellen returnen arguments als JSON string
        import json
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"command": args}

    console.print(Panel.fit(
        f"[yellow]tool:[/yellow] {name}\n[yellow]args:[/yellow] {args}",
        title="🔧 Tool call", border_style="yellow",
    ))

    fn = AVAILABLE_TOOLS.get(name)
    if fn is None:
        result = f"(unknown tool: {name})"
    else:
        try:
            result = fn(**args)
        except Exception as exc:  # noqa: BLE001
            result = f"(tool error: {exc})"

    console.print(Panel(result, title="📤 Tool result", border_style="green"))
    return {"role": "tool", "content": result, "name": name}


def main() -> None:
    console.print(Panel.fit(
        "[bold red]Vulnerable AI Agent Lab[/bold red]\n"
        "Educational use only. Run lokaal — niet exposen.\n"
        "Type [cyan]/quit[/cyan] om te stoppen, [cyan]/reset[/cyan] voor nieuwe sessie.",
        border_style="red",
    ))

    llm = LLMClient()
    messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]you[/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            console.print("\nbye!")
            break

        cmd = user_input.strip()
        if cmd == "/quit":
            break
        if cmd == "/reset":
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            console.print("[dim]history reset[/dim]")
            continue
        if not cmd:
            continue

        messages.append({"role": "user", "content": user_input})

        for _ in range(5):  # max 5 tool-rondes per user turn
            msg = llm.chat(messages, tools=TOOL_SCHEMAS)
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                console.print(Panel(
                    msg.get("content", "") or "(empty)",
                    title="🤖 assistant", border_style="blue",
                ))
                break

            for tc in tool_calls:
                messages.append(run_tool_call(tc))
        else:
            console.print("[red]Max tool-rondes bereikt.[/red]")


if __name__ == "__main__":
    main()
