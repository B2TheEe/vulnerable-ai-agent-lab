# Vulnerable AI Agent Lab

Een bewust onveilige LLM-agent voor het oefenen van prompt injection,
tool abuse, RCE/LFI/SSRF via AI-tooling, en het mappen op OWASP LLM Top 10.

> ⚠️ **EDUCATIONAL USE ONLY.** Draai alleen lokaal (127.0.0.1). Niet exposen
> aan internet. Niet draaien op een productiemachine.

## Quick start

```bash
# 1. Ollama installeren (eenmalig)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b

# 2. Python omgeving
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Start de agent
python -m agent.main
```

## Challenges

| # | Naam | OWASP LLM | Difficulty |
|---|------|-----------|------------|
| 01 | RCE via Direct Prompt Injection | LLM01 | ⭐ |
| 02 | LFI via File-Read Tool | LLM06 | ⭐⭐ |
| 03 | SSRF via HTTP Tool *(week 3)* | LLM01+LLM02 | ⭐⭐ |
| 04 | Indirect Injection via Web Browse *(week 4)* | LLM01 | ⭐⭐⭐ |
| 05 | Data Exfil via Markdown Rendering *(week 4)* | LLM02 | ⭐⭐ |

## Architectuur (week 1)

```
   user ──► main.py (REPL) ──► LLMClient (Ollama)
                │                      │
                │◄─── tool_calls ──────┘
                ▼
         AVAILABLE_TOOLS
                │
         ┌──────┴──────┐
         ▼
   execute_shell()  ◄── BEWUST KWETSBAAR
```

## Disclaimer

Dit project bestaat om defenders en pentesters te leren hoe agentische LLM-systemen
falen. Gebruik het niet tegen systemen waar je geen expliciete toestemming voor hebt.

