"""
LLM client — dunne wrapper rond de Ollama Python SDK.

Werkt met zowel oude (<0.4) dict-responses als nieuwe (>=0.4) ChatResponse objects.
"""
from __future__ import annotations

import ollama

DEFAULT_MODEL = "llama3.1:8b"
# DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_TEMPERATURE = 0.7


def _to_dict(obj):
    """Normaliseer Ollama response naar een dict, ongeacht SDK-versie."""
    if isinstance(obj, dict):
        return obj
    # nieuwe SDK: pydantic-achtige objects
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return dict(obj)


class LLMClient:
    def __init__(self, model: str = DEFAULT_MODEL, temperature: float = DEFAULT_TEMPERATURE):
        self.model = model
        self.temperature = temperature
        self.client = ollama.Client()

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Stuur conversatie naar Ollama. Returnt het 'message' dict."""
        response = self.client.chat(
            model=self.model,
            messages=messages,
            tools=tools,
            options={"temperature": self.temperature},
        )
        data = _to_dict(response)
        msg = data.get("message", {})
        return _to_dict(msg)

    def list_local_models(self) -> list[str]:
        data = _to_dict(self.client.list())
        models = data.get("models", [])
        out = []
        for m in models:
            md = _to_dict(m)
            # oude SDK: "name", nieuwe SDK: "model"
            out.append(md.get("name") or md.get("model") or str(md))
        return out


if __name__ == "__main__":
    import traceback
    llm = LLMClient()
    print(f"Model in gebruik   : {llm.model}")
    try:
        print(f"Lokaal beschikbaar : {llm.list_local_models()}")
    except Exception as e:
        print(f"list_local_models() faalde (niet fataal): {e}")
        traceback.print_exc()
    try:
        reply = llm.chat([{"role": "user", "content": "Say 'pong' and nothing else."}])
        print(f"Raw message        : {reply}")
        print(f"Reply.content      : {reply.get('content')!r}")
    except Exception as e:
        print(f"chat() faalde: {e}")
        traceback.print_exc()
