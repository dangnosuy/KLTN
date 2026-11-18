from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def decode_json_response(raw: str) -> dict:
    try:
        value, _ = json.JSONDecoder().raw_decode(raw.lstrip())
    except json.JSONDecodeError as error:
        raise RuntimeError(f"API returned invalid JSON: {raw[-1000:]}") from error
    if not isinstance(value, dict):
        raise RuntimeError("API returned a non-object JSON response")
    return value


class OpenAICompatibleClient:
    def __init__(
        self,
        model: str,
        base_url: str = "http://127.0.0.1:20128/v1",
        timeout: int = 300,
        max_tokens: int = 16384,
        reasoning_effort: str = "low",
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.reasoning_effort = reasoning_effort

    def _request(self, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
            method="POST" if data is not None else "GET",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return decode_json_response(response.read().decode("utf-8"))
        except HTTPError as error:
            message = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM API HTTP {error.code}: {message[-1000:]}") from error
        except (URLError, TimeoutError) as error:
            raise RuntimeError(f"Cannot reach LLM API at {self.base_url}: {error}") from error

    def doctor(self) -> dict:
        try:
            document = self._request("/models")
            models = [item.get("id") for item in document.get("data", []) if isinstance(item, dict)]
            available = self.model in models
            return {
                "ready": available,
                "base_url": self.base_url,
                "model": self.model,
                "model_available": available,
                "model_count": len(models),
            }
        except Exception as error:
            return {
                "ready": False,
                "base_url": self.base_url,
                "model": self.model,
                "error": str(error),
            }

    def generate(self, system: str, user: str, temperature: float) -> str:
        response = self._request("/chat/completions", {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "temperature": temperature,
            "max_tokens": self.max_tokens,
            "reasoning_effort": self.reasoning_effort,
        })
        if response.get("error"):
            raise RuntimeError(f"LLM API error: {response['error']}")
        choices = response.get("choices")
        content = choices[0].get("message", {}).get("content") if isinstance(choices, list) and choices else None
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("LLM API returned no message content")
        return content
