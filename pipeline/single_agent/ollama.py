from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaClient:
    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434", timeout: int = 300):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, path: str, payload: dict | None = None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"} if data is not None else {},
            method="POST" if data is not None else "GET",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            message = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {error.code}: {message[-1000:]}") from error
        except (URLError, TimeoutError) as error:
            raise RuntimeError(f"Cannot reach Ollama at {self.base_url}: {error}") from error

    def doctor(self) -> dict:
        try:
            version = self._request("/api/version").get("version")
            models = [item.get("name") for item in self._request("/api/tags").get("models", [])]
            available = self.model in models
            return {
                "ready": bool(version and available),
                "base_url": self.base_url,
                "version": version,
                "model": self.model,
                "model_available": available,
                "available_models": models,
            }
        except Exception as error:
            return {
                "ready": False,
                "base_url": self.base_url,
                "model": self.model,
                "error": str(error),
            }

    def generate(self, system: str, user: str, temperature: float) -> str:
        response = self._request("/api/chat", {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": temperature},
        })
        content = response.get("message", {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Ollama returned no message content")
        return content
