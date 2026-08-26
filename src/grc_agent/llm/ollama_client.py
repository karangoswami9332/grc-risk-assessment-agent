"""Minimal Ollama HTTP client using the stdlib. No LangChain or vendor SDKs."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from grc_agent.llm.errors import OllamaResponseError, OllamaUnavailableError

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"
DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text"
CHAT_PATH = "/api/chat"
EMBED_PATH = "/api/embed"
DEFAULT_TIMEOUT_SECONDS = 180


class OllamaChatClient:
    """POST /api/chat with stream=false and a JSON schema ``format``."""

    def __init__(
        self,
        host: str = DEFAULT_OLLAMA_HOST,
        model: str = DEFAULT_OLLAMA_MODEL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        embed_model: str = DEFAULT_OLLAMA_EMBED_MODEL,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.embed_model = embed_model

    @property
    def chat_url(self) -> str:
        return f"{self.host}{CHAT_PATH}"

    @property
    def embed_url(self) -> str:
        return f"{self.host}{EMBED_PATH}"

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise OllamaUnavailableError(f"Ollama HTTP error {exc.code} from {url}") from exc
        except urllib.error.URLError as exc:
            raise OllamaUnavailableError(
                f"Ollama is unavailable at {url}. Is Ollama running? {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise OllamaUnavailableError(f"Ollama request timed out contacting {url}") from exc

        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaResponseError("Ollama returned a non-JSON HTTP body") from exc
        if not isinstance(body, dict):
            raise OllamaResponseError("Ollama JSON body must be an object")
        return body

    def chat(self, messages: list[dict[str, str]], format_schema: dict[str, Any]) -> Any:
        """Return parsed ``message.content`` (object or JSON string)."""
        body = self._post_json(
            self.chat_url,
            {
                "model": self.model,
                "stream": False,
                "format": format_schema,
                "messages": messages,
                "options": {"num_predict": 1024},
            },
        )
        try:
            content = body["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise OllamaResponseError("Ollama response missing message.content") from exc
        return content

    def embed(self, text: str) -> list[float]:
        """POST /api/embed and return the first embedding vector."""
        body = self._post_json(
            self.embed_url,
            {"model": self.embed_model, "input": text},
        )
        vectors = body.get("embeddings")
        if not isinstance(vectors, list) or not vectors:
            raise OllamaResponseError("Ollama embed response missing embeddings")
        vector = vectors[0]
        if not isinstance(vector, list) or not vector:
            raise OllamaResponseError("Ollama embed response contained an empty embedding")
        try:
            return [float(value) for value in vector]
        except (TypeError, ValueError) as exc:
            raise OllamaResponseError("Ollama embedding must be a list of numbers") from exc
