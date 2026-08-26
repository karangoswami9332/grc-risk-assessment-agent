"""Local Ollama package. HTTP only; scoring stays in RiskEngine."""

from grc_agent.llm.errors import OllamaError, OllamaResponseError, OllamaUnavailableError
from grc_agent.llm.ollama_client import OllamaChatClient

__all__ = [
    "OllamaChatClient",
    "OllamaError",
    "OllamaResponseError",
    "OllamaUnavailableError",
]
