"""Errors from the local Ollama HTTP API. No cloud providers."""


class OllamaError(Exception):
    """Base error for local Ollama calls."""


class OllamaUnavailableError(OllamaError):
    """Ollama did not respond (not running, network error, HTTP error, timeout)."""


class OllamaResponseError(OllamaError):
    """Ollama responded, but the body was not valid RiskProposal JSON."""
