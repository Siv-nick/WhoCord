"""
web_services/llm_models.py
--------------------------
Fetch the model list for whichever LLM provider is active.

Change log
----------
- Phase 4: added a third provider, ``"ollama"``, that reads the local
  Ollama server's ``/api/tags`` endpoint. Ollama returns its own shape
  (``{"models": [{"name": "llama3.2:latest", ...}]}``) which this
  module translates to the OpenAI-compatible ``{"data": [{"id": ...}]}``
  form so the rest of the codebase does not need to care.
- Phase 5: added a 5-minute TTL cache keyed by (provider, api_key).
"""

from __future__ import annotations

import time
from typing import Any, Optional


_GROQ_FALLBACK_MODELS = [
    {"id": "llama-3.1-8b-instant",                             "owned_by": "groq", "free": True},
    {"id": "llama-3.3-70b-versatile",                          "owned_by": "groq", "free": True},
    {"id": "meta-llama/llama-4-maverick-17b-128e-instruct",    "owned_by": "groq", "free": True},
    {"id": "meta-llama/llama-4-scout-17b-16e-instruct",        "owned_by": "groq", "free": True},
    {"id": "openai/gpt-oss-120b",                              "owned_by": "groq", "free": True},
    {"id": "openai/gpt-oss-20b",                               "owned_by": "groq", "free": True},
    {"id": "qwen/qwen3-32b",                                   "owned_by": "groq", "free": True},
    {"id": "moonshotai/kimi-k2-instruct",                      "owned_by": "groq", "free": True},
    {"id": "gemma2-9b-it",                                     "owned_by": "groq", "free": True},
    {"id": "groq/compound",                                    "owned_by": "groq", "free": True},
    {"id": "groq/compound-mini",                               "owned_by": "groq", "free": True},
]

_OPENROUTER_FALLBACK_MODELS = [
    {"id": "deepseek/deepseek-chat-v3.1:free",              "owned_by": "deepseek", "free": True},
    {"id": "deepseek/deepseek-r1:free",                     "owned_by": "deepseek", "free": True},
    {"id": "google/gemini-2.0-flash-exp:free",              "owned_by": "google",   "free": True},
    {"id": "qwen/qwen3-coder:free",                         "owned_by": "qwen",     "free": True},
    {"id": "meta-llama/llama-3.3-70b-instruct:free",        "owned_by": "meta",     "free": True},
    {"id": "mistralai/mistral-7b-instruct:free",            "owned_by": "mistral",  "free": True},
]

# Ollama has no fallback — models are local and must be pulled by the
# operator. An empty list is the correct answer when the daemon is not
# reachable.
_OLLAMA_FALLBACK_MODELS: list[dict] = []

_OPENROUTER_CURATED_PAID = {
    "openai/gpt-4o-mini",
    "openai/gpt-4o",
    "anthropic/claude-3.5-sonnet",
    "google/gemini-2.0-flash-001",
    "deepseek/deepseek-chat",
}

_OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"


_MODELS_TTL_SECONDS = 300
_models_cache: dict[tuple, tuple[float, dict]] = {}


def reset_cache() -> None:
    """Clear the model-list cache. For tests and explicit refreshes."""
    _models_cache.clear()


def _cache_key(config_service: Any) -> tuple:
    provider = config_service.llm_provider
    if provider == "openrouter":
        key = getattr(config_service, "openrouter_api_key", "") or ""
    elif provider == "ollama":
        # No key for a local server. The base URL is fixed, so no need
        # to include it — the "ollama" provider string is the whole key.
        key = ""
    else:
        key = getattr(config_service, "groq_api_key", "") or ""
    return (provider, key)


def fetch_models_for_provider(config_service: Any) -> dict:
    """
    Return ``{"models": [...], "source": "live"|"fallback", "reason"?: str}``.

    Result is cached for 5 minutes per (provider, api_key) pair.
    """
    key = _cache_key(config_service)
    now = time.time()

    cached = _models_cache.get(key)
    if cached is not None:
        ts, data = cached
        if now - ts < _MODELS_TTL_SECONDS:
            return data

    result = _fetch_fresh(config_service)
    _models_cache[key] = (now, result)
    return result


def _fetch_fresh(config_service: Any) -> dict:
    import requests as _req

    provider = config_service.llm_provider

    if provider == "openrouter":
        return _fetch_openrouter(config_service, _req)
    if provider == "ollama":
        return _fetch_ollama(_req)
    return _fetch_groq(config_service, _req)


def _fetch_openrouter(config_service: Any, _req: Any) -> dict:
    key = config_service.openrouter_api_key or ""
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        resp = _req.get(
            "https://openrouter.ai/api/v1/models",
            headers=headers, timeout=12,
        )
        if resp.status_code != 200:
            return {
                "models": _OPENROUTER_FALLBACK_MODELS,
                "source": "fallback",
                "reason": f"OpenRouter returned HTTP {resp.status_code}",
            }

        payload = resp.json()
        raw     = payload.get("data", []) or []

        models: list[dict] = []
        for m in raw:
            if not isinstance(m, dict):
                continue
            mid = m.get("id", "")
            if not mid:
                continue
            pricing = m.get("pricing") or {}
            is_free = (
                mid.endswith(":free")
                or (str(pricing.get("prompt", "")) in ("0", "0.0")
                    and str(pricing.get("completion", "")) in ("0", "0.0"))
            )
            if not is_free and mid not in _OPENROUTER_CURATED_PAID:
                continue
            models.append({
                "id":       mid,
                "owned_by": mid.split("/")[0] if "/" in mid else "openrouter",
                "free":     is_free,
            })

        models.sort(key=lambda m: (not m["free"], m["id"]))
        return {"models": models, "source": "live"}

    except Exception as exc:
        return {
            "models": _OPENROUTER_FALLBACK_MODELS,
            "source": "fallback",
            "reason": str(exc),
        }


def _fetch_groq(config_service: Any, _req: Any) -> dict:
    key = config_service.groq_api_key or ""
    if not key:
        return {
            "models": _GROQ_FALLBACK_MODELS,
            "source": "fallback",
            "reason": "GROQ_API_KEY not configured",
        }

    try:
        resp = _req.get(
            "https://api.groq.com/openai/v1/models",
            headers={
                "Authorization": f"Bearer {key}",
                "Accept":        "application/json",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            return {
                "models": _GROQ_FALLBACK_MODELS,
                "source": "fallback",
                "reason": f"Groq returned HTTP {resp.status_code}",
            }

        payload = resp.json()
        raw     = payload.get("data", []) or []
        models = [
            {
                "id":       m.get("id", ""),
                "owned_by": m.get("owned_by", "groq"),
                "free":     True,
            }
            for m in raw
            if isinstance(m, dict) and m.get("id")
        ]
        models.sort(key=lambda m: m["id"])
        return {"models": models, "source": "live"}

    except Exception as exc:
        return {
            "models": _GROQ_FALLBACK_MODELS,
            "source": "fallback",
            "reason": str(exc),
        }


def _fetch_ollama(_req: Any) -> dict:
    """
    Read the locally-pulled model list from the Ollama daemon.

    Ollama's ``/api/tags`` returns::

        {"models": [{"name": "llama3.2:latest", "size": ..., ...}, ...]}

    The translation to OpenAI's shape drops everything but the name —
    the UI only uses ``id`` and ``owned_by``. ``owned_by`` is set to
    the model family when the name has a ``family:tag`` form, or
    ``"ollama"`` otherwise.

    A connection failure (daemon not running) returns an empty model
    list with a reason explaining the state. This is the "not an error"
    case: the operator has selected Ollama but not started the server.
    """
    try:
        resp = _req.get(_OLLAMA_TAGS_URL, timeout=3)
    except Exception as exc:
        return {
            "models": _OLLAMA_FALLBACK_MODELS,
            "source": "fallback",
            "reason": (
                f"Ollama daemon not reachable at "
                f"http://localhost:11434 ({type(exc).__name__}). "
                f"Start it with `ollama serve`."
            ),
        }

    if resp.status_code != 200:
        return {
            "models": _OLLAMA_FALLBACK_MODELS,
            "source": "fallback",
            "reason": f"Ollama returned HTTP {resp.status_code}",
        }

    try:
        payload = resp.json()
    except Exception as exc:
        return {
            "models": _OLLAMA_FALLBACK_MODELS,
            "source": "fallback",
            "reason": f"invalid JSON from Ollama: {exc}",
        }

    raw = payload.get("models", []) or []
    models: list[dict] = []
    for m in raw:
        if not isinstance(m, dict):
            continue
        name = m.get("name") or m.get("model") or ""
        if not name:
            continue
        family = name.split(":", 1)[0] if ":" in name else name
        models.append({
            "id":       name,
            "owned_by": family or "ollama",
            "free":     True,
        })

    models.sort(key=lambda m: m["id"])
    return {"models": models, "source": "live"}