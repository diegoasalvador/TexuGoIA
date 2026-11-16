"""
Gerenciador Resiliente de Obtenção e Cache de Modelos de IA.

Implementa estratégias de retry com exponential backoff, cache local em disco com TTL,
fallback offline automático para contingência de rede e proteção contra vazamento
de credenciais no stdout/logs.
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from TeXGuardIA.config import settings

# Catálogo offline de contingência (caso a rede esteja sem acesso ao OpenRouter)
FALLBACK_OPENROUTER_FREE_MODELS = [
    {
        "id": "cohere/north-mini-code:free",
        "name": "Cohere: North Mini Code (free) [Recomendado para Comandos]",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 256000
    },
    {
        "id": "liquid/lfm-2.5-2.6b:free",
        "name": "Liquid: LFM 2.5 2.6B (free)",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 32000
    },
    {
        "id": "meta-llama/llama-3.3-70b-instruct:free",
        "name": "Meta: Llama 3.3 70B Instruct (free)",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 131072
    },
    {
        "id": "deepseek/deepseek-r1:free",
        "name": "DeepSeek: R1 Reasoning (free)",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 64000
    },
    {
        "id": "qwen/qwen-2.5-coder-32b-instruct:free",
        "name": "Qwen: Qwen 2.5 Coder 32B (free)",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 32768
    },
    {
        "id": "google/gemini-2.0-flash-exp:free",
        "name": "Google: Gemini 2.0 Flash Exp (free)",
        "pricing": {"prompt": "0", "completion": "0"},
        "context_length": 1048576
    }
]

# Modelos padrão Alibaba para contingência
FALLBACK_ALIBABA_MODELS = [
    "qwen-plus",
    "qwen-turbo",
    "qwen-max",
    "qwen-flash",
    "qwen2.5-coder-32b-instruct",
    "qwen2.5-72b-instruct"
]

# Modelos padrão Google Gemini para contingência e catálogo rápido
FALLBACK_GEMINI_MODELS: List[Tuple[str, str]] = [
    ("gemini-1.5-flash", "⚡ Mais Rápido & Econômico (Recomendado / Cota Gratuita Alta)"),
    ("gemini-1.5-pro", "🧠 Raciocínio Profundo & Análise Complexa"),
    ("gemini-2.0-flash", "🚀 Nova Geração 2.0 (Super Rápido & Multimodal)"),
    ("gemini-2.0-flash-lite", "🪶 Ultraleve & Baixíssima Latência"),
    ("gemini-1.5-flash-8b", "📦 Modelo Compacto para Tarefas Rápidas"),
]

CACHE_FILE_NAME = ".cache_openrouter_models.json"
CACHE_TTL_SECONDS = 3600  # 1 hora


def fetch_with_retry(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 6,
    max_retries: int = 3,
    backoff_factor: float = 1.5
) -> Optional[bytes]:
    """Executa requisição HTTP com tentativas automáticas e backoff exponencial.

    Não expõe segredos nem headers em caso de falha.
    """
    req_headers = {"User-Agent": "TeXuGo-GuardIA-Cybersecurity-Agent/1.0"}
    if headers:
        req_headers.update(headers)

    delay = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            if attempt < max_retries:
                time.sleep(delay)
                delay *= backoff_factor
            else:
                return None
    return None


def get_cached_models(cache_path: Path) -> Optional[List[dict]]:
    """Lê modelos do cache local se ainda estiver dentro da validade (TTL)."""
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        saved_at = data.get("timestamp", 0)
        if time.time() - saved_at < CACHE_TTL_SECONDS:
            return data.get("models", [])
    except Exception:
        pass
    return None


def save_models_cache(cache_path: Path, models: List[dict]) -> None:
    """Grava catálogo de modelos em arquivo de cache local seguro."""
    try:
        payload = {
            "timestamp": time.time(),
            "count": len(models),
            "models": models
        }
        cache_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def fetch_openrouter_models_resilient(force_refresh: bool = False) -> List[dict]:
    """Obtém a lista de modelos do OpenRouter com cache local, retry e fallback seguro."""
    cache_path = settings.base_dir / CACHE_FILE_NAME

    if not force_refresh:
        cached = get_cached_models(cache_path)
        if cached:
            return cached

    # Tenta buscar remotamente com retry
    raw = fetch_with_retry("https://openrouter.ai/api/v1/models", timeout=7, max_retries=3)
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
            models = parsed.get("data", [])
            if models:
                save_models_cache(cache_path, models)
                return models
        except Exception:
            pass

    # Se falhou a busca remota, tenta usar cache antigo mesmo expirado
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            models = data.get("models", [])
            if models:
                return models
        except Exception:
            pass

    # Último recurso: retorna o catálogo de modelos gratuitos pré-carregados
    return FALLBACK_OPENROUTER_FREE_MODELS


def fetch_alibaba_models_resilient(agent: Any) -> List[str]:
    """Lista modelos disponíveis na conta Alibaba com fallback seguro e sem exposição de chaves."""
    if not agent or not getattr(agent, "ai_client", None):
        return FALLBACK_ALIBABA_MODELS

    try:
        models_page = agent.ai_client.models.list()
        found = []
        for m in getattr(models_page, "data", []):
            mid = getattr(m, "id", None)
            if mid and isinstance(mid, str):
                found.append(mid)
        if found:
            return sorted(list(set(found)))
    except Exception:
        pass

    return FALLBACK_ALIBABA_MODELS


def fetch_gemini_models_resilient(api_key: Optional[str] = None) -> List[Tuple[str, str]]:
    """Lista modelos disponíveis na API Google Gemini com fallback seguro e sem expor credenciais."""
    key = api_key or getattr(settings, "gemini_api_key", "")
    if not key:
        return FALLBACK_GEMINI_MODELS

    try:
        import google.generativeai as genai
        genai.configure(api_key=key)
        remote_models: List[Tuple[str, str]] = []
        for m in genai.list_models():
            methods = getattr(m, "supported_generation_methods", []) or []
            if "generateContent" in methods:
                clean_name = m.name.replace("models/", "")
                display = getattr(m, "display_name", clean_name)
                remote_models.append((clean_name, display))
        if remote_models:
            return remote_models
    except Exception:
        pass

    return FALLBACK_GEMINI_MODELS
