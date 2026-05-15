import json
import logging
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
_api_keys = [
    item.strip()
    for item in os.getenv("OPENROUTER_API_KEYS", _api_key).split(",")
    if item.strip()
]
_model = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4-flash:free").strip()
_model_fallbacks = [
    item.strip()
    for item in os.getenv(
        "OPENROUTER_MODELS",
        ",".join(
            [
                _model or "deepseek/deepseek-v4-flash:free",
                "google/gemma-4-26b-a4b-it:free",
                "google/gemma-4-31b-it:free",
                "z-ai/glm-4.5-air:free",
            ]
        ),
    ).split(",")
    if item.strip()
]
_site_url = os.getenv("OPENROUTER_SITE_URL", "http://localhost:3000").strip()
_site_name = os.getenv("OPENROUTER_SITE_NAME", "CyberAgent SOC").strip()
_debug_raw = os.getenv("OPENROUTER_DEBUG_RESPONSES", "").strip().lower() in {"1", "true", "yes", "on"}
_ollama_enabled = os.getenv("OLLAMA_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
_ollama_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate").strip()
_ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b").strip()
logger = logging.getLogger("cyberagent.openrouter")


def _extract_text(message: dict) -> str:
    content = message.get("content", "")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "\n".join(part for part in parts if part).strip()
    return str(content).strip()


def _build_response(text: str, reasoning_details: list, used: bool, model: str, status: str) -> dict:
    return {
        "text": text,
        "reasoning_details": reasoning_details,
        "used": used,
        "model": model,
        "provider": "openrouter",
        "status": status,
    }


def _call_ollama(prompt: str) -> dict:
    if not _ollama_enabled:
        return _build_response("", [], False, _ollama_model, "ollama_disabled")
    logger.info("Ollama request started model=%s prompt_chars=%s", _ollama_model, len(prompt))
    payload = {
        "model": _ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    request = Request(
        _ollama_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=90) as response:
            body = json.loads(response.read().decode("utf-8"))
        text = str(body.get("response") or "").strip()
        logger.info("Ollama request succeeded model=%s response_chars=%s", _ollama_model, len(text))
        if _debug_raw:
            logger.info("Ollama raw text response model=%s text=%s", _ollama_model, text)
        return {
            "text": text,
            "reasoning_details": [],
            "used": bool(text),
            "model": _ollama_model,
            "provider": "ollama",
            "status": "ok" if text else "empty_response",
        }
    except HTTPError as exc:
        logger.error("Ollama HTTP error model=%s status=%s reason=%s", _ollama_model, exc.code, exc.reason)
        return {
            "text": "",
            "reasoning_details": [],
            "used": False,
            "model": _ollama_model,
            "provider": "ollama",
            "status": f"http_{exc.code}",
        }
    except URLError as exc:
        logger.error("Ollama URL error model=%s error=%s", _ollama_model, exc.reason)
        return {
            "text": "",
            "reasoning_details": [],
            "used": False,
            "model": _ollama_model,
            "provider": "ollama",
            "status": "url_error",
        }
    except TimeoutError:
        logger.error("Ollama timeout model=%s", _ollama_model)
        return {
            "text": "",
            "reasoning_details": [],
            "used": False,
            "model": _ollama_model,
            "provider": "ollama",
            "status": "timeout",
        }
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Ollama response parse error model=%s error=%s", _ollama_model, exc)
        return {
            "text": "",
            "reasoning_details": [],
            "used": False,
            "model": _ollama_model,
            "provider": "ollama",
            "status": "parse_error",
        }


def call_llm_response(prompt: str, enable_reasoning: bool = True) -> dict:
    if not _api_keys:
        logger.warning("OpenRouter request skipped because OPENROUTER_API_KEY is missing.")
        return _build_response("", [], False, _model, "missing_api_key")

    models = list(dict.fromkeys(_model_fallbacks or [_model]))
    last_error = _build_response("", [], False, _model, "no_models_configured")
    for key_index, api_key in enumerate(_api_keys, start=1):
        for model_name in models:
            logger.info(
                "OpenRouter request started key_slot=%s model=%s prompt_chars=%s reasoning=%s",
                key_index,
                model_name,
                len(prompt),
                enable_reasoning,
            )
            payload = {
                "model": model_name,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                "reasoning": {"enabled": bool(enable_reasoning)},
            }
            request = Request(
                OPENROUTER_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": _site_url,
                    "X-Title": _site_name,
                },
                method="POST",
            )
            try:
                with urlopen(request, timeout=45) as response:
                    body = json.loads(response.read().decode("utf-8"))
                message = ((body.get("choices") or [{}])[0] or {}).get("message") or {}
                text = _extract_text(message)
                reasoning_details = message.get("reasoning_details") or []
                logger.info(
                    "OpenRouter request succeeded key_slot=%s model=%s response_chars=%s reasoning_details=%s",
                    key_index,
                    model_name,
                    len(text or ""),
                    bool(reasoning_details),
                )
                if _debug_raw:
                    logger.info("OpenRouter raw text response key_slot=%s model=%s text=%s", key_index, model_name, text)
                    if reasoning_details is not None:
                        logger.info(
                            "OpenRouter reasoning details key_slot=%s model=%s details=%s",
                            key_index,
                            model_name,
                            json.dumps(reasoning_details, ensure_ascii=False),
                        )
                return _build_response(text, reasoning_details, True, model_name, "ok")
            except HTTPError as exc:
                logger.error("OpenRouter HTTP error key_slot=%s model=%s status=%s reason=%s", key_index, model_name, exc.code, exc.reason)
                last_error = _build_response("", [], False, model_name, f"http_{exc.code}")
                if exc.code not in {408, 409, 425, 429, 500, 502, 503, 504}:
                    return last_error
                logger.info("OpenRouter rotating after retryable status=%s from key_slot=%s model=%s", exc.code, key_index, model_name)
            except URLError as exc:
                logger.error("OpenRouter URL error key_slot=%s model=%s error=%s", key_index, model_name, exc.reason)
                last_error = _build_response("", [], False, model_name, "url_error")
                logger.info("OpenRouter rotating to next fallback option after URL error")
            except TimeoutError:
                logger.error("OpenRouter timeout key_slot=%s model=%s", key_index, model_name)
                last_error = _build_response("", [], False, model_name, "timeout")
                logger.info("OpenRouter rotating to next fallback option after timeout")
            except (json.JSONDecodeError, KeyError) as exc:
                logger.error("OpenRouter response parse error key_slot=%s model=%s error=%s", key_index, model_name, exc)
                last_error = _build_response("", [], False, model_name, "parse_error")
                logger.info("OpenRouter rotating to next fallback option after parse error")
    ollama_result = _call_ollama(prompt)
    if ollama_result.get("used"):
        return ollama_result
    return ollama_result if ollama_result.get("status") != "ollama_disabled" else last_error


def call_gemini(prompt: str) -> str:
    return call_llm_response(prompt, enable_reasoning=True).get("text", "")
