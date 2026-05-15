import json
import logging
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

_ollama_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate").strip()
_ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b").strip()
_debug_raw = os.getenv("OLLAMA_DEBUG_RESPONSES", "").strip().lower() in {"1", "true", "yes", "on"}
logger = logging.getLogger("cyberagent.ollama")


def _build_response(text: str, used: bool, model: str, status: str) -> dict:
    return {
        "text": text,
        "reasoning_details": [],
        "used": used,
        "model": model,
        "provider": "ollama",
        "status": status,
    }


def call_llm_response(prompt: str, enable_reasoning: bool = True) -> dict:
    logger.info("Ollama request started model=%s prompt_chars=%s", _ollama_model, len(prompt))
    payload = {
        "model": _ollama_model,
        "prompt": prompt,
        "stream": False,
    }
    if enable_reasoning:
        payload["options"] = {"num_predict": 2048}
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
        return _build_response(text, bool(text), _ollama_model, "ok" if text else "empty_response")
    except HTTPError as exc:
        logger.error("Ollama HTTP error model=%s status=%s reason=%s", _ollama_model, exc.code, exc.reason)
        return _build_response("", False, _ollama_model, f"http_{exc.code}")
    except URLError as exc:
        logger.error("Ollama URL error model=%s error=%s", _ollama_model, exc.reason)
        return _build_response("", False, _ollama_model, "url_error")
    except TimeoutError:
        logger.error("Ollama timeout model=%s", _ollama_model)
        return _build_response("", False, _ollama_model, "timeout")
    except (json.JSONDecodeError, KeyError) as exc:
        logger.error("Ollama response parse error model=%s error=%s", _ollama_model, exc)
        return _build_response("", False, _ollama_model, "parse_error")


def call_gemini(prompt: str) -> str:
    return call_llm_response(prompt, enable_reasoning=True).get("text", "")
