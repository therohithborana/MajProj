import os

from dotenv import load_dotenv
import google.generativeai as genai


load_dotenv()

_api_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
if _api_key:
    genai.configure(api_key=_api_key)

_model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))


def call_gemini(prompt: str) -> str:
    if not _api_key:
        return ""
    try:
        response = _model.generate_content(prompt)
        text = getattr(response, "text", "") or ""
        cleaned = text.strip()
        if cleaned:
            return cleaned
    except Exception:
        pass
    return ""
