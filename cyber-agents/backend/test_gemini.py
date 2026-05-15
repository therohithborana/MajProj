from pathlib import Path
import os

from dotenv import load_dotenv
import google.generativeai as genai


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

print("ENV_PATH", ENV_PATH)
print("GEMINI_KEY_PRESENT", bool(os.getenv("GEMINI_API_KEY")))
print("GOOGLE_KEY_PRESENT", bool(os.getenv("GOOGLE_API_KEY")))

from gemini_client import call_gemini  # noqa: E402

response = call_gemini("Reply with exactly this text and nothing else: CYBERAGENT_GEMINI_OK")
print("RAW_RESPONSE", response if response else "<empty>")
print("GEMINI_WORKING", "CYBERAGENT_GEMINI_OK" in response)

api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
if api_key:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-2.0-flash"))
        direct = model.generate_content("Reply with exactly this text and nothing else: CYBERAGENT_DIRECT_OK")
        print("DIRECT_RAW_RESPONSE", getattr(direct, "text", "") or "<empty>")
    except Exception as exc:
        print("DIRECT_ERROR", repr(exc))
