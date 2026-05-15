from pathlib import Path
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv


ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

print("ENV_PATH", ENV_PATH)
print("OPENROUTER_KEY_PRESENT", bool(os.getenv("OPENROUTER_API_KEY")))
print("OPENROUTER_MODEL", os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4-flash:free"))

from gemini_client import call_gemini  # noqa: E402

response = call_gemini("Reply with exactly this text and nothing else: CYBERAGENT_OPENROUTER_OK")
print("RAW_RESPONSE", response if response else "<empty>")
print("OPENROUTER_WORKING", "CYBERAGENT_OPENROUTER_OK" in response)

json_probe = call_gemini(
    """
Return a JSON object only with exactly this structure:
{
  "mode": "approval_required",
  "reason": "one sentence",
  "safety_notes": ["note 1", "note 2"],
  "requires_human_review": true
}
""".strip()
)
print("JSON_PROBE_RAW", json_probe if json_probe else "<empty>")
try:
    parsed_probe = json.loads(json_probe)
    print("JSON_PROBE_VALID", True)
    print("JSON_PROBE_KEYS", sorted(parsed_probe.keys()))
except Exception as exc:
    print("JSON_PROBE_VALID", False)
    print("JSON_PROBE_ERROR", repr(exc))

api_key = os.getenv("OPENROUTER_API_KEY")
if api_key:
    payload = {
        "model": os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v4-flash:free"),
        "messages": [
            {
                "role": "user",
                "content": "Reply with exactly this text and nothing else: CYBERAGENT_OPENROUTER_DIRECT_OK",
            }
        ],
        "reasoning": {"enabled": True},
    }
    request = Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost:3000"),
            "X-Title": os.getenv("OPENROUTER_SITE_NAME", "CyberAgent SOC"),
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as direct_response:
            body = json.loads(direct_response.read().decode("utf-8"))
        message = ((body.get("choices") or [{}])[0] or {}).get("message") or {}
        print("DIRECT_RAW_RESPONSE", message.get("content") or "<empty>")
        print("DIRECT_REASONING_PRESENT", bool(message.get("reasoning_details")))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print("DIRECT_ERROR", repr(exc))
