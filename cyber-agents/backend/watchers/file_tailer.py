import argparse
import json
import time
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_POLL_SECONDS = 1.0


def _load_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _post_event(api_base: str, payload: dict, collector_key: Optional[str]):
    headers = {"Content-Type": "application/json"}
    if collector_key:
        headers["X-Collector-Key"] = collector_key
    request = Request(
        f"{api_base.rstrip('/')}/collector/ingest",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


class FileTailer:
    def __init__(self, config: dict, from_start: bool = False):
        self.config = config
        self.api_base = config.get("api_base", "http://localhost:8000")
        self.website_id = config["website_id"]
        self.collector_key = config.get("collector_key")
        self.poll_seconds = float(config.get("poll_seconds", DEFAULT_POLL_SECONDS))
        self.offset_path = Path(config.get("offset_store", ".collector_offsets.json"))
        self.offsets = _load_json(self.offset_path, {})
        self.from_start = from_start

    def _initial_offset(self, path: Path):
        if self.from_start:
            return 0
        return path.stat().st_size if path.exists() else 0

    def _read_new_lines(self, source: dict):
        path = Path(source["path"])
        key = str(path.resolve())
        if not path.exists():
            return []

        previous_offset = int(self.offsets.get(key, self._initial_offset(path)))
        current_size = path.stat().st_size
        if current_size < previous_offset:
            previous_offset = 0

        lines = []
        with path.open("r", encoding=source.get("encoding", "utf-8"), errors="replace") as handle:
            handle.seek(previous_offset)
            for line in handle:
                clean = line.strip()
                if clean:
                    lines.append(clean)
            self.offsets[key] = handle.tell()
        return lines

    def run_forever(self):
        print(f"CyberAgent collector watching {len(self.config.get('sources', []))} source(s).")
        while True:
            changed = False
            for source in self.config.get("sources", []):
                try:
                    lines = self._read_new_lines(source)
                    for line in lines:
                        payload = {
                            "website_id": self.website_id,
                            "source_type": source.get("source_type", "access"),
                            "parser": source.get("parser", "auto"),
                            "raw_line": line,
                        }
                        result = _post_event(self.api_base, payload, self.collector_key)
                        print(f"sent {source.get('source_type', 'access')} line: {result.get('status')}")
                    changed = changed or bool(lines)
                except (HTTPError, URLError, OSError, ValueError) as exc:
                    print(f"collector warning for {source.get('path')}: {exc}")
            if changed:
                _save_json(self.offset_path, self.offsets)
            time.sleep(self.poll_seconds)


def main():
    parser = argparse.ArgumentParser(description="Tail local log files and forward events to CyberAgent.")
    parser.add_argument("--config", default="collector_config.json", help="Path to collector JSON config.")
    parser.add_argument("--from-start", action="store_true", help="Read existing file content on first run.")
    args = parser.parse_args()

    config = _load_json(Path(args.config), None)
    if not config:
        raise SystemExit(f"Collector config not found: {args.config}")
    FileTailer(config, from_start=args.from_start).run_forever()


if __name__ == "__main__":
    main()
