from parsers.access_log import parse_access_log
from parsers.json_log import parse_json_log


def parse_log_line(line: str, parser: str = "auto"):
    selected = (parser or "auto").lower()
    if selected == "json" or (selected == "auto" and line.lstrip().startswith("{")):
        return parse_json_log(line)
    return parse_access_log(line)
