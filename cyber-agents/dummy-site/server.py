import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse


MITIGATIONS = []
BLOCKED_IPS = set()


class NovaCartHandler(SimpleHTTPRequestHandler):

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/mitigate":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8") if length else "{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            commands = payload.get("commands", [])
            source_ip = payload.get("source_ip", "unknown")
            attack_type = payload.get("attack_type", "unknown")
            BLOCKED_IPS.add(source_ip)
            MITIGATIONS.append({
                "source_ip": source_ip,
                "attack_type": attack_type,
                "commands": commands,
                "status": "applied",
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "mitigated", "blocked_ips": list(BLOCKED_IPS), "commands_applied": len(commands)}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/mitigation-status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"mitigations": MITIGATIONS, "blocked_ips": list(BLOCKED_IPS)}).encode())
            return
        if parsed.path == "/blocked-ips":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"blocked_ips": list(BLOCKED_IPS)}).encode())
            return
        return super().do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3001))
    server = HTTPServer(("0.0.0.0", port), NovaCartHandler)
    print(f"NovaCart server with mitigation endpoint on http://localhost:{port}")
    print(f"  POST /mitigate  - apply mitigation commands")
    print(f"  GET  /mitigation-status - view applied mitigations")
    print(f"  GET  /blocked-ips - view blocked IPs")
    server.serve_forever()
