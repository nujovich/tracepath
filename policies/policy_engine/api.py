"""Minimal HTTP API for policy versioning — consumed by the dashboard."""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

from .versioning import PolicyVersioning

pv = PolicyVersioning()


class PolicyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/policies/versions":
            versions = pv.list_versions()
            data = [
                {
                    "hash": v.commit_hash,
                    "author": v.author,
                    "message": v.message,
                    "timestamp": v.timestamp,
                    "changed_files": v.changed_files,
                }
                for v in versions
            ]
            self._json(data)
        elif self.path.startswith("/api/policies/diff"):
            # /api/policies/diff?old=<hash>&new=<hash>
            try:
                qs = self.path.split("?", 1)[1] if "?" in self.path else ""
                params = dict(p.split("=") for p in qs.split("&") if "=" in p)
                old_hash = params.get("old", "")
                new_hash = params.get("new", "")
                if old_hash and new_hash:
                    diffs = pv.diff_versions(old_hash, new_hash)
                else:
                    diffs = []
                self._json(diffs)
            except Exception:
                self._json([])
        elif self.path.startswith("/api/policies/content"):
            # /api/policies/content?hash=<hash>&file=<filename>
            try:
                qs = self.path.split("?", 1)[1] if "?" in self.path else ""
                params = dict(p.split("=") for p in qs.split("&") if "=" in p)
                commit_hash = params.get("hash", "")
                filename = params.get("file", "main.rego")
                content = pv.get_policy_at(commit_hash, filename)
                self._json({"content": content, "file": filename})
            except Exception:
                self._json({"content": None, "error": "not found"}, 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/policies/rollback":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length > 0 else {}
            commit_hash = body.get("hash", "")
            if commit_hash:
                ok = pv.rollback(commit_hash)
                self._json({"success": ok, "hash": commit_hash})
            else:
                self._json({"error": "missing hash"}, 400)
        else:
            self._json({"error": "not found"}, 404)

    def _json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # silence HTTP logs


def main():
    port = int(os.environ.get("POLICY_API_PORT", "9003"))
    server = HTTPServer(("0.0.0.0", port), PolicyHandler)
    print(f"Policy API listening on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
