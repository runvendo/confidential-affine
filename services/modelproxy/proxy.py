#!/usr/bin/env python3
"""Tiny OpenAI-compatible proxy: rewrites model names to Tinfoil's and forwards
to confidential inference. Stdlib only (small, auditable TCB). Runs rootless."""
import json, os, sys, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("UPSTREAM_HOST", "https://inference.tinfoil.sh").rstrip("/")
KEY = os.environ.get("INFERENCE_API_KEY", "")
CHAT_MODEL = os.environ.get("CHAT_MODEL", "gpt-oss-120b")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
PORT = int(os.environ.get("PORT", "8081"))

CHAT_ALIASES = {m: CHAT_MODEL for m in (
    "gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-4", "gpt-4-turbo",
    "gpt-3.5-turbo", "o1", "o1-mini", "o3", "o3-mini", "chatgpt-4o-latest")}


def log(*a):
    print("[modelproxy]", *a, file=sys.stderr, flush=True)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.proxy("GET")

    def do_POST(self):
        self.proxy("POST")

    def proxy(self, method):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n) if n else b""
            is_embed = "embedding" in self.path
            if body:
                try:
                    d = json.loads(body)
                    if isinstance(d, dict) and "model" in d:
                        d["model"] = EMBED_MODEL if is_embed else CHAT_ALIASES.get(d.get("model", ""), CHAT_MODEL)
                        body = json.dumps(d).encode()
                except Exception as e:
                    log("body parse skip:", e)
            req = urllib.request.Request(UPSTREAM + self.path, data=body if method == "POST" else None, method=method)
            req.add_header("Authorization", "Bearer " + KEY)
            if body:
                req.add_header("Content-Type", "application/json")
            acc = self.headers.get("Accept")
            if acc:
                req.add_header("Accept", acc)
            with urllib.request.urlopen(req, timeout=300) as r:
                self.send_response(r.status)
                self.send_header("Content-Type", r.headers.get("Content-Type", "application/json"))
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = r.read(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.HTTPError as e:
            d = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(d)
        except Exception as e:
            log("error:", e)
            m = json.dumps({"error": {"message": str(e)}}).encode()
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(m)
            except Exception:
                pass


if __name__ == "__main__":
    log("listening :%d -> %s chat=%s embed=%s" % (PORT, UPSTREAM, CHAT_MODEL, EMBED_MODEL))
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
