"""OT Specialist AI — HTTP server (accounts + chat).

Small ThreadingHTTPServer (stdlib only). Users register / log in; every message
they send is streamed from the local Ollama model and appended to
``chats.json``. Bound to ``0.0.0.0`` by default so it is reachable across the
network.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Optional

try:
    import ollama
except Exception:  # pragma: no cover
    ollama = None  # type: ignore

from redai.core import paths
from .store import OTAIStore

STATIC = Path(__file__).parent / "static"

SYSTEM_PROMPT = (
    "You are OT Specialist AI, an assistant for operational-technology and "
    "industrial-control-system engineers. You help with PLC and HMI "
    "configuration and industrial-protocol troubleshooting (Modbus, S7comm, "
    "PROFINET, DNP3, EtherNet/IP, OPC UA).\n\n"
    "Be concrete and practical. To give useful, plant-specific answers, ask the "
    "engineer for the relevant details of their environment — controller "
    "makes/models, IP addressing and subnets, the protocols in use, how the "
    "cells are segmented, and how devices are reached (management IPs, jump / "
    "pivot hosts, the credentials used in the lab). Use details already shared. "
    "Keep answers short (a few sentences) unless asked for depth."
)


def _secret() -> bytes:
    p = paths.ROOT / "otai" / "secret"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_bytes(hashlib.sha256(os.urandom(32)).hexdigest().encode())
    return p.read_bytes()


def _sign(username: str) -> str:
    sig = hmac.new(_secret(), username.encode(), hashlib.sha256).hexdigest()[:20]
    return f"{username}.{sig}"


def _verify_token(tok: str) -> Optional[str]:
    if not tok or "." not in tok:
        return None
    name, _, sig = tok.rpartition(".")
    if hmac.compare_digest(sig, hmac.new(_secret(), name.encode(), hashlib.sha256).hexdigest()[:20]):
        return name
    return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "OT-Specialist-AI/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    @property
    def store(self) -> OTAIStore:
        return self.server.store  # type: ignore

    @property
    def model(self) -> str:
        return self.server.model  # type: ignore

    # ---- helpers -------------------------------------------------
    def _user(self) -> Optional[str]:
        c = SimpleCookie(self.headers.get("Cookie", ""))
        if "otai_session" in c:
            name = _verify_token(c["otai_session"].value)
            if name and self.store.user_exists(name):
                return name
        return None

    def _send(self, code, body: bytes, ctype="application/json", cookie: str = ""):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj, code=200, cookie=""):
        self._send(code, json.dumps(obj).encode(), "application/json", cookie)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def _cookie_for(self, username: str) -> str:
        return (f"otai_session={_sign(username)}; Path=/; Max-Age=604800; "
                f"SameSite=Lax; HttpOnly")

    # ---- routes ----------------------------------------------
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = (STATIC / "index.html").read_text(encoding="utf-8")
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        if self.path.startswith("/api/health"):
            return self._json({"ok": True, "model": self.model, "stats": self.store.stats()})
        if self.path.startswith("/api/me"):
            u = self._user()
            return self._json({"authed": bool(u), "username": u})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path.startswith("/api/register") or self.path.startswith("/api/login"):
            return self._auth(register=self.path.startswith("/api/register"))
        if self.path.startswith("/api/logout"):
            return self._send(200, b'{"ok":true}', "application/json",
                              "otai_session=; Path=/; Max-Age=0")
        if self.path.startswith("/api/chat"):
            return self._chat()
        return self._json({"error": "not found"}, 404)

    def _auth(self, register: bool):
        d = self._body()
        username = (d.get("username") or "").strip()
        password = d.get("password") or ""
        if register:
            res = self.store.create_user(username, password)
            if not res.get("ok"):
                return self._json(res, 400)
        else:
            if not self.store.verify_user(username, password):
                return self._json({"ok": False, "error": "invalid username or password"}, 401)
        return self._json({"ok": True, "username": username}, 200, self._cookie_for(username))

    def _chat(self):
        username = self._user()
        if not username:
            return self._json({"error": "sign in first"}, 401)
        d = self._body()
        msg = (d.get("message") or "").strip()
        if not msg:
            return self._json({"error": "empty message"}, 400)
        client_ip = self.client_address[0] if self.client_address else ""

        self.store.ensure_conv(username, client_ip)
        self.store.add_message(username, "user", msg)
        try:
            self.store.harvest(username, msg)
        except Exception:
            pass

        history = self.store.history(username, limit=16)
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}] + history

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def chunk(s: str) -> None:
            b = s.encode("utf-8")
            self.wfile.write(f"{len(b):X}\r\n".encode() + b + b"\r\n")
            self.wfile.flush()

        parts = []
        try:
            for piece in _generate(self.server, msgs):  # type: ignore
                parts.append(piece)
                chunk(piece)
        except Exception as e:
            chunk(f"\n[the assistant is busy — please send that again] ({e})")
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass

        reply = "".join(parts).strip()
        if reply:
            self.store.add_message(username, "assistant", reply)


def _generate(server, msgs):
    # Prefer the configured provider layer (Claude CLI / Ollama role-routing) so
    # the assistant answers even when Ollama isn't running — and its replies are
    # stored + shown by /showchats.
    try:
        from redai.llm import LLM
        from redai.core.config import Config
        llm = getattr(server, "_llm", None)
        if llm is None:
            cfg = Config.load()
            llm = LLM(cfg.get("llm.host"), server.model or cfg.get("llm.model"),
                      provider=cfg.get("llm.provider", "auto"),
                      claude_bin=cfg.get("llm.claude_bin", "claude"),
                      claude_extra_args=cfg.get("llm.claude_extra_args", []),
                      timeout=cfg.get("llm.request_timeout", 120))
            server._llm = llm
        reply = llm.chat(msgs)
        if reply:
            yield reply
            return
    except Exception:
        pass
    # legacy Ollama streaming fallback
    if ollama is not None and getattr(server, "client", None) is not None:
        try:
            opts = {"temperature": 0.5, "num_ctx": 1536, "num_predict": 260}
            for ch in server.client.chat(model=server.model, messages=msgs,
                                         options=opts, keep_alive="60m", stream=True):
                piece = ch.get("message", {}).get("content", "")
                if piece:
                    yield piece
            return
        except Exception:
            pass
    yield "The assistant backend is not available right now."


class OTAIServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 model: str = "llama3.2:1b",
                 ollama_host: str = "http://127.0.0.1:11434") -> None:
        self.host = host
        self.port = port
        self.model = model
        self.store = OTAIStore()
        self.httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.client = None
        if ollama is not None:
            try:
                self.client = ollama.Client(host=ollama_host, timeout=300)
            except Exception:
                self.client = None

    @property
    def running(self) -> bool:
        return self.httpd is not None and self._thread is not None and self._thread.is_alive()

    def start(self) -> str:
        if self.running:
            return self.url
        self.httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.httpd.store = self.store          # type: ignore
        self.httpd.model = self.model          # type: ignore
        self.httpd.client = self.client        # type: ignore
        self.httpd.daemon_threads = True
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True,
                                        name="ot-specialist-ai")
        self._thread.start()
        threading.Thread(target=self._warm, daemon=True).start()
        return self.url

    def _warm(self) -> None:
        try:
            if self.client:
                self.client.chat(model=self.model,
                                 messages=[{"role": "user", "content": "ready?"}],
                                 options={"num_predict": 1}, keep_alive="60m")
        except Exception:
            pass

    def stop(self) -> None:
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
        self.httpd = None
        self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
