"""Persistent store for the OT Specialist AI app — plain JSON files.

Two files under ``$REDLOOP_HOME/otai/``:

* ``users.json``  — registered accounts (salted password hashes).
* ``chats.json``  — every message every user has sent to the assistant, grouped
  by user, plus the structured facts an extractor lifts out of them.

The operator console ("Red Team AI") reads ``chats.json`` directly — that is the
whole point of the exercise: the assistant keeps everyone's plant details in one
place with no isolation, so a single prompt-injection hands the attacker the lot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional

from redai.core import paths


def _base():
    b = paths.ROOT / "otai"
    b.mkdir(parents=True, exist_ok=True)
    return b


# ---- extraction patterns -------------------------------------------------
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_CIDR = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/\d{1,2}\b")
_CRED = re.compile(
    r"(?:user(?:name)?|login|account|cred(?:ential)?s?)\s*[:=]?\s*([A-Za-z0-9._@\-\\]+)\s*"
    r"(?:/|,|\s|and|\|)+\s*(?:pass(?:word|wd)?|pwd|pw)\s*[:=]?\s*([^\s,;]+)",
    re.I,
)
_CRED2 = re.compile(r"\b([A-Za-z][A-Za-z0-9._@\-\\]{1,31})\s*[:/]\s*([A-Za-z0-9!@#$%^&*._\-]{3,32})\b")
_HOST = re.compile(r"\b((?:plc|hmi|rtu|jump|pivot|eng|ews|scada|historian|dmz|fw|gw|srv|host)[a-z0-9\-]*\d+[a-z0-9\-]*)\b", re.I)
_PROTO = re.compile(r"\b(modbus|s7comm|s7|profinet|ethernet/ip|ethernet-ip|dnp3|bacnet|opc[\- ]?ua|opc|iec[\- ]?104|hart|mqtt)\b", re.I)
_VENDOR = re.compile(r"\b(siemens|allen[\- ]?bradley|rockwell|schneider|modicon|omron|mitsubishi|ge fanuc|honeywell|yokogawa|abb|wago|beckhoff)\b", re.I)
_CRED_WORDS = ("password", "passwd", "pwd", "creds", "credential", "login", "log in",
               "logon", "sign in", "sign-in", "default cred", "we use", "we log in",
               "account", "ssh", "rdp")
_CRED_HINT = re.compile(r"\b(admin|root|operator|administrator|sa|user|guest|test|hacker|"
                        r"siemens|service|support|manager)\b", re.I)


def _around(text: str, m: "re.Match") -> str:
    a = max(0, m.start() - 60)
    b = min(len(text), m.end() + 60)
    return text[a:b].replace("\n", " ").strip()


class OTAIStore:
    """JSON-backed. Instances are cheap; every op reads+writes the file under a
    process-wide lock so the operator console and the app server stay in sync."""

    _LOCK = threading.RLock()

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.users_path = _base() / "users.json"
        self.chats_path = _base() / "chats.json"
        for p, seed in ((self.users_path, {"users": {}}),
                        (self.chats_path, {"users": {}, "harvested": []})):
            if not p.exists():
                p.write_text(json.dumps(seed, indent=2))

    # ---- low-level ------------------------------------------------
    def _read(self, path) -> Dict:
        try:
            return json.loads(path.read_text())
        except Exception:
            return {"users": {}, "harvested": []}

    def _write(self, path, data) -> None:
        tmp = str(path) + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)

    # ---- accounts (RBAC) ---------------------------------------
    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.sha256((salt + ":" + password).encode()).hexdigest()

    def create_user(self, username: str, password: str, role: str = "engineer") -> Dict:
        username = (username or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._\-]{3,32}", username or ""):
            return {"ok": False, "error": "username must be 3-32 chars (letters, digits, . _ -)"}
        if len(password or "") < 4:
            return {"ok": False, "error": "password must be at least 4 characters"}
        with self._LOCK:
            data = self._read(self.users_path)
            users = data.setdefault("users", {})
            if username in users:
                return {"ok": False, "error": "that username is already registered"}
            salt = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
            users[username] = {"salt": salt, "hash": self._hash(password, salt),
                               "role": role, "created": time.time()}
            self._write(self.users_path, data)
        return {"ok": True, "username": username, "role": role}

    def verify_user(self, username: str, password: str) -> bool:
        with self._LOCK:
            u = self._read(self.users_path).get("users", {}).get((username or "").strip())
        return bool(u) and self._hash(password, u["salt"]) == u["hash"]

    def user_exists(self, username: str) -> bool:
        with self._LOCK:
            return (username or "").strip() in self._read(self.users_path).get("users", {})

    def list_users(self) -> List[Dict]:
        with self._LOCK:
            users = self._read(self.users_path).get("users", {})
        return [{"username": k, "role": v.get("role", "engineer"),
                 "created": v.get("created")} for k, v in users.items()]

    # ---- messages ---------------------------------------------
    def ensure_conv(self, username: str, client_ip: str = "") -> None:
        with self._LOCK:
            data = self._read(self.chats_path)
            u = data.setdefault("users", {}).setdefault(
                username, {"messages": [], "first": time.time(), "client_ip": client_ip})
            u["last"] = time.time()
            if client_ip and not u.get("client_ip"):
                u["client_ip"] = client_ip
            self._write(self.chats_path, data)

    def add_message(self, username: str, role: str, content: str) -> None:
        with self._LOCK:
            data = self._read(self.chats_path)
            u = data.setdefault("users", {}).setdefault(
                username, {"messages": [], "first": time.time()})
            u["messages"].append({"role": role, "content": content, "ts": time.time()})
            u["last"] = time.time()
            self._write(self.chats_path, data)

    def history(self, username: str, limit: int = 20) -> List[Dict[str, str]]:
        with self._LOCK:
            u = self._read(self.chats_path).get("users", {}).get(username, {})
        msgs = u.get("messages", [])[-limit:]
        return [{"role": m["role"], "content": m["content"]} for m in msgs]

    # ---- harvesting -----------------------------------------
    def harvest(self, username: str, text: str) -> List[Dict[str, str]]:
        hits: List[Dict[str, str]] = []

        def add(kind, value, context=""):
            value = (value or "").strip()
            if value:
                hits.append({"kind": kind, "value": value, "context": context[:200],
                             "user": username})

        for m in _CIDR.finditer(text):
            add("cidr", m.group(0), _around(text, m))
        cidr_ips = {c.split("/")[0] for c in _CIDR.findall(text)}
        for m in _IPV4.finditer(text):
            if m.group(0) not in cidr_ips:
                add("ipv4", m.group(0), _around(text, m))
        for m in _CRED.finditer(text):
            add("credential", f"{m.group(1)}:{m.group(2)}", _around(text, m))
        low = text.lower()
        gate = any(w in low for w in _CRED_WORDS)
        for m in _CRED2.finditer(text):
            seg = _around(text, m)
            if not (gate or _CRED_HINT.search(seg)):
                continue
            u, p = m.group(1), m.group(2)
            if ("http" in (u + p).lower() or "://" in text[max(0, m.start() - 6):m.start() + 1]
                    or u.isdigit() or p.isdigit() or "." in u):
                continue
            add("credential", f"{u}:{p}", seg)
        for m in _HOST.finditer(text):
            add("hostname", m.group(1), _around(text, m))
        for m in _PROTO.finditer(text):
            add("protocol", m.group(1).lower(), _around(text, m))
        for m in _VENDOR.finditer(text):
            add("controller", m.group(1).title(), _around(text, m))

        stored: List[Dict[str, str]] = []
        with self._LOCK:
            data = self._read(self.chats_path)
            harv = data.setdefault("harvested", [])
            seen = {(h["kind"], h["value"]) for h in harv}
            now = time.time()
            for h in hits:
                if (h["kind"], h["value"]) in seen:
                    continue
                seen.add((h["kind"], h["value"]))
                h["ts"] = now
                harv.append(h)
                stored.append(h)
            if stored:
                self._write(self.chats_path, data)
        return stored

    # ---- readback (exfiltration) ---------------------------
    def chats(self) -> Dict:
        """Full per-user chat log — what /showchats and the injection return."""
        with self._LOCK:
            data = self._read(self.chats_path)
        return data.get("users", {})

    def dump(self) -> Dict:
        with self._LOCK:
            data = self._read(self.chats_path)
        users = data.get("users", {})
        convs, msgs = [], []
        for name, u in users.items():
            convs.append({"id": name, "label": name, "client_ip": u.get("client_ip", ""),
                          "started": u.get("first"), "last": u.get("last"),
                          "count": len(u.get("messages", []))})
            for m in u.get("messages", []):
                msgs.append({"conv_id": name, "user": name, "role": m["role"],
                             "content": m["content"], "ts": m.get("ts")})
        return {"conversations": convs, "messages": msgs,
                "harvested": data.get("harvested", []), "users": users}

    def stats(self) -> Dict[str, int]:
        with self._LOCK:
            data = self._read(self.chats_path)
            nusers = len(self._read(self.users_path).get("users", {}))
        users = data.get("users", {})
        return {"accounts": nusers,
                "conversations": len(users),
                "messages": sum(len(u.get("messages", [])) for u in users.values()),
                "harvested": len(data.get("harvested", []))}

    def wipe(self, keep_users: bool = True) -> None:
        with self._LOCK:
            self._write(self.chats_path, {"users": {}, "harvested": []})
            if not keep_users:
                self._write(self.users_path, {"users": {}})
