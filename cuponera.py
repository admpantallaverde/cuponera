#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cuponera - servidor independiente de cupones de un solo uso.
Solo usa la librería estándar de Python (sin instalar nada).
Uso:  python3 cuponera.py            (escucha en el puerto 8000)
      PORT=9000 python3 cuponera.py  (otro puerto)
La base de datos se guarda en 'cuponera.db' junto al archivo.
"""
import os, base64, gzip, json, sqlite3, hashlib, hmac, secrets, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
DB   = os.environ.get("CUPONERA_DB", os.path.join(BASE, "cuponera.db"))
PORT = int(os.environ.get("PORT", "8000"))
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_lock = threading.Lock()

# ---------------- base de datos ----------------
def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    return c

def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT, pin_hash TEXT, salt TEXT, created INTEGER)")
        c.execute("""CREATE TABLE IF NOT EXISTS coupons(
            code TEXT PRIMARY KEY, type TEXT, value REAL, descr TEXT, created INTEGER,
            status TEXT, used_at INTEGER, order_no TEXT, redeemer TEXT, expires INTEGER)""")
        c.execute("CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, role TEXT, name TEXT, user_id TEXT, created INTEGER)")
        c.commit()

def cfg_get(c, k, d=None):
    r = c.execute("SELECT value FROM config WHERE key=?", (k,)).fetchone()
    return r["value"] if r else d

def cfg_set(c, k, v):
    c.execute("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

# ---------------- helpers ----------------
def now_ms(): return int(time.time() * 1000)

def hash_pin(pin, salt=None):
    if salt is None: salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 120000).hex()
    return h, salt

def verify_pin(pin, h, salt):
    if not h or not salt: return False
    calc = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 120000).hex()
    return hmac.compare_digest(calc, h)

def gen_code():
    return "".join(secrets.choice(ALPHABET) for _ in range(8))

def pretty(k):
    return (k[:4] + "-" + k[4:]) if len(k) == 8 else k

def norm(v):
    return "".join(ch for ch in (v or "").upper() if ch.isalnum())

def coupon_dict(r):
    return {
        "code": r["code"], "display": pretty(r["code"]), "type": r["type"],
        "value": r["value"] if r["type"] == "fixed" else int(r["value"]),
        "descr": r["descr"] or "", "created": r["created"], "status": r["status"],
        "usedAt": r["used_at"], "order": r["order_no"], "redeemer": r["redeemer"],
        "expires": r["expires"],
    }

# ---------------- sesiones ----------------
def new_session(c, role, name, user_id=None):
    tok = secrets.token_urlsafe(24)
    c.execute("INSERT INTO sessions(token,role,name,user_id,created) VALUES(?,?,?,?,?)",
              (tok, role, name, user_id, now_ms()))
    return tok

def session_for(c, tok):
    if not tok: return None
    return c.execute("SELECT * FROM sessions WHERE token=?", (tok,)).fetchone()

# ---------------- HTTP ----------------
class H(BaseHTTPRequestHandler):
    server_version = "Cuponera/1.0"
    protocol_version = "HTTP/1.0"

    def log_message(self, *a): pass  # silencio

    # ---- utilidades de respuesta ----
    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def json(self, obj, code=200, cookie=None):
        self._send(code, json.dumps(obj).encode("utf-8"), cookie=cookie)

    def err(self, code, msg):
        self.json({"error": msg}, code=code)

    def cookie_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("token="):
                return part[6:]
        return None

    def body_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0: return {}
            return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            return {}

    def session(self, c):
        return session_for(c, self.cookie_token())

    # ---- routing ----
    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        if p == "/" or p == "/index.html":
            return self._send(200, INDEX_HTML.encode("utf-8"), ctype="text/html; charset=utf-8")
        if p == "/api/config":   return self.api_config()
        if p == "/api/me":       return self.api_me()
        if p == "/api/coupons":  return self.api_list_coupons()
        if p == "/api/history":  return self.api_history(parse_qs(u.query))
        if p == "/api/users":    return self.api_list_users()
        if p.startswith("/api/coupon/"): return self.api_validate(p.rsplit("/", 1)[-1])
        return self.err(404, "No encontrado")

    def do_POST(self):
        p = urlparse(self.path).path
        b = self.body_json()
        if p == "/api/setup-admin": return self.api_setup_admin(b)
        if p == "/api/login":       return self.api_login(b)
        if p == "/api/logout":      return self.api_logout()
        if p == "/api/coupons":     return self.api_create_coupons(b)
        if p == "/api/redeem":      return self.api_redeem(b)
        if p == "/api/users":       return self.api_add_user(b)
        if p == "/api/settings":    return self.api_settings(b)
        if p == "/api/admin-pin":   return self.api_admin_pin(b)
        if p == "/api/wipe":        return self.api_wipe()
        return self.err(404, "No encontrado")

    def do_DELETE(self):
        p = urlparse(self.path).path
        if p.startswith("/api/coupons/"): return self.api_delete_coupon(p.rsplit("/", 1)[-1])
        if p.startswith("/api/users/"):   return self.api_delete_user(p.rsplit("/", 1)[-1])
        return self.err(404, "No encontrado")

    # ---- endpoints públicos ----
    def api_config(self):
        with db() as c:
            self.json({
                "currency": cfg_get(c, "currency", "$"),
                "adminPinSet": cfg_get(c, "admin_hash") is not None,
                "anyUsers": c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] > 0,
            })

    def api_me(self):
        with db() as c:
            s = self.session(c)
            if not s: return self.json({"role": None})
            self.json({"role": s["role"], "name": s["name"]})

    def api_setup_admin(self, b):
        pin = (b.get("pin") or "").strip()
        with db() as c:
            if cfg_get(c, "admin_hash") is not None:
                return self.err(403, "Ya existe un administrador")
            if not pin.isdigit() or not (4 <= len(pin) <= 8):
                return self.err(400, "El PIN debe tener 4 a 8 dígitos")
            h, salt = hash_pin(pin)
            cfg_set(c, "admin_hash", h); cfg_set(c, "admin_salt", salt)
            if cfg_get(c, "currency") is None: cfg_set(c, "currency", "$")
            tok = new_session(c, "admin", "Administrador")
            c.commit()
        self.json({"role": "admin", "name": "Administrador"}, cookie=self._cookie(tok))

    def api_login(self, b):
        pin = (b.get("pin") or "").strip()
        if not pin: return self.err(400, "Ingresá el PIN")
        with db() as c:
            ah, asalt = cfg_get(c, "admin_hash"), cfg_get(c, "admin_salt")
            if ah and verify_pin(pin, ah, asalt):
                tok = new_session(c, "admin", "Administrador"); c.commit()
                return self.json({"role": "admin", "name": "Administrador"}, cookie=self._cookie(tok))
            for u in c.execute("SELECT * FROM users").fetchall():
                if verify_pin(pin, u["pin_hash"], u["salt"]):
                    tok = new_session(c, "user", u["name"], u["id"]); c.commit()
                    return self.json({"role": "user", "name": u["name"]}, cookie=self._cookie(tok))
        return self.err(401, "PIN incorrecto")

    def api_logout(self):
        tok = self.cookie_token()
        if tok:
            with db() as c:
                c.execute("DELETE FROM sessions WHERE token=?", (tok,)); c.commit()
        self.json({"ok": True}, cookie="token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")

    def _cookie(self, tok):
        return "token=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000" % tok

    # ---- requiere sesión / admin ----
    def _need(self, c, admin=False):
        s = self.session(c)
        if not s:
            self.err(401, "No autenticado"); return None
        if admin and s["role"] != "admin":
            self.err(403, "Solo el administrador"); return None
        return s

    # ---- cupones ----
    def api_create_coupons(self, b):
        with db() as c:
            if not self._need(c, admin=True): return
            typ = "fixed" if b.get("type") == "fixed" else "pct"
            try: value = float(b.get("value"))
            except Exception: return self.err(400, "Valor inválido")
            if value <= 0: return self.err(400, "El valor debe ser mayor a 0")
            if typ == "pct":
                value = round(value)
                if value < 1 or value > 100: return self.err(400, "El porcentaje va de 1 a 100")
            else:
                value = round(value, 2)
            qty = max(1, min(50, int(b.get("qty") or 1)))
            descr = (b.get("descr") or "").strip()[:60]
            expires = b.get("expires")
            expires = int(expires) if expires else None
            created = now_ms()
            out = []
            for i in range(qty):
                code = gen_code(); guard = 0
                while c.execute("SELECT 1 FROM coupons WHERE code=?", (code,)).fetchone() and guard < 30:
                    code = gen_code(); guard += 1
                c.execute("""INSERT INTO coupons(code,type,value,descr,created,status,used_at,order_no,redeemer,expires)
                             VALUES(?,?,?,?,?,?,?,?,?,?)""",
                          (code, typ, value, descr, created + i, "valid", None, None, None, expires))
                out.append(coupon_dict(c.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()))
            c.commit()
        self.json({"coupons": out})

    def api_list_coupons(self):
        with db() as c:
            if not self._need(c, admin=True): return
            rows = c.execute("SELECT * FROM coupons ORDER BY created DESC").fetchall()
            self.json({"coupons": [coupon_dict(r) for r in rows]})

    def api_delete_coupon(self, code):
        code = norm(code)
        with db() as c:
            if not self._need(c, admin=True): return
            c.execute("DELETE FROM coupons WHERE code=?", (code,)); c.commit()
        self.json({"ok": True})

    def api_wipe(self):
        with db() as c:
            if not self._need(c, admin=True): return
            c.execute("DELETE FROM coupons"); c.commit()
        self.json({"ok": True})

    def api_validate(self, code):
        code = norm(code)
        with db() as c:
            if not self._need(c): return
            r = c.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
            if not r: return self.json({"found": False})
            d = coupon_dict(r)
            d["found"] = True
            d["expired"] = bool(r["expires"] and now_ms() > r["expires"] and r["status"] != "used")
            self.json(d)

    def api_redeem(self, b):
        code = norm(b.get("code") or "")
        order = (b.get("order") or "").strip()[:40]
        if not code:  return self.err(400, "Falta el código")
        if not order: return self.err(400, "Falta el número de orden o factura")
        with db() as c:
            s = self._need(c)
            if not s: return
            with _lock:
                c.execute("BEGIN IMMEDIATE")
                r = c.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
                if not r:
                    c.execute("ROLLBACK"); return self.json({"ok": False, "reason": "notfound"})
                if r["status"] == "used":
                    c.execute("ROLLBACK")
                    return self.json({"ok": False, "reason": "used", "coupon": coupon_dict(r)})
                if r["expires"] and now_ms() > r["expires"]:
                    c.execute("ROLLBACK")
                    return self.json({"ok": False, "reason": "expired", "coupon": coupon_dict(r)})
                ts = now_ms()
                c.execute("""UPDATE coupons SET status='used', used_at=?, order_no=?, redeemer=?
                             WHERE code=? AND status='valid'""", (ts, order, s["name"], code))
                ok = c.execute("SELECT changes() ch").fetchone()["ch"] == 1
                c.execute("COMMIT")
                if not ok:
                    r2 = c.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
                    return self.json({"ok": False, "reason": "used", "coupon": coupon_dict(r2)})
                r2 = c.execute("SELECT * FROM coupons WHERE code=?", (code,)).fetchone()
                self.json({"ok": True, "coupon": coupon_dict(r2)})

    def api_history(self, q):
        with db() as c:
            if not self._need(c): return
            rows = c.execute("SELECT * FROM coupons WHERE status='used' ORDER BY used_at DESC").fetchall()
            self.json({"items": [coupon_dict(r) for r in rows]})

    # ---- usuarios ----
    def api_list_users(self):
        with db() as c:
            if not self._need(c, admin=True): return
            rows = c.execute("SELECT id,name,created FROM users ORDER BY created").fetchall()
            self.json({"users": [{"id": r["id"], "name": r["name"]} for r in rows]})

    def api_add_user(self, b):
        name = (b.get("name") or "").strip()[:40]
        pin = (b.get("pin") or "").strip()
        with db() as c:
            if not self._need(c, admin=True): return
            if not name: return self.err(400, "Falta el nombre")
            if not pin.isdigit() or not (4 <= len(pin) <= 8): return self.err(400, "El PIN debe tener 4 a 8 dígitos")
            ah, asalt = cfg_get(c, "admin_hash"), cfg_get(c, "admin_salt")
            if ah and verify_pin(pin, ah, asalt): return self.err(400, "Ese PIN es el del administrador")
            for u in c.execute("SELECT * FROM users").fetchall():
                if verify_pin(pin, u["pin_hash"], u["salt"]): return self.err(400, "Ese PIN ya está en uso")
            h, salt = hash_pin(pin)
            uid = "u" + secrets.token_hex(5)
            c.execute("INSERT INTO users(id,name,pin_hash,salt,created) VALUES(?,?,?,?,?)",
                      (uid, name, h, salt, now_ms()))
            c.commit()
        self.json({"id": uid, "name": name})

    def api_delete_user(self, uid):
        with db() as c:
            if not self._need(c, admin=True): return
            c.execute("DELETE FROM users WHERE id=?", (uid,))
            c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            c.commit()
        self.json({"ok": True})

    # ---- ajustes ----
    def api_settings(self, b):
        with db() as c:
            if not self._need(c, admin=True): return
            cur = (b.get("currency") or "$").strip()[:4] or "$"
            cfg_set(c, "currency", cur); c.commit()
        self.json({"currency": cur})

    def api_admin_pin(self, b):
        pin = (b.get("pin") or "").strip()
        with db() as c:
            if not self._need(c, admin=True): return
            if pin == "":
                cfg_set(c, "admin_hash", None); cfg_set(c, "admin_salt", None); c.commit()
                return self.json({"adminPinSet": False})
            if not pin.isdigit() or not (4 <= len(pin) <= 8): return self.err(400, "El PIN debe tener 4 a 8 dígitos")
            for u in c.execute("SELECT * FROM users").fetchall():
                if verify_pin(pin, u["pin_hash"], u["salt"]): return self.err(400, "Ese PIN ya lo usa un usuario")
            h, salt = hash_pin(pin)
            cfg_set(c, "admin_hash", h); cfg_set(c, "admin_salt", salt); c.commit()
        self.json({"adminPinSet": True})


INDEX_HTML = gzip.decompress(base64.b64decode("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")).decode("utf-8")

if __name__ == "__main__":
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print("Cuponera escuchando en http://0.0.0.0:%d  (DB: %s)" % (PORT, DB))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nChau!")
