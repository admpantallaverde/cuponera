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
