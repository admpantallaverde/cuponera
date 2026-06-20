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
        _ensure_col(c, "users", "can_gen", "INTEGER DEFAULT 0")
        _ensure_col(c, "users", "can_red", "INTEGER DEFAULT 1")
        c.commit()

def _ensure_col(c, table, col, decl):
    cols = [r["name"] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()]
    if col not in cols:
        c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))

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
            if s["role"] == "admin":
                return self.json({"role": "admin", "name": s["name"], "canGen": True, "canRed": True})
            u = c.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
            cg = bool(u["can_gen"]) if u else False
            cr = bool(u["can_red"]) if u else False
            self.json({"role": "user", "name": s["name"], "canGen": cg, "canRed": cr})

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
    def _need(self, c, admin=False, cap=None):
        s = self.session(c)
        if not s:
            self.err(401, "No autenticado"); return None
        if s["role"] == "admin":
            return s
        if admin:
            self.err(403, "Solo el administrador"); return None
        if cap:
            u = c.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
            if not u:
                self.err(403, "Usuario no válido"); return None
            if cap == "gen" and not u["can_gen"]:
                self.err(403, "No tenés permiso para generar"); return None
            if cap == "red" and not u["can_red"]:
                self.err(403, "No tenés permiso para canjear"); return None
        return s

    # ---- cupones ----
    def api_create_coupons(self, b):
        with db() as c:
            if not self._need(c, cap="gen"): return
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
            if not self._need(c, cap="gen"): return
            rows = c.execute("SELECT * FROM coupons ORDER BY created DESC").fetchall()
            self.json({"coupons": [coupon_dict(r) for r in rows]})

    def api_delete_coupon(self, code):
        code = norm(code)
        with db() as c:
            if not self._need(c, cap="gen"): return
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
            if not self._need(c, cap="red"): return
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
            s = self._need(c, cap="red")
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
            if not self._need(c, cap="red"): return
            rows = c.execute("SELECT * FROM coupons WHERE status='used' ORDER BY used_at DESC").fetchall()
            self.json({"items": [coupon_dict(r) for r in rows]})

    # ---- usuarios ----
    def api_list_users(self):
        with db() as c:
            if not self._need(c, admin=True): return
            rows = c.execute("SELECT id,name,can_gen,can_red FROM users ORDER BY created").fetchall()
            self.json({"users": [{"id": r["id"], "name": r["name"], "canGen": bool(r["can_gen"]), "canRed": bool(r["can_red"])} for r in rows]})

    def api_add_user(self, b):
        name = (b.get("name") or "").strip()[:40]
        pin = (b.get("pin") or "").strip()
        can_gen = 1 if b.get("canGen") else 0
        can_red = 1 if b.get("canRed") else 0
        with db() as c:
            if not self._need(c, admin=True): return
            if not name: return self.err(400, "Falta el nombre")
            if not (can_gen or can_red): return self.err(400, "Elegí al menos un permiso")
            if not pin.isdigit() or not (4 <= len(pin) <= 8): return self.err(400, "El PIN debe tener 4 a 8 dígitos")
            ah, asalt = cfg_get(c, "admin_hash"), cfg_get(c, "admin_salt")
            if ah and verify_pin(pin, ah, asalt): return self.err(400, "Ese PIN es el del administrador")
            for u in c.execute("SELECT * FROM users").fetchall():
                if verify_pin(pin, u["pin_hash"], u["salt"]): return self.err(400, "Ese PIN ya está en uso")
            h, salt = hash_pin(pin)
            uid = "u" + secrets.token_hex(5)
            c.execute("INSERT INTO users(id,name,pin_hash,salt,created,can_gen,can_red) VALUES(?,?,?,?,?,?,?)",
                      (uid, name, h, salt, now_ms(), can_gen, can_red))
            c.commit()
        self.json({"id": uid, "name": name, "canGen": bool(can_gen), "canRed": bool(can_red)})

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
