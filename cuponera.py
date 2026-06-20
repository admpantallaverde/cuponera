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
CODE_DIGITS = "0123456789"
CODE_LETTERS = "ABCDEFGHJKMNPQRSTUVWXYZ"
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
        _ensure_col(c, "coupons", "creator", "TEXT")
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
    # 4 caracteres: 3 números y 1 letra, en posiciones al azar
    chars = [secrets.choice(CODE_DIGITS) for _ in range(3)] + [secrets.choice(CODE_LETTERS)]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)

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
        "expires": r["expires"], "creator": r["creator"],
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
            s = self._need(c, cap="gen")
            if not s: return
            creator = s["name"]
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
                while c.execute("SELECT 1 FROM coupons WHERE code=?", (code,)).fetchone() and guard < 200:
                    code = gen_code(); guard += 1
                c.execute("""INSERT INTO coupons(code,type,value,descr,created,status,used_at,order_no,redeemer,expires,creator)
                             VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                          (code, typ, value, descr, created + i, "valid", None, None, None, expires, creator))
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
