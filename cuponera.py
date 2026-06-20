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
