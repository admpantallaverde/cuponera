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
        if p == "/api/my-pin":      return self.api_my_pin(b)
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

    def api_my_pin(self, b):
        cur = (b.get("currentPin") or "").strip()
        new = (b.get("newPin") or "").strip()
        with db() as c:
            s = self._need(c)
            if not s: return
            if not new.isdigit() or not (4 <= len(new) <= 8):
                return self.err(400, "El PIN nuevo debe tener 4 a 8 dígitos")
            tok = self.cookie_token()
            if s["role"] == "admin":
                ah, asalt = cfg_get(c, "admin_hash"), cfg_get(c, "admin_salt")
                if not verify_pin(cur, ah, asalt):
                    return self.err(403, "El PIN actual no es correcto")
                for u in c.execute("SELECT * FROM users").fetchall():
                    if verify_pin(new, u["pin_hash"], u["salt"]):
                        return self.err(400, "Ese PIN ya lo usa un usuario")
                h, salt = hash_pin(new)
                cfg_set(c, "admin_hash", h); cfg_set(c, "admin_salt", salt)
                c.execute("DELETE FROM sessions WHERE role='admin' AND token!=?", (tok,))
                c.commit()
            else:
                u = c.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
                if not u: return self.err(403, "Usuario no válido")
                if not verify_pin(cur, u["pin_hash"], u["salt"]):
                    return self.err(403, "El PIN actual no es correcto")
                ah, asalt = cfg_get(c, "admin_hash"), cfg_get(c, "admin_salt")
                if ah and verify_pin(new, ah, asalt):
                    return self.err(400, "Ese PIN es el del administrador")
                for ou in c.execute("SELECT * FROM users WHERE id!=?", (u["id"],)).fetchall():
                    if verify_pin(new, ou["pin_hash"], ou["salt"]):
                        return self.err(400, "Ese PIN ya está en uso")
                h, salt = hash_pin(new)
                c.execute("UPDATE users SET pin_hash=?, salt=? WHERE id=?", (h, salt, u["id"]))
                c.execute("DELETE FROM sessions WHERE user_id=? AND token!=?", (u["id"], tok))
                c.commit()
        self.json({"ok": True})

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
