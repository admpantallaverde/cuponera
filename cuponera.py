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


INDEX_HTML = gzip.decompress(base64.b64decode("H4sIACTUNmoC/819TZPbRpbgXb8iRckC2SJZ/C4WKZZaVsu2Zi1ZY8mK6LE9YxBIkrBAgAbAKpUpRviye9udw/bGHLYnOvqyEX3oiI3ow2zMHjai9U/8B3Z+wr73MhPIxAeL0qhnttsuk0Dmy5eZ7/u9TN5b88RmzsqOYp7Mattk0RrXzm/cS7zE5+cPt5sw4JHN/vxP7JkdJLbv2+wlj1x+70S0uHGPAAT2ms9qFx6/3IRRUmNOGCQ8AICXnpusZi6/8Bzeoi9N5gVe4tl+K3Zsn8+6Tba2X3vr7Vo9wPF9L3jFIu7PapuIA7SAOwB2FfHFrLZKkk08OTlZwCBxexmGS5/bGy9uO+H6HfvGiZ14DnVkThTGcRh5Sy9QQK4f78SJ4979hb32/KvZ843t8LufRmHC41eTy+Uq+eWg05kO4d8R/Hva6dwxWj4JgzBrhq9dL9749tUsvrQ3NTGHOLnyebziPMG50bfzG4xNojBMdvCBsVZrvpzc6nW7bo9P6Vtr6YeX8MjtnQ56U9kIJvqKJ5Nbi/nilFPDONnO4XufO66rWsG0oaPd6/U7U/G1FYcL6DbunJ6OzlQz23Fgfye3+GI4EC3Fk5bL+WZyaz7uD7spzAvb91yAujjjw8VUPZBNu4tTe3Cqmi5DH1ry3rwzsKfyu4LZOeXdET6EveGTW+7Ycecj1XHhcezZB2xET3ogmw5Ggy6MLJs6EbfXMO8Ot12a0B7+/cVuHr5uxd6PXrCczEMg8agFT/DVKln7zXnoXu3WdgTUMengU3pAEJEuWmJjJzXaWSZpoNaMr+KEr1tbrxnbQdyKeeRJPOa282oZhdvAndB3xiLbRbZY4n9hKevdbqezec1G9NdO2LjzEWt1Ox812YUd1dN9bjRZEgHwjR1BL2j+UaNZAfGMQA0VQATGugTxVr/bg20wQQ2HGSg1ZCOPfctOEttZrZEcFt5rLnfdCf0wmohetOCNKVt7QWvFPSD4CUztYgXbdMnnrzxYPVzCeA0kvcL1B1EDeHt2LKDhcrcvI3sDG/BaSJHJaAyTmKoNYfY2Cacb23Wxe68H8+uO4M8ZNNrfwO5JuNlJ7posfP56CvCXQcuD3YknSLk8mn6/jRNvcdWS0msS41625jy55DyYLu3NpNtLBwXqSJJwPemON0Ql7TmsnHvtGASlK7sApFc7MZ8BTkcuDn2WNIhbt42pyxRhTgKQyFONeJDC7UijmmHH5cumWHnBlA3jG7FTozFVmC4jz53CJ5iqganYwVuLxWJK23MpkAMxNSVWWdkuCJkOw3XGRWAt/BQt53a91z9rjgfNwbjZHjWmmzAGgR8GE5BnIG4veDr3yWTOF2HEm/KbvYCBd2r5a7Wsqz2PQ3+b8KlYLVoORUrdwmoNOx/pS5TRLlABvSQqh5HXE/oEaPFf11vwplHAbedzEH+tYXsIm2bgGdHw8k1KAWzV3Qly9n7kk267O474eurzBLq0kKKQQrFLSrz55dVgbZTIgTmyDpNNCXL7tIeA5S7Zp2cLt1MYBnZkmvDXSSub8Haz4ZEDrJXyRYsmchTlKlpfAsntbIBkA1yHS6KkPSBUYbM8V9LCcNhU/7a7vYa+McUGnWFDTclZOKinjmcPZxuB/p5sQo/wNTaB9gA4JZU/6TQmtoM0uSslCQArKCKx53OYsrFGuCC4wNdO6IiF6Ywb+SmhqFESbVAtdgRmbL6Fx8GORER3WrE1HR1XTdKrJZ+f2gtQibpC84IV6KzEoFE0ZjRCHA/LKLyvod8lPVbYtbPiphFSguXb3WFcnGEbJllgbalgdJ0DhkvDlFMDlFOoGVoDJac6Tfx/e9AQvID2a7rFtG524K1tIbu8mLN2fxgzZzv3HNAKP3o8qrd7zTZIuV6zK+gEQSCKCsrcD51X+OaXr/jVIgIzOWYIareIwvUuxMVKrmBfyqmvg+SXhGm7rtYO8dsLvDd2wP3dYTIcHEeGZwUyHGv72OtU0yEhwVa91EgCeYU0oLNhhyglR0pa7zZo/0QHgEpcEefZ2VnH6RmEhxKQlsC357ACxqIbonKA41YJwgLpnmaDSrmqoTSS8wXLC3RADiYRjex6yk9HtphdFF4WRQcxOH5roWkzwT/UmAxXxchoMkmV1y9Z/IFAxgs22+Tr5GrDZ8F2PefRt03tEeJoPHCBuowHGzuOL2HbvxUGrRywA4qyUhSIHc00UJERwZ1b8TWfuKAyCyavaE5TzQgTtaIkTe092fCNMoGfipc+sjbKyHCbkMVP+1AiS2jOkwlZOytwLcjayO2WaLMInW28k4PqU5QmlS5Jb/Xt/nDYk0LE9slULbd65FvWBqEUBbuifXO9hVLGD5ptJiVpi18AmrEQE9rI7Xi7ADNdISBsGEVH+Ua0FDu5zMJMIO1rtAUnWwNI1lIBnmxjwqOm/dRCj/nSZJK/FLkgoSADDir5CXH5d9WoZDMqfM8KinN8nOLMZlGqNRUlZ4a+2Ih5Euwqp1tmZB2Y2Kk5sbNKU+GA8dMdSA8jP8lpJqj2EvHjrDlo2NpEoNqjq92HcKU0V8kwOdArQp3JWuMS1+i0gMwE6N+e+9xNNX57qFbc5Qt76yf6AClvI4hlePRUKPzS0L+8x0QGp83ucNw8GxoTWa7COLnGFDltlOmM47yHdCDXDpYgvfMjdWFth/1m7wxaj7T5jEG8Vw2R7Uh/KC1BjAvGRZU9LkqMUbkSRwBFHX7au9ZdGLyvu2DY2z1pb5N5Qr6c9OJS5Ni80lzqtgcFOw35uOg/ESBg40DzeNuj0TsZW8OChSdXmDQhvCyY0jRs+wJmoHT3gnfs0V4832bPxbbL5zx9LsgOI4tyt30vTlbcdv+VASJpJKK06klfY6+DZ6v+zvT5pXU6fqcFGxes0zKDGuPXKMg1assJcoM1Dtt5EsUy2Z8blq83ydWuQHZqtLEzHsz7KZ32BzJQZ+p0145XvFQADApkPzJcjPaZ8gjaItxdNMOmh20M0a3UlzTGLTEehBrTpCa5vT2cY6ub9zmHQxlYaK1tL7UyUgZWQTVNeHRk+42TaOzWE7GNQ7wKWjdPRC20h9Dib81B+r6a0N8WPsgGYfHa9v1dQXvn7ZYy41iujLDwYKgSppcDuTx2dhrHD4r7qYhnuBieDk4Poo2ejQ7t1ISmh8zSraX8RkMD0OavNwVRITRkKc0nlEiRcVxQtFWRWgEM26bURAvUy0heNCmzYDtMmEH4p5Ojk54mJYmqSSG5XsQdIn2Yy3YdFKSXGderCNOKyWWBWvX9+FDtWAvVjo8P1Yqwa7eTUoqOxw43t3WGEVkTIcmL9Ep0c0KX70pSNJh8qzXX8Jek+AGrtVsVwC3IiAJpAgNJNOa2u+SpgvECYtBDodahSbpCq+aRfCctm0pdoJniRlBsR2zZwksUkejYty8K5pZmBGbmVsGuNIBsD9psg0aJPCmBwos2Zm/U7J6OmqeDZrtnQsn4V8KwiS/i8nCuJj56KRXJHsc5hZnldov33DGYNHqwAI1rU6Jdp3x7ZWJX7SZKgMERHmLpRJS7ZODXxbzoPtOhbdfLQpXtUe6NUkmZhu+d9pWZtt6UhDi8IOYJWCBmpPV6a0s+rgpwSJRoVBClcnh9izOshNEqtwv5wQ234HcxWDL03h/iXN7Zj9UtcDRjukW/9lQ5scSuUQiGKa+3un3wzRrTdInHwxInodvsAbf1+spNUVNpb2OYLc2nRBNr7UCrFZvprEGRSg5f1i3HjtxdufOgtcBor+429Mn4YuyWaPOYoj1FW/BYYSyhVi310bIwVZZjqUDlPGJwp3VjoVvMUNAjM6081pRteY4g1uC345UW+81cGPk2fHVQpPZLg135ZoOGDhLk40EJewCm1syEeWlHwUGBewiq3m4wNOAGfAsbdl3qYngAds470ICztueEhqHcK08CquZzb2k0L1W4ZXa09OlGlKLtHTSs1Vj+3DSsx1V5EdUhBgOzkHJTMUZ3PnQdXW+NDBoHKhMj5tzljGCM18pr1vZef294zxqGSqfqDDU+zjBFzXsmw8Anv2DIJOwXJyLJ4rwqkSBGZHAk/t2r9vD3VWHfs7dZhmpMGzbQuyq7vyzZREuey02RtMOeH0jWDUpk3ago69RKrUPX9uVShRc8gnXO9K0oxlHKtiAShs1uD1QKRu/opRuFm9bC82FokFPbqA4ytlGto2knQbFESaWeVgZKRzn5P4KV7ILhNOhMEdsFFqlh4c5ew98UmKnWppnutMRUVgk0EPUAmgXTG/W6/dHR9QhFM1iX+KZL3xcVWejSUzxUd+llGFRsipkIHeQSod2hoknRWiQ+Dyc6DdpTWVfRPRb8pNJVxHvXRA9VEiZVfDlFWIQOBBXFSStctDBnqI/VMaB1dFAdfUn6u79QTjb1EtHZi4/x9q7LLR2fWerk464yNPRaaZkeltuZBG+YkkW11D6tDJhIcnkNHkhoJxNKyU2vi/EVCEoKmlw8z8BBLS8VS9AfWGiSO7eS0I6TvJwhd52ceeGB93KVMZqXXBL8NxawV6zvody3zhCjMpfIDL4hqL6Zs5CMOsps7dJ8qZFn6g3jVHCNOscKlTTrNMGcLSM2EAsnBFyuoiNr2VKcvQjDJAgTXh1MPbVPe3anWOegO7AowEzaGsrUoB05q5LoaGVCFNuXJXAHWqpOpoj7Y7NXe20vS/zANFV8TNK7bJtSh+nUGM3xo5LRBGrj40Z7D47qF9g4z1+GLtWS0Sy/XDCBKr9h5QBSya6qDFDG11PRqPIQx8tZJfpX5AJ+mFh5vxgr7+oiceW5Lg+qMo7F0HkjwxD+4++yaKuwCM5yabZCMnREyVBZCd+8xRd85PYax5iq7xCmyOfi1KIIpVAe8y13udOZsvmuUNV4nYdyZKQSH+QkRWeYGz2f6RuOyxAoywdUl78acTY1VFTIh3RTxZrLh6gu//owrwzqHB/UVUPjCZhdMVlmhPi0yfYPeog60FzGkrApcxJVn8sVN/bntDLbMTUzLgiFatEP+fjDtDRXxShzOlozhEjyEG7bmEeFytn3q73vlCTP9WhJryp1rjXqHyyzpYRdt7wuaFrpfi/4mbPQJ5tloLm9WCx65jsRQX6f4unxdcXTo1Lj6qjc7qHwcrd3bHx5W6h0/CBb/SFN9I6akLnF47I8spzRO+6ZUU8yfacKleu2anDtVnWO3Kpfrrnr2XXNjUavtrHLZTPRgNwXks7dNtLM3ojz6m97ZTFbhLS/ce9EHmHLjrK1l5i1Nayjwkmhd9e7PWW6InQyZkqjB/1x5wPV5HQPhxLIoOmV1eRURxgG5REGNSNxUIUCl2Iyw0GWax0Wk0LdYS4MYYa00DPN4uPpILnzLP1cKGKUb38ohjYqiWOU+icpNO/DBNb6JQQ5KEkiVLg/l6sQhjIisAUNcFA3DY7QTb0sLIOJIlZysKnbkbEFvSY8b0fTYqUPue97m9iLp5crYB+aPIovUakmwogz/B97wdc2swMUcN8DLbJ55Pm+DYvNfv7pN7njv7ILRR6Nk6jqXCjIs0V3UTgXysen/Y6jDmKKGj48RDroDOgQqXgiGzvd3qiXHvDEM65dt2v3bOOMa9/ujbpDdUowO5R5xPHKjjgNOVLHK4fqeGXK291Bv9nvws6Mcocsh+PqQ5ZjcluGPXXIcoxnLHtlYIEqqg9cVpzdVGApVtCjo5s9B4/5Vp8CvdV1ume9s6MObmbHElnhkJ+oZMoO+WkzOW1MWZVoYkW/bmyWxJYB0kt0SyCMKiGMUwjyBB1LVazTGXflS1Uel720RwNXvsznVY3DrIJE1SBZVUNJI1kzxHQRkg3oduz+lJVpHo0+oEGl5lHN+saMW5sLbZAztw+DVHr/rKijpyzvQbC8wcFUbLBHYUGyjgUGAHe9Y2VVLqxEgzO09TCwy8qO0eRxg3HLDhUXwuQsrbFkuQBMhqNUK/KkC4VkmRRUZe6r6LgVszNDLcZqkXqjxiBVPw6Tt38K2HOYeMTWb38fM1gNkKsqs7UMEYN3WisMIzD9FCTLHC6xCyXHHtiRIUt2bRaWmSczWZm1WiSW4gbltyVf1i9ZlFZoskJNtisil1nZ3WHKJnL38i0GGe7AEs741BxCFsGwykMDRnMWX4BQy2JO2n7D15iBdnz7RzBKQ1bnAYjvwP6esyvmAG+CBGtopBBLWqDTtMw4j81KDmSz7Mxq1aKUCw9jVbQmxrLMO6NOOpfHOODC/pFtA4aXBBDOzspzbIkymg/NTNw3ZWaiqbID7McQ7Kf2GUJMTf4b91zvgnnurIb9aszx7TiWX87vncBLvQ14W2kTHK7GCMyspnsKNXQgqItsmYQbemY+Jckon5tvUE3Vzj+So2fvz++tuun9J/dO4Mu9zXn+DpTNudZP/2giJGJ+2fCoVNKZkVqo0YzlZwCKLdLmwvtMVwv2v8bCwPE959WsFm548OTqgUNx4Xqjxuhellntob2eezYIHo89e/wUYALVCnE3q3VHNSlFxGc8tPpx+HpWQ5O8N4B/amwBxt+sRksM6x6FrwCmXh2lnrYkzF76AOWYY29mNSJM4/H3wPHq+fk9DK0yGLVfY1eASLeW4jfW8IPH0WuEfwI7YCcrBgv15BRMqpen9pANGbkRQKSsczHANicwUfgrFu3gGhIhwqePkyC3oM9B84BUjbX1fIDuJo9zC3mqIXr677aQjhc5WLwGA3ehu3Ml/hvh0uqr1j1rD1h3aHfboyGjPx36f7vfh6/jnt/ujOAfu8d6YlFbvfa4z/CP34IX+G++cws7tgSE3Av4Muy+7HUlPIDYGsAuAZSzB3kUzhgiVwocYNPoRczoj1+BGM6K+hcRA7Ra3c/6GV7wcLAqQ2vQHrGzAlYKcrYoKV7MwKsMLTmlz86KbwizlzpeuF6AV7EprS0rg43Y+eV4ZTtZtpGKCl6WDEeDfaZvJS7OqlWCW0s0/vFYXhRKVWNA8UBjPbKgJOOVcZhixqHGjMP3YLz2e7BexluwBqf+sEX/N7iuh7noz86MZ2es1/1sqDFGr9V7qX1n8H2liTPSB7QOUjeYi5qqnuyDroHo/gSlFeXqo/CDF5/yIFWyoS4GMf/4Eha7bi15YDVq59ASNGGUG9iE9iV3S0FE3EUQD+3ge34NiM+8OCmFsYIXCAQbhBG4xjoYZTzAp5utFvv00dNHXz74krVa9FIWsNAQSED6pPE7DFdiM9CVBJnSXvXOn275RQjW6wbsejAJeum7jeqDZTy181/xhRe8/SPjPsPjLVuguBAswCWu4Nvfg00VshCj1h5YgM7bP7neEj68/efAc8K4jVZFiZ0S86XQWFh88xy+qEbmCkKzZ3jbWemW8uQFdK5bG4dW8lkYoWUJ5mmeRQswP8H4QBkoChwgsCchTnLhfR8W+D1vWinkovBSn4X2hmL52jt4Szc8wMrK5bx3Ih7oTTQA6pi9OMcuFk4+q50b9hedWhcNxEe0BQWLkY+ouoI0wpsSauJ+hRreZQVipsa0qwTge6cmPEswhtFQ5Y63hq7nxhLkVqR05nK6D/EiLPAa1Gw1lH5IrqpQWtsgH4eACqC95fRIQwpag6Pm5JB6701SRjn5Qz39vgqMq6UzwY2LvI3joUtsbADdo1E7r4fwMgxsv5FKuMKckZnUpDFikFv9R99PACgGyzh7ENjshH0Mr1+xT8Chsq9oXXzwyFDWjzrFTanchZc8cHg50pswAhZfgHwJWb/D3Ld/tOMDE+CvNwp/V3d6yvZAY0AQHGSjKmcmCZgWHtPYEmMiCX8YotuCxqsS2qnMKlUaOUGDR59LXSV8AyjPhVBIXoQJ0nYHoEoFRU94nM6/gqTo1PCFBuklHhUyIL18+3t4FB4HaquB+irmJiShc44FxTVQj2CzDJyADMpxqlhJde4XYK760peE3vA5bwKJYKS2kRFfRDxe4Rb+/J/+N3vgJFtYox813ZkfE3HGAWEwDQU6jouKN1qCAxz+/NP/EP00g0Eqx0x5Pnzw9K8eVStP0vGa8qzSnEw7KGJoUWkFHKFHHwdLWAXQmABN6kngNj9l8o0d2YzOmdmRHxqaM+M5LUd5QHY8lODrHITI6X/o9cH8xLCgE643Pk+gU7hYyEf2xktwN9CeXAEKTsKjGAThhvu+s+K4fwvbj7nJRFJOpllNEo4GMWY4U9TmOpSf/vmfMdaEbQOwJxaAxxbWox7OfW9po40Ulk9Ck4ODzkEkB0UkNbEkVj7hx8km1fohaCGk65di3wrWgiJmca4gBSy/lstrMJyECo8ewyeJsRH/8aT1FH0Mnw6Jfn/uy5afz/0yUPF2Lhs8h0+HQMkTEbL1A/mtUubrH1NGUFWgIAd++q1csp9/+kcM5IZ4yy4uik38QdzUZl+CzfH2DwGzfXy98CLYBnqPXMdijtFxx4Z365BtY8zzXQEVfW8jKS22AengqM3+estdG1h4CSIlwlY2S7YsCNfziCtGK5Ednz1+/uKLLx8/+LxKegjz/gjxYYiM1OZHLGkm8SG5IUUtu7LZNvFQboLYbrOPt7EDwgR1tpQmTcE9zZR5wtwUi1Y4VmjqVKhbBWsbaOtffveb/2wG8AzWRjfmuYBSzdqIaSohK5EEaV7G30UjXqLn+DLohTg89PUoouMDSp+lqCF/vv2How15UZSqwaavJapWNfj83RWV4eSmdFcIGstTJJkDpL6nU/UWdaohbicwFk9ms1kCKDUcP4z5E4xh4+SNCDE+FJMTH88N1NKhKfCtxbHJ4E3ObyCXJuz2DNqcu6GzxYRrG0Z+5HP8+PHVY7fuuY3pDdhC9uTRbBeFPp8EW99v4rXa9GnfZA8/+XS2E/EL52pi3baatgvW9jMPo5UTUjhNO7gCAyiKxVfo9OLXzx7NyN+b3rhx8gvgSmDSB88eiw+/OLlhx1eBQ4xPbAqqrb7mySp0mxiroFuPG5hQF5MIZzv5Fu0aHGi332PaGBYVm96czbaBi94vdxu7sC1bfW09FDU6LXQarW9nlr3ZwG7QqcmT7+MwsKZhGwHM/ur5F0/bIHK8YOktrghoY7pPEYhm9qXtJWzBE6BSQjGkG4lx7dwZLhWmk652rmwYtRF8HWDAaNCFN3Z7gW9E18JsYyCAQafL7txhCA5mYJ3AKpysuVV45odLL7AaO3OX9lOQkzDr6FM8zCtzRTDAzagdvmqwZIUVZDsx2ESN2gRVaE9cWryIA1sHzJ3e2GebtOL+BpYu3SicIFHYi2m2XfSgvm7sxOoks9t1i55ZjSkQOAgWufCzNXwnekbWa9uuW7cwtALtiPVfeGuOQTcxAt6Ti/+doZsv39Qbs3MdRMTXwFsKSrPX73Rwo1LUwFWzN/yzZO3X48ZOTrEev3ljWQ3oTOKufvL1nXvnNevbk2VzPTuv76w71sS6Y683U6tp3cPPfoIfz/Hjkj7W8OMP2xC/1KwafLnVP5ta+6/X3zYMBBbr5Fe4IQkMjxQhUQj4JVPP20n4eYh3zj8ngqtbPLaaO/AVJ1avBfrBSywsJwJnFqcZwbcrTL5Z0oW2mqtwG+ltvWCb8OzBXie7I8aH5vkJXB2FPz54zzkcjaM2RgHPJ6Bur+oXBqIgr9pKXN1FiI+DxG8/pVjFJyGYJQni2vrq10APC/H9ogQXA8yFMTBYlJ+jh1130tZOm3QqMKwITN1PkXPaFA1pTOSHu9ZHlk4uXgz+ngfOggGN07P4JkkWlAe4Cu0gvKw3ztO3AEbwXwDTmF0AIV8IMk/Cr7DS4qEdg1zQiP5vH7T+ptM6Q7KHZtO8EHbCDWw7MG8TLGnF2+GrGbLgTrA8CNSNB1YN9EbRC83gX4PhrZehD7qPoakHTSOY7BR3R4jFwL4QPgJwtLeZh+CjtS8jL+EvAASN3ZiGrwyxKUWMPUt1mIg2SDUGggd62fAIZY8tFpmuHsVv5Fe01aEctTvZG3mSZ2Z1rGkKH4V/G2tuA/fhyvPdemIT6Jj7oP/rDZpP2pq/5s7DcL0G86Fu4RJa5hT+rqHW7mmIdvBm64ZqbaCROaqQbtmoOtmtfLE5P6g1ie0Fn2nyDt8SAeDe3PyhIakJmxHKUpXxGXLFl3wJhFe36tbdHzQSaf/i7v2/vb3b1xtvvv7m22++IVr55pvbd6zGXasBctBbAnwNcto34iA6Mat9frt774Q+WCV8RdjsNYUzB0+DnTBMxldZB9ikTuYATgMNEkFNaDVYnz56AWiRniTHY2nllS52As1Z3gf0rd4+p2H3pCY1JXtD2xD9xU7qXhQbmn3UUEoWpwfft5t6Q9otN588auNIRpPPUdOLJqjgHmw2uTE1ODgk6F0gVGB5Qc7qZzwszD5ZU7HhS9TO2A8musw3xPCphcMt214Q8OizF08+n32nm6Gq1CJnnML+MvRujRIGql2gTdhiwgE8N7OSIV8Z0dpc1ArFDZo3ev4w4iIM8+zxU/TBaGmlawjeIozF3v7BB4kcg8BZZkFH4YZpzSNwOreU+chcLM07inFJYcuUb6QuJi6NYOuBjHHOg0I8Bz//9F/HGJMFJRjG6AK84ldueBloTgA8QW3xCOtdrIYbyj3NJcuuDW5oHWGpYJbGAuWCdt8RWZmmFZCGmjvpQ2cb1xvNYYeoLseG6WCZYb7xglndhEECWOohwDej95O//cbdDZrj/e0T0BggEKFzIxWOj9QezzlLcCPZALY0W8ZU6kwVS2v8/OyL5ylDEyotWgcwSGAMsDREUyFGpnLAP/8e7cnwJnsexkhhxspZ0vhXYkH0qQPjgPl85474b5tHURg1YK66ZMdtoO45rpWs/f8r174fnwKLpsFS4HbcQQqOAokDz5WyGjkzH4LVXtB4x7GXXPx3Z6+0o5imfSRPqUkewVMaXZg8pcEo8hRxFDKQZIpSNaezhfAhSxmihNIt3EkvcMIIi6XQ3BO4cX9mYIaWBvcbO+5Lw8uypvBZzhn1vMYFqUaTPCCou5wJKnmEjiQT7QuMiG1nUpfingvOzxo4dvApD2b0+M0baCgeNPHFl9w1X3wpqtFhcFEThwuuGbfQCEMjuBOymazjKuBJUO9bWnUt+I9iaqKjqIEo9BPI3ZfTLHT5EpPexS7wuLLLZ1S/cGwf3e2Z6V9gzrctRexZNn/KMKRy9StxSXScmS5UPKFmg6UcE1GNUcIDqvBmd0isi0ambYc39lAsB4xQP7RdEQTJCC5Xo4hkR48o2vZdTgq8NsKSelAuH5EUySS9zDELChdCwthOE448ijHZLEwX0DoBlnY0wS9yPS6qXTehi7aTkKAi/E2lB+hQURc8GgOGjC5dRcIXB7ApY2dUKWiyFzbzPSVvSTqnRBiTiQbevq1H13O5nV4ut6MhT4tRhTs4LYB79y+BvGlpvDvuX/INT0TdzZHT6P0lpvFFgmlJ/uOBCYzyEzhWE8b2BX9y9Uzowk/BknaBOGmigv4lf3zXKNGH0vHkqDoEBUrF0eCZpqjQj9q4mYYEIKQhFbBym1PGRrrUVFLPNW17WtveIVsWRk5VZd4AEixo2qul9m/QLZi/YkWPNIIBaNC9OZsFvRTM52DLYn1/CitmAUYbPCwhQHVT6A8qU5+MgQf4UODJ2T4m9cpmdUBcr69aG7I3ZOUjLOgEPjbF2k6C7j41xHE8h8QpBUbI4rAxJMIpSpxJ4vc2yaWsFuwpbfM0/gAqMot2G7YKqbALZa3IAj4ghSwYnYTLpQ+qMISZXqDxQTWL06yD0NcHOkidmHaQ2vpAD1GPmLcijsQpNSGORCmzH47CCCgqHRKjlvWCXaZZYA2MfMhyE72zAMdQoYv865X5nvDbQV8QM19SkYXQ+9qeyt+siNkJidni9soGFHq9ep5EdRVTc2dpELoxddswBH12MXEmnt7td5Q1vJ7JwDS9xkpEmMrdbqO9sd3neEVdvde0Olaj6YLJpTcVkArtVFyN2nyy9f1fg3UJEK2WdXdNfwGQHjzO2V47JCJkUmmMUxZuJvJw961uB2wwawpt+OtN2qa4Etjih+QqbWF1qRMWwWXPjBi2MgkT4hUaNZEEJOpCK+knUeg1svafiNLOQz1k9WcmuS9nYupYaAnrbbv4neoq4Rto1plaGUlI2bi7SzHQU/wlYcus37SmtmsGtz+ypgCtratdXFd6iOWP8AW/Ler4gJZKKg4cz2qkT0UvlGfcj3k5DuK3iwo46EZ5EZlhR2IjIskPEhgedDMsHqAn1G4ZaoCNjpxlikgVWKsIz+aq/zI9HdmXsw3+wvMneGlcvW6Sp5mSA8XRtNpWI1Wxdeh93sk05LMwePsHPBcGnUMwvO2rEM1jZJsUrrImTCWns8GdOwj3XvfNGwQPu2Wo4E1amQyjoDHbhRFwSw+PgTlS4Bgx18fgapgc1Ox2QCN1p9TmiZ2skFTq3ab4CKbNsNOEVw2NnpHZolmO6zQbBEeUWSCZfIZ5mpydJWcpd0S45ZrctV70+pPhGfxjyZCCB0T4FBi5oaAnWhYcTEOKSlFZKPTA3I/65aBZEm25lItAi7NcXmhayBOJElFRc2Gp+IX8CV+Rp4irYhmOIDWwLlC6T3B/mzShCWwqLmWT1q8p57CXvx2c91SZTNXrSkik6Dn+xjaN0Zb292zWTQnlIZXHMOuu1u7rzrfKub5rEUe4ImqyuaqXNxPmjBAAZG58TJaN1pgQ2h9r8DzCD2ipSW6VIcyFB+6mf7Uz9orKNApbAttm8j3WdaJRVsH36cJlHI89KEKUmgS5Xd3Jue0rUzhiaxtTrROeiJ+pDRFXxdad2bmTVVJY2ATIWuyW3hdo4EDXm6rrnTt6ItYEhGpJVB3nwkEmjUyp3VcCEb0ZDiBePiLe098BeuIV1dgdhN9COC3soOj0ptmgscNl1yLCVkml0wuwpS/e/tFGv0BQSpxwlTJp35tHWc4FvUAehcyOQIfYbeE2WrrgYyw3okJobW/qIj32QtzV18bjS3XLytH0EQgbhny0xCLBFyHW0/3802+z+uSff/rHFMF9MUknsMAU+w2TqPIk1CSCuYmfTZJQUpeuXWjSTQ2gJ5uOH89EMBD2A3s1dtQCpqJX6MnrGrBk/Od/+HumisNlvZ41JTD4owbyVwSsqRwhVym+3hDeNVVkTiXTv/rCKA3P7ArECaZzGCUuUJJV5u+DEZ4uULXqj54+fFyNzyE8LiQeogI/xcNQibBfJNnvG1iIH/OpnVt3tWS4bAnGs8RiIrZJas7PvYDsHFyitKCisUvf5OBjctq6i4t5nxQoAAPIOKR4Rqv39k8TBm/o2AZ8atyVlTQZ/BQZTaniftKYguYcuv/jQXK/BIVaeqoAwN9VhUaqR2GqMliC1lkY0RBOW36rgA6cj3Mw11F2qQBPJeMG/vSkfIAvsKC0MAB1qAAvAqYGfFFYXzUErVDJLFSvinHm3nL2LkU89+hHqujMFn3QV2SxKIJSHdgXn3yS9plYTD7Wn2qleUZKT9x6ym7vgDX3tfPbO+K+ffHgP/2yl5n4o4vUsA/Mc397ByjuxSrc3iGb7EuKazWiIIK7vcsITlj8biMFohEZgJdcBJ8UceOYilDgc7ar+6rbC+g2OMIYpcPefIeXbuI7RxlT+8oa4fSXZ2rp6ZcszI/WmaWDAf8Si3Jh1lSgkyX78l1loQ6pOwECcYL+JjiA9HEYRRXnZ7Ry3u9KYp/GGAi+qUxHVW0iK+3r1p//jxgmq8gH+k/t0ftMKVFgAhSkK/C4InS2zOyhZpL96tHnj148ylllJ9ZdREOlDzPD2TSM54gKmb9541WPylGrKB+Nc+QhHb38FAuxvGCJBziEs6NrdzyI8HH4uv7KC9ym54RNoPCmP/eb8XbelFuvXCHyqEQXDLboTrf8NQm0w2HlEBiaZXisI2eTwRD05mMsNNJMFxiW0oLZOzPjBu/z6TZs+vk8b1QC7img59u5MQjMKX0nz3UY7+V8qY0qDoSNfbAEgQAuG6i18ng//XqqcQxMi63Vzp9FId4gGiZRdsjWKpQPmgdttGg97VsIZEqrn56KSh3VackOK/p2eTHOvg3UOQozHG04qdohoVJPteiaOAddkpT2M+O7vcDD+FjZpojQkj8sA11//u1/g7/wjzrhBfY2GAZhQAUm8PxLfuHhbH7Ygg0WJ2//ADqIU/1y5CVhGyRRtnGGr0gWS97z0ZEAiYkI/PffCAR+bcMeyeMrYuiv6PwNiIoyI6Kua1g6tFKlSYURdB2mwvYxlwl/2wVR/Pv/KddICI4LYYPCA2lPaTiaZlT1oDupA3SSwo2byucqzJtZkuDylFqO0j7IOiF6sxQL0VOc0S1HUwOgzT18BfP7l9/9l9/93//191ZTqyW+a6FxoK2GsITxAfg9wiUzzt5dqZNWb3/fBml/F/FrpodwKnk91BPdAkDG6g/Ts1tELwUF+G6C4yHeWetr2k/59fuSyEYWwVDnyyI8VuaRWMQpXhvQ2Bd1aG6CSnFq1KHpQM2ipURgdhzyUC5QmK8FKYXJ/bf/TA508bSkCCga8EviisdHxARPYroNZjTRZtekMfZmbCt81dgZlO3MsrBTFcn+/Nv/WEGudMJPHfojgn2Ap2zEGqQXUbTZo9Q2uaLwg6x0iLg8LBfFnAIQ5CWcyJWq8hYMMUVhi+sMfxRXTevojHeRlMkwMZWgImcl7nAZwRQG41YTzZVL/ebNbl+y3P/m8vs9zYKH3LBsr1kMqQfeYz0+hLb4C0xxV8T0HdT/B0fpRl7rKUNq/z4pc6UGihLYiK1pmO0KY2vGdtHUFkZs0RqcCfO2KHrxhZSD3izfF/NakdeIvKygRDvSlp7i1b0KOjBqOys++/rbabEkTUs+F8Pb6ixpFuKW0W26N7Eqti3wwPMh2djUQfOTDKzeJzqKTJBOuCxmKwKiWma9ECwtmXhkX9JKk1rMjhKXl6ZmyT/VjQ5zXaoTSarFD8IrUI1UClieEi7NANOpv6bqcZOSqiqqR0s5SxdQqucU+i73XssGGF4AkO+T2Q8EGqNN+B32wPG3oMnqPxh5CSLSJzOpk9LYlznbrDOgYnTHKAj2VgJZD24dCwPV6xNlzCIA+nBsbyfiT7KgIE1XfLwegDqqhsv15o1YiTdvaEpv3hBWb94g+OleP0dLlZiKg+i4dpqSv5ntjEpnUGsza0jCIWO/d0h2rOyr9GSI0qVxGYMUR1U0dJ9ISKIH9o+LQeE82pj+o5sCrEn1KzVnHSCVbxw9teeein7gPETV/c8//dbQ9Snt37X0/Ig216oRBV6YxQH2ENOI3LqTcl7zh4ae0tFPqRmN8bDae8dYP9Kj2EhnKCTB2D/MnFl7XIOZ1vH+ipw7EZBB7BoT0+1TidmcK1Aa0qYfysGYYs5cxXt7kCpSU5UG0oLORSCqSDP7qWuxvcJnSO/CsNX+5YLjs6qQeIaiso115FSfPH7F1EFV2kCDH+Whyw4HgFfncyRcCUmk8svglAXJV8VDLyufcBSx7+xaJRFyz9+opPeLcnDSqLOkrTT6LXwsFdbep+HwfXV0nX4zSc/n6OF1acrv9QCxFibOnNv87Rm7Uu2MUjOv9fMNS8wmunRigsVddCctu8vmyEfFYrqspn4Fq0JIUF9DouArMuzExRiGdtevBTCml9V+7iq6mtcBQG+0BP6OECW7zijoFBUWaFWRVJLNyMqSoq5MCOBlEtQIizeqpJd6L2WY8VVJsg919uC2SJsLrbHPlFok7xurOouQXmIIxIaT2rM//xMoJNdOL7kCdDm5jNtA3PSzjbXrrXT6pR88RWYQiyh1AcXSGoWczjW3Ox3tklO+xhjwm28Cq5Gma1gS0gIYC1ZE4Oy48fN+mLkxdHjQqHsvxJ7MG51l6ElWxN5MK2LTyNFzXPCSg4iFCPfKjp95QRrG/lBkJW+aJvopHGORh3ptcZGiKByhW5F8WxJgZGuUoi7KwQvokEGAxupkouCVEGCu4H2deGEhvK64+1HtWeG3n3ngHnUxpPmLOnjvonEOpuSWM/1+svQSy9s7zUbQay8b+9zxi9tHXO1o3FqJN+7ST0AUUT1IkRJG+stiffk717njGg8lotqJjbIsZO4usPSKo8I+fiUPUBu7ZtJJ+dqLYzMPUdDIQ9jidBMdaIrzB6Me+Xz59o/sh+3bP8iEJWUrJ/nj3U2VKwTCbrIQCFEcfXDC2I7b7Lm6NQwTLOaVYmBUCamH/Qs3biF94G/mxVWXRRXWfySmV32DVDV16z9+TTfzvTNhj43fpuz2xP1+xnkjvJoJQy+H7vQTS3XFbLxM0HPD/G19Zfd9HU3tJb94p+i/26lA+Ohzavnj99efmrruBtrczz3QT6PQrwOOJOYtrM+e4B/1m2LyB2l65hbSCbD0djkerdOJionRpY3zUN4TLCeOl0Sfs2dE+Ut193Xu0uH3gyxu0MQ33FUjOOpqbGOE0qsXr1GPwA04CEqbB0vgtuzKhfz1r9UipuyWh/cWN/rByzZ7aTtv/xiyGYgDLwHcQG9tojDhjtBo9SAEEQF0wsWvpVRc6rnxAkNxvPfh9afq6Byrm0e8Goeu1jvyQs93OdT3QF5WQvuWllMah/qu3ba/AcmN+xZ5PF6GxoaVoyJ+pkrD5NLb8Ac+mSaykIVMOeajQFcX2JajI44cCv+GLqGrN0prabT3WkgifI3RqFTeqzJ4eJ6rjdFrmKl5VZSXXlpanQA9SGM8APlwZKdcveQjWdptJiVVueYgAgH0cLYq1qmmktjLGP0kql5V57LwYXuzjVd1WaQvV2UrT8jrDYQDq6arBSbWM2olzHR0NCxMMfz802+0nHjRfd/Std/CQTcsry0dvG/szYsvt0L01cn1Xu+zG7DFf8qLtkhKWbd327bnioKtknEqK7e+k+mWqorm99zfYpWzXs2cvy1RidqMkBFrdXhV6fvDh13VNROZvj3cXt6jkPWQBw+FPkmvU8jey4OG4r0KeNLqmkd6MFEuzA+8Y1kS9hHHZ/8V18dQ+Q7NB08p3pRkncEiCxT8G9AGIIDAGUby8uKQ1ZURGirN2Tj6SKwQDM0dLkETkG/KiyjE6HuKyZTsnox5F7fJfGHshqyHqNgL4TmaElNOXdr4zCYNLmr43u/QrYCg6vtKKxuJhj23KWiisqTRTomCWXex7V3r/vGli7TqJ9ZdvOn04JTfo2qx5Kx65nRlvHmhDqtXlpKkl2scvteIIgnpmWrnanIBVGPc2HEx1c67yVOS2UlII6lxoRZA+udLchFdKri4KL8URlsH0frAQmR2RX4hlA11oKbmQkb4i0x/kbH8V7G8JoMDr18d4nU6NozgNOL6a2EGVlwtdp89BEsITEVgdlGnAqpXu03sYO2svmvURx6Fh7+0YwJ/gdR9Ov5ONinQ3sTKLhCg26M/0An4g7uV2l7VLPjii1998Vw3xu6zR3Fi409XkvUcvGt5sb5EOH5+ntUFxhTqlLwaH8WsZErm64xhpb4Ps3P/hVoEULGP8CYpNApR5NctecmU1eRgROHBmtwlUzve3kR0+5Q8YghomyWx0z3WYeWLG/6iI4kjqx9miOw0ana9kxjFyCQUByPXyGoaKQjoeENeP4W/0yivrP5/EFVz9ha2AAA=")).decode("utf-8")

if __name__ == "__main__":
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print("Cuponera escuchando en http://0.0.0.0:%d  (DB: %s)" % (PORT, DB))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nChau!")
