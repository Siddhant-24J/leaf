import hashlib, hmac, math, os, re, secrets, sqlite3, time
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from typing import Dict, Optional, Tuple
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

# Load .env file automatically if present
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from google.auth.transport import requests as grequests
from google.oauth2 import id_token
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse


def env(key, required=True):
    v = os.getenv(key, "")
    if required and not v:
        raise SystemExit(f"Missing {key}. Copy .env.example to .env and fill it in.")
    return v


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}:{dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or ":" not in stored:
        return False
    salt, hash_val = stored.split(":", 1)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return hmac.compare_digest(dk.hex(), hash_val)


SECRET = env("SECRET_KEY")
ADMIN_EMAIL = env("ADMIN_EMAIL").strip().lower()
ADMIN_PASSWORD = env("ADMIN_PASSWORD")
CLIENT_ID = env("GOOGLE_CLIENT_ID", False)
DB_RAW = os.getenv("DB_PATH", "leave.db")


def resolve_db_path(path_str: str) -> str:
    db_dir = os.path.dirname(path_str)
    if db_dir:
        try:
            os.makedirs(db_dir, exist_ok=True)
            # Test write permissions
            test_path = os.path.join(db_dir, ".write_test")
            with open(test_path, "w") as f:
                f.write("1")
            os.remove(test_path)
            return path_str
        except Exception:
            print(f"[Notice] Path '{path_str}' is not writable. Falling back to 'leave.db' in current directory.")
            return "leave.db"
    return path_str


DB = resolve_db_path(DB_RAW)
TZ = ZoneInfo(os.getenv("TZ_NAME", "Asia/Kolkata"))
DEFAULT_TYPES = [("CL", "Casual", 12, 1), ("SL", "Sick", 8, 1), ("AL", "Annual", 10, 1), ("UL", "Unpaid", 0, 0)]

SCHEMA = """
CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  title TEXT DEFAULT '', role TEXT DEFAULT 'employee', active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, emp INTEGER NOT NULL, kind TEXT, type TEXT,
  start_date TEXT, end_date TEXT, part TEXT, days REAL, reason TEXT, status TEXT, decided_by INTEGER,
  note TEXT, over_quota INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS leave_types(code TEXT PRIMARY KEY, name TEXT, quota REAL, tracked INTEGER DEFAULT 1, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS quotas(emp INTEGER, type TEXT, days REAL, PRIMARY KEY(emp, type));
CREATE TABLE IF NOT EXISTS adjustments(id INTEGER PRIMARY KEY, emp INTEGER, type TEXT, days REAL, reason TEXT, by_id INTEGER, at TEXT, year INTEGER);
CREATE TABLE IF NOT EXISTS holidays(date TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1), quota INTEGER, max_remote INTEGER, max_off INTEGER DEFAULT 2);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT, who TEXT, action TEXT);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  ip TEXT DEFAULT '',
  user_agent TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
"""


@contextmanager
def db():
    c = sqlite3.connect(DB, timeout=10.0)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def today():
    return datetime.now(TZ).date()


def log(c, who, text):
    now_str = datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO audit(at,who,action) VALUES(?,?,?)", (now_str, who, text))


with db() as c:
    try:
        c.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    c.executescript(SCHEMA)
    for stmt in (
        "ALTER TABLE policy ADD COLUMN max_off INTEGER DEFAULT 2",
        "ALTER TABLE adjustments ADD COLUMN year INTEGER",
        "ALTER TABLE employees ADD COLUMN password_hash TEXT DEFAULT ''"
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    c.execute("UPDATE adjustments SET year=? WHERE year IS NULL", (today().year,))
    c.executemany("INSERT OR IGNORE INTO leave_types(code,name,quota,tracked,active) VALUES(?,?,?,?,1)", DEFAULT_TYPES)
    c.execute("INSERT OR IGNORE INTO policy(id,quota,max_remote,max_off) VALUES(1,4,3,2)")
    c.execute("INSERT OR IGNORE INTO employees(name,email,title,role,active) VALUES('Admin',?,'Administrator','admin',1)", (ADMIN_EMAIL,))
    c.execute("UPDATE employees SET role='admin', active=1 WHERE email=?", (ADMIN_EMAIL,))


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. CSRF Protection for state-changing requests
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin:
                host = request.headers.get("host")
                origin_host = origin.split("://")[-1].rstrip("/")
                if host and origin_host != host:
                    return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})

        # 2. Process request
        response: Response = await call_next(request)

        # 3. Security Headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/client; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "frame-src https://accounts.google.com/gsi/; "
            "connect-src 'self' https://accounts.google.com/gsi/; "
            "img-src 'self' data: https:; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        return response


app = FastAPI(title="Leaf – Leave & WFH", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET, same_site="lax", max_age=7 * 86400,
                   https_only=os.getenv("COOKIE_SECURE", "false").lower() == "true")
app.add_middleware(SecurityMiddleware)
from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    details = []
    for err in exc.errors():
        msg = str(err.get("msg", "Invalid input"))
        loc = err.get("loc", ())
        field = ".".join(str(x) for x in loc if x != "body")
        details.append(f"{field}: {msg}" if field else msg)
    return JSONResponse(status_code=422, content={"detail": "; ".join(details)})


# ---------- Pydantic Validation Models ----------
class GoogleIn(BaseModel):
    credential: str = Field(..., max_length=4096)


class AdminIn(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)


class PasswordSetIn(BaseModel):
    password: str = Field(..., min_length=6, max_length=128)


class ReqIn(BaseModel):
    kind: str = Field(..., max_length=10)
    type: Optional[str] = Field(None, max_length=20)
    start: str = Field(..., max_length=10)
    end: str = Field(..., max_length=10)
    part: str = Field("full", max_length=10)
    reason: str = Field("", max_length=500)
    emp: Optional[int] = None


class DecideIn(BaseModel):
    action: str = Field(..., max_length=20)
    note: str = Field("", max_length=300)
    force: bool = False


class AdjIn(BaseModel):
    emp: int
    type: str = Field(..., max_length=20)
    days: float
    reason: str = Field(..., min_length=1, max_length=500)

    @field_validator("days")
    def check_days(cls, v):
        if not math.isfinite(v) or abs(v) > 365 or v == 0:
            raise ValueError("Adjustment days must be a non-zero finite number between -365 and 365")
        return round(v, 2)


class EmpIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=3, max_length=254)
    title: str = Field("", max_length=100)
    role: str = Field("employee", max_length=20)
    password: Optional[str] = Field(None, max_length=128)


class EmpEditIn(EmpIn):
    quotas: Dict[str, Optional[float]] = {}

    @field_validator("quotas")
    def check_quotas(cls, v):
        for code, val in v.items():
            if val is not None:
                if not math.isfinite(val) or val < 0 or val > 365:
                    raise ValueError(f"Quota for {code} must be a number between 0 and 365")
        return v


class TypeIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    quota: float = 0
    tracked: bool = True

    @field_validator("quota")
    def check_quota(cls, v):
        if not math.isfinite(v) or v < 0 or v > 365:
            raise ValueError("Quota must be a finite number between 0 and 365")
        return round(v, 2)


class HolIn(BaseModel):
    date: str = Field(..., max_length=10)
    name: str = Field(..., min_length=1, max_length=100)


class PolIn(BaseModel):
    quota: int = Field(..., ge=0, le=31)
    max_remote: int = Field(..., ge=1, le=1000)
    max_off: int = Field(..., ge=1, le=1000)


def user(req: Request):
    token = req.session.get("token")
    if not token:
        raise HTTPException(401)
    with db() as c:
        row = c.execute("""
            SELECT e.* FROM sessions s
            JOIN employees e ON s.user_id = e.id
            WHERE s.token = ? AND s.expires_at > ? AND e.active = 1
        """, (token, time.time())).fetchone()
    if not row:
        req.session.clear()
        raise HTTPException(401)
    return dict(row)


def admin(u=Depends(user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Only admins can do that")
    return u


# ---------- In-Memory Rate Limiting with Auto-Pruning ----------
class LoginRateLimiter:
    def __init__(self, max_attempts=5, window_seconds=600):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[Tuple[str, str], list] = {}
        self.last_cleanup = time.time()

    def _cleanup(self, now: float):
        if now - self.last_cleanup < 60:
            return
        self.last_cleanup = now
        cutoff = now - self.window_seconds
        for k in list(self.attempts.keys()):
            self.attempts[k] = [t for t in self.attempts[k] if t > cutoff]
            if not self.attempts[k]:
                del self.attempts[k]

    def check(self, ip: str, target: str) -> Tuple[bool, int]:
        now = time.time()
        self._cleanup(now)
        cutoff = now - self.window_seconds
        fails = [t for t in self.attempts.get((ip, target), []) if t > cutoff]
        if len(fails) >= self.max_attempts:
            wait_time = int(self.window_seconds - (now - fails[0]))
            return False, max(1, wait_time)
        return True, 0

    def record_failure(self, ip: str, target: str):
        now = time.time()
        cutoff = now - self.window_seconds
        fails = [t for t in self.attempts.get((ip, target), []) if t > cutoff]
        fails.append(now)
        self.attempts[(ip, target)] = fails

    def reset(self, ip: str, target: str):
        self.attempts.pop((ip, target), None)


rate_limiter = LoginRateLimiter()


# ---------- auth ----------
@app.get("/api/config")
def config():
    return {"google_client_id": CLIENT_ID}


@app.post("/api/auth/google")
def google_login(b: GoogleIn, req: Request):
    if not CLIENT_ID:
        raise HTTPException(403, "Google sign-in isn’t configured")
    try:
        info = id_token.verify_oauth2_token(b.credential, grequests.Request(), CLIENT_ID)
    except Exception:
        raise HTTPException(403, "Google sign-in failed. Please try again.")

    email = (info.get("email") or "").strip().lower()
    if not info.get("email_verified") or not email:
        raise HTTPException(403, "Your Google email isn’t verified")

    with db() as c:
        u = c.execute("SELECT * FROM employees WHERE email=? AND active=1", (email,)).fetchone()
    if not u:
        raise HTTPException(403, f"{email} hasn’t been given access. Ask your admin to add it.")

    token = secrets.token_hex(32)
    expires_at = time.time() + 7 * 86400
    ip = req.client.host if req.client else ""
    ua = req.headers.get("user-agent", "")[:200]

    with db() as c:
        # Periodic cleanup of expired sessions
        c.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        c.execute("INSERT INTO sessions(token, user_id, created_at, expires_at, ip, user_agent) VALUES(?,?,?,?,?,?)",
                  (token, u["id"], time.time(), expires_at, ip, ua))

    req.session.clear()
    req.session["token"] = token
    return {"ok": True}


@app.post("/api/auth/login")
@app.post("/api/auth/admin")
def admin_login(b: AdminIn, req: Request):
    ip = req.client.host if req.client else "unknown"
    clean_email = b.email.strip().lower()
    allowed, wait_secs = rate_limiter.check(ip, clean_email)
    if not allowed:
        raise HTTPException(429, f"Too many attempts. Try again in {max(1, wait_secs // 60)} minutes.")

    # 1. Check master admin credentials from .env
    is_master_admin = (
        hmac.compare_digest(clean_email.encode("utf-8"), ADMIN_EMAIL.encode("utf-8")) and
        hmac.compare_digest(b.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8"))
    )

    user_id = None
    with db() as c:
        if is_master_admin:
            admin_row = c.execute("SELECT id FROM employees WHERE email=?", (ADMIN_EMAIL,)).fetchone()
            if admin_row:
                user_id = admin_row["id"]
        else:
            # 2. Check registered employees/admins with a password_hash
            row = c.execute("SELECT id, password_hash, active FROM employees WHERE email=?", (clean_email,)).fetchone()
            if row and row["active"]:
                if clean_email == ADMIN_EMAIL.strip().lower() and ADMIN_PASSWORD:
                    rate_limiter.record_failure(ip, clean_email)
                    time.sleep(0.15)
                    raise HTTPException(403, "Wrong email or password")
                if not row["password_hash"]:
                    rate_limiter.record_failure(ip, clean_email)
                    time.sleep(0.15)
                    raise HTTPException(400, "No password set yet. Please sign in with Google to set your password.")
                if verify_password(b.password, row["password_hash"]):
                    user_id = row["id"]

    if not user_id:
        rate_limiter.record_failure(ip, clean_email)
        time.sleep(0.15)  # Throttles high-frequency automated brute-force attacks
        raise HTTPException(403, "Wrong email or password")

    rate_limiter.reset(ip, clean_email)
    token = secrets.token_hex(32)
    expires_at = time.time() + 7 * 86400
    ua = req.headers.get("user-agent", "")[:200]

    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))
        c.execute("INSERT INTO sessions(token, user_id, created_at, expires_at, ip, user_agent) VALUES(?,?,?,?,?,?)",
                  (token, user_id, time.time(), expires_at, ip, ua))

    req.session.clear()
    req.session["token"] = token
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(req: Request):
    token = req.session.get("token")
    if token:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
    req.session.clear()
    return {"ok": True}


@app.post("/api/auth/password")
def update_password(b: PasswordSetIn, u=Depends(user)):
    p_hash = hash_password(b.password)
    with db() as c:
        c.execute("UPDATE employees SET password_hash=? WHERE id=?", (p_hash, u["id"]))
        log(c, u["name"], "Created or updated personal password")
    return {"ok": True}


# ---------- helpers ----------
def workdays(s, e, part, hols):
    n, d = 0, s
    while d <= e:
        if d.weekday() < 5 and d.isoformat() not in hols:
            n += 1
        d += timedelta(days=1)
    return n / 2 if s == e and part != "full" else n


def quota(c, emp, t):
    o = c.execute("SELECT days FROM quotas WHERE emp=? AND type=?", (emp, t)).fetchone()
    if o:
        return o[0]
    row = c.execute("SELECT quota FROM leave_types WHERE code=?", (t,)).fetchone()
    return row[0] if row else 0


def avail(c, emp, t, year):
    used = c.execute("SELECT COALESCE(SUM(days),0) FROM requests WHERE emp=? AND kind='leave' AND type=? AND status IN ('approved','cancellation_requested') AND start_date LIKE ?", (emp, t, f"{year}%")).fetchone()[0]
    adj = c.execute("SELECT COALESCE(SUM(days),0) FROM adjustments WHERE emp=? AND type=? AND year=?", (emp, t, year)).fetchone()[0]
    return quota(c, emp, t) + adj - used


def clash(c, emp, s, e, part):
    for r in c.execute("SELECT * FROM requests WHERE emp=? AND status IN ('pending','approved','cancellation_requested') AND start_date<=? AND end_date>=?", (emp, e, s)):
        if s == e == r["start_date"] == r["end_date"] and part != "full" and r["part"] not in ("full", part):
            continue
        return True
    return False


def team_clash(c, r):
    cfg = c.execute("SELECT * FROM policy").fetchone()
    limit = cfg["max_off"] if r["kind"] == "leave" else cfg["max_remote"]
    hols = {h[0] for h in c.execute("SELECT date FROM holidays")}
    bad = []
    d = date.fromisoformat(r["start_date"])
    e = date.fromisoformat(r["end_date"])
    days_checked = 0
    while d <= e and days_checked < 366:
        iso = d.isoformat()
        if d.weekday() < 5 and iso not in hols:
            n = c.execute("SELECT COUNT(DISTINCT emp) FROM requests WHERE kind=? AND status IN ('approved','cancellation_requested') AND emp!=? AND start_date<=? AND end_date>=?", (r["kind"], r["emp"], iso, iso)).fetchone()[0]
            if n + 1 > limit:
                bad.append(f"{d.strftime('%d %b')} ({n + 1})")
        d += timedelta(days=1)
        days_checked += 1
    word = "on leave" if r["kind"] == "leave" else "working from home"
    return f"Approving this puts more than {limit} people {word} on: {', '.join(bad)}." if bad else ""


def rq(r):
    return dict(id=r["id"], emp=r["emp"], kind=r["kind"], type=r["type"], start=r["start_date"], end=r["end_date"],
                part=r["part"], days=r["days"], reason=r["reason"], status=r["status"], by=r["decided_by"],
                note=r["note"], over=bool(r["over_quota"]))


def n_admins(c):
    return c.execute("SELECT COUNT(*) FROM employees WHERE role='admin' AND active=1").fetchone()[0]


# ---------- data ----------
@app.get("/api/state")
def state(u=Depends(user)):
    adm = u["role"] == "admin"
    with db() as c:
        emps = [dict(id=e["id"], n=e["name"], role=e["role"], t=e["title"], on=e["active"], **({"email": e["email"]} if adm else {}))
                for e in c.execute("SELECT * FROM employees ORDER BY id")]
        q = "SELECT * FROM requests" + ("" if adm else " WHERE emp=?") + " ORDER BY id"
        reqs = [rq(r) for r in c.execute(q, () if adm else (u["id"],))]
        adj = {f'{a["emp"]}{a["type"]}': a["d"] for a in c.execute("SELECT emp,type,SUM(days) d FROM adjustments WHERE year=? GROUP BY emp,type", (today().year,))
               if adm or a["emp"] == u["id"]}
        quotas = {f'{x["emp"]}{x["type"]}': x["days"] for x in c.execute("SELECT * FROM quotas") if adm or x["emp"] == u["id"]}
        types = [[t["code"], t["name"], t["quota"], t["tracked"]] for t in c.execute("SELECT * FROM leave_types WHERE active=1")]
        hol = [dict(d=h["date"], n=h["name"]) for h in c.execute("SELECT * FROM holidays ORDER BY date")]
        p = c.execute("SELECT * FROM policy").fetchone()
        aud = [dict(t=a["at"], who=a["who"], a=a["action"]) for a in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 60")] if adm else []
    is_master = bool(ADMIN_EMAIL and u.get("email", "").strip().lower() == ADMIN_EMAIL.strip().lower() and ADMIN_PASSWORD)
    has_pwd = bool(u.get("password_hash")) or is_master
    return dict(me=u["id"], has_password=has_pwd, employees=emps, requests=reqs, adj=adj, quotas=quotas, types=types, holidays=hol,
                policy=dict(q=p["quota"], max=p["max_remote"], off=p["max_off"]), audit=aud)


# ---------- requests ----------
@app.post("/api/requests")
def create_request(b: ReqIn, u=Depends(user)):
    if b.kind not in ("leave", "wfh") or b.part not in ("full", "first", "second"):
        raise HTTPException(400, "Invalid request")
    on_behalf = bool(b.emp) and b.emp != u["id"]
    if on_behalf and u["role"] != "admin":
        raise HTTPException(403, "Only admins can record leave for someone else")

    try:
        s = date.fromisoformat(b.start)
        e = date.fromisoformat(b.end)
    except ValueError:
        raise HTTPException(400, "Choose valid dates (YYYY-MM-DD)")

    if e < s:
        raise HTTPException(400, "The end date is before the start date")

    # Guard against unbounded while loop DoS
    if (e - s).days > 365:
        raise HTTPException(400, "Requests cannot exceed 365 days")

    min_year = today().year - 1
    max_year = today().year + 2
    if s.year < min_year or e.year > max_year:
        raise HTTPException(400, f"Dates must be between {min_year} and {max_year}")

    if s < today() and not on_behalf:
        raise HTTPException(400, "You can’t request dates in the past")

    part = b.part if s == e else "full"
    with db() as c:
        tid = b.emp if on_behalf else u["id"]
        tgt = c.execute("SELECT * FROM employees WHERE id=? AND active=1", (tid,)).fetchone()
        if not tgt:
            raise HTTPException(404, "Employee not found")
        ty = None
        if b.kind == "leave":
            ty = c.execute("SELECT * FROM leave_types WHERE code=? AND active=1", (b.type,)).fetchone()
            if not ty:
                raise HTTPException(400, "Choose a leave type")
        hols = {h[0] for h in c.execute("SELECT date FROM holidays")}
        n = workdays(s, e, part, hols)
        if not n:
            raise HTTPException(400, "Those dates are all weekends or holidays")
        if clash(c, tid, b.start, b.end, part):
            raise HTTPException(409, f"{'They already have' if on_behalf else 'You already have'} leave or WFH on these dates")
        if ty and ty["tracked"]:
            left = avail(c, tid, ty["code"], s.year)
            if n > left:
                raise HTTPException(409, f"Not enough balance. {tgt['name']} has {left:g} days left.")
        over = 0
        if b.kind == "wfh":
            qt = c.execute("SELECT quota FROM policy").fetchone()[0]
            used = c.execute("SELECT COALESCE(SUM(days),0) FROM requests WHERE emp=? AND kind='wfh' AND status IN ('approved','cancellation_requested') AND start_date LIKE ?", (tid, b.start[:7] + "%")).fetchone()[0]
            over = int(used + n > qt)
        status, by, note = ("approved", u["id"], "Recorded by admin") if on_behalf else ("pending", None, None)
        c.execute("INSERT INTO requests(emp,kind,type,start_date,end_date,part,days,reason,status,decided_by,note,over_quota) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (tid, b.kind, ty["code"] if ty else None, b.start, b.end, part, n, b.reason.strip()[:500], status, by, note, over))
        log(c, u["name"], f"{'Recorded approved' if on_behalf else 'Submitted'} {b.kind} for {tgt['name']}: {b.start} to {b.end}")
    return {"ok": True}


@app.post("/api/requests/{rid}/cancel")
def cancel(rid: int, u=Depends(user)):
    with db() as c:
        r = c.execute("SELECT * FROM requests WHERE id=? AND emp=?", (rid, u["id"])).fetchone()
        if not r:
            raise HTTPException(404, "Request not found")
        if r["status"] == "pending":
            new = "cancelled"
        elif r["status"] == "approved" and r["end_date"] >= today().isoformat():
            new = "cancellation_requested"
        else:
            raise HTTPException(409, "This request can’t be cancelled")
        c.execute("UPDATE requests SET status=? WHERE id=?", (new, rid))
        log(c, u["name"], f"{'Cancelled' if new == 'cancelled' else 'Asked to cancel'} request #{rid}")
    return {"ok": True}


@app.post("/api/requests/{rid}/decide")
def decide(rid: int, b: DecideIn, u=Depends(admin)):
    flow = {("pending", "approve"): "approved", ("pending", "reject"): "rejected",
            ("cancellation_requested", "approve"): "cancelled", ("cancellation_requested", "keep"): "approved",
            ("approved", "revoke"): "cancelled", ("cancellation_requested", "revoke"): "cancelled"}
    with db() as c:
        r = c.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        if not r:
            raise HTTPException(404, "Request not found")
        if r["emp"] == u["id"]:
            raise HTTPException(403, "You can’t decide your own request")
        new = flow.get((r["status"], b.action))
        if not new:
            raise HTTPException(409, "This request was already decided")
        forced = ""
        if r["status"] == "pending" and b.action == "approve":
            ty = c.execute("SELECT tracked FROM leave_types WHERE code=?", (r["type"],)).fetchone()
            if r["kind"] == "leave" and ty and ty["tracked"] and r["days"] > avail(c, r["emp"], r["type"], int(r["start_date"][:4])):
                raise HTTPException(409, "Not enough balance. Adjust it first.")
            msg = team_clash(c, r)
            if msg and not b.force:
                raise HTTPException(409, "clash:" + msg)
            forced = " (team-limit override)" if msg else ""
        note = b.note.strip()[:300] if b.action in ("reject", "revoke") else r["note"]
        n = c.execute("UPDATE requests SET status=?, decided_by=?, note=? WHERE id=? AND status=?", (new, u["id"], note or None, rid, r["status"])).rowcount
        if not n:
            raise HTTPException(409, "This request was already decided")
        who = c.execute("SELECT name FROM employees WHERE id=?", (r["emp"],)).fetchone()[0]
        extra = forced + (" (over WFH quota, override)" if r["over_quota"] and new == "approved" else "")
        verb = "Revoked" if b.action == "revoke" else new.capitalize()
        log(c, u["name"], f"{verb} {who}’s {r['kind']} request #{rid}{extra}")
    return {"ok": True}


# ---------- admin: people ----------
def check_person(name, email, role):
    name = name.strip()
    email = email.strip().lower()
    if not name or len(name) > 100:
        raise HTTPException(400, "Enter a valid name (1-100 characters)")
    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email) or len(email) > 254:
        raise HTTPException(400, "Enter a valid email address")
    if role not in ("employee", "admin"):
        raise HTTPException(400, "Invalid role")


@app.post("/api/employees")
def add_employee(b: EmpIn, u=Depends(admin)):
    email, name = b.email.strip().lower(), b.name.strip()
    check_person(name, email, b.role)
    p_hash = hash_password(b.password) if b.password else ""
    with db() as c:
        ex = c.execute("SELECT * FROM employees WHERE email=?", (email,)).fetchone()
        if ex and ex["active"]:
            raise HTTPException(409, "That email already has access")
        if ex:
            if p_hash:
                c.execute("UPDATE employees SET name=?, title=?, role=?, active=1, password_hash=? WHERE id=?", (name, b.title.strip()[:100], b.role, p_hash, ex["id"]))
            else:
                c.execute("UPDATE employees SET name=?, title=?, role=?, active=1 WHERE id=?", (name, b.title.strip()[:100], b.role, ex["id"]))
        else:
            c.execute("INSERT INTO employees(name,email,title,role,password_hash) VALUES(?,?,?,?,?)", (name, email, b.title.strip()[:100], b.role, p_hash))
        log(c, u["name"], f"Gave {name} ({email}) access as {b.role}")
    return {"ok": True}


@app.put("/api/employees/{eid}")
def edit_employee(eid: int, b: EmpEditIn, u=Depends(admin)):
    email, name = b.email.strip().lower(), b.name.strip()
    check_person(name, email, b.role)
    with db() as c:
        e = c.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
        if not e:
            raise HTTPException(404, "Employee not found")
        if e["email"] == ADMIN_EMAIL and (email != ADMIN_EMAIL or b.role != "admin"):
            raise HTTPException(400, "The main admin’s email and role can’t be changed")
        if e["role"] == "admin" and b.role != "admin" and (eid == u["id"] or n_admins(c) < 2):
            raise HTTPException(400, "Keep at least one other admin before removing this role")
        if c.execute("SELECT 1 FROM employees WHERE email=? AND id!=?", (email, eid)).fetchone():
            raise HTTPException(409, "Another person already uses that email")

        # If role changed from admin to employee, invalidate existing sessions
        if e["role"] == "admin" and b.role != "admin":
            c.execute("DELETE FROM sessions WHERE user_id=?", (eid,))

        if b.password:
            p_hash = hash_password(b.password)
            c.execute("UPDATE employees SET name=?, email=?, title=?, role=?, password_hash=? WHERE id=?", (name, email, b.title.strip()[:100], b.role, p_hash, eid))
        else:
            c.execute("UPDATE employees SET name=?, email=?, title=?, role=? WHERE id=?", (name, email, b.title.strip()[:100], b.role, eid))
        changes = []
        for code, v in b.quotas.items():
            if not c.execute("SELECT 1 FROM leave_types WHERE code=? AND tracked=1", (code,)).fetchone():
                continue
            if v is None:
                c.execute("DELETE FROM quotas WHERE emp=? AND type=?", (eid, code))
            elif v < 0 or not math.isfinite(v):
                raise HTTPException(400, "Leave days must be non-negative finite number")
            else:
                c.execute("INSERT OR REPLACE INTO quotas(emp,type,days) VALUES(?,?,?)", (eid, code, round(v, 2)))
                changes.append(f"{code}={v:g}")
        log(c, u["name"], f"Edited {name}" + (f" (yearly quota: {', '.join(changes)})" if changes else ""))
    return {"ok": True}


@app.post("/api/employees/{eid}/toggle")
def toggle_employee(eid: int, u=Depends(admin)):
    with db() as c:
        e = c.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
        if not e:
            raise HTTPException(404, "Employee not found")
        if eid == u["id"] or e["email"] == ADMIN_EMAIL:
            raise HTTPException(400, "The main admin can’t be removed")
        if e["active"]:
            c.execute("UPDATE requests SET status='cancelled' WHERE emp=? AND status='pending'", (eid,))
            # Immediately revoke all active sessions for deactivated employee
            c.execute("DELETE FROM sessions WHERE user_id=?", (eid,))
        c.execute("UPDATE employees SET active=? WHERE id=?", (0 if e["active"] else 1, eid))
        log(c, u["name"], f"{'Removed access for' if e['active'] else 'Restored access for'} {e['name']}")
    return {"ok": True}


@app.post("/api/adjust")
def adjust(b: AdjIn, u=Depends(admin)):
    reason = b.reason.strip()
    if not b.days or not reason:
        raise HTTPException(400, "Enter a valid number of days and a reason")
    with db() as c:
        e = c.execute("SELECT name FROM employees WHERE id=?", (b.emp,)).fetchone()
        if not e or not c.execute("SELECT 1 FROM leave_types WHERE code=? AND tracked=1", (b.type,)).fetchone():
            raise HTTPException(404, "Employee or leave type not found")
        y = today().year
        old = avail(c, b.emp, b.type, y)
        c.execute("INSERT INTO adjustments(emp,type,days,reason,by_id,at,year) VALUES(?,?,?,?,?,?,?)",
                  (b.emp, b.type, b.days, reason[:500], u["id"], datetime.now(TZ).isoformat(), y))
        log(c, u["name"], f"Adjusted {e['name']}’s {b.type} balance {old:g} → {old + b.days:g}. Reason: {reason[:100]}")
    return {"ok": True}


# ---------- admin: company settings ----------
@app.post("/api/leave-types")
def add_type(b: TypeIn, u=Depends(admin)):
    name = b.name.strip()
    if not name or b.quota < 0:
        raise HTTPException(400, "Enter a valid name and number of days")
    with db() as c:
        base = re.sub(r"[^A-Z0-9]", "", name.upper())[:4] or "LV"
        code, i = base, 2
        while c.execute("SELECT 1 FROM leave_types WHERE code=?", (code,)).fetchone():
            code, i = f"{base}{i}", i + 1
        c.execute("INSERT INTO leave_types(code,name,quota,tracked,active) VALUES(?,?,?,?,1)", (code, name[:50], b.quota, int(b.tracked)))
        log(c, u["name"], f"Added leave type {name} ({b.quota:g} days/year)")
    return {"ok": True}


@app.put("/api/leave-types/{code}")
def edit_type(code: str, b: TypeIn, u=Depends(admin)):
    name = b.name.strip()
    if not name or b.quota < 0:
        raise HTTPException(400, "Enter a valid name and number of days")
    with db() as c:
        if not c.execute("UPDATE leave_types SET name=?, quota=?, tracked=? WHERE code=?", (name[:50], b.quota, int(b.tracked), code)).rowcount:
            raise HTTPException(404, "Leave type not found")
        log(c, u["name"], f"Updated leave type {name}: {b.quota:g} days/year")
    return {"ok": True}


@app.post("/api/holidays")
def add_holiday(b: HolIn, u=Depends(admin)):
    try:
        d = date.fromisoformat(b.date)
    except ValueError:
        raise HTTPException(400, "Enter a valid date (YYYY-MM-DD)")
    name = b.name.strip()
    if not name:
        raise HTTPException(400, "Enter a holiday name")
    min_year = today().year - 1
    max_year = today().year + 5
    if d.year < min_year or d.year > max_year:
        raise HTTPException(400, f"Holiday date must be between {min_year} and {max_year}")
    with db() as c:
        c.execute("INSERT OR REPLACE INTO holidays(date,name) VALUES(?,?)", (b.date, name[:100]))
        log(c, u["name"], f"Added holiday {name} on {b.date}")
    return {"ok": True}


@app.delete("/api/holidays/{d}")
def delete_holiday(d: str, u=Depends(admin)):
    try:
        date.fromisoformat(d)
    except ValueError:
        raise HTTPException(400, "Invalid date format")
    with db() as c:
        if c.execute("DELETE FROM holidays WHERE date=?", (d,)).rowcount:
            log(c, u["name"], f"Removed holiday on {d}")
    return {"ok": True}


@app.put("/api/policy")
def set_policy(b: PolIn, u=Depends(admin)):
    with db() as c:
        c.execute("UPDATE policy SET quota=?, max_remote=?, max_off=? WHERE id=1", (b.quota, b.max_remote, b.max_off))
        log(c, u["name"], f"Set policy: WFH {b.quota}/month, max {b.max_remote} remote and {b.max_off} on leave per day")
    return {"ok": True}


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)

