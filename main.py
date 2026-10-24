import hashlib, hmac, json, math, os, re, secrets, sqlite3, time
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
DEFAULT_TYPES = [("CL", "Casual", 12, 1), ("SL", "Sick", 8, 1), ("AL", "Annual", 10, 1), ("CO", "Comp-off (Overtime)", 0, 1), ("UL", "Unpaid", 0, 0)]

SCHEMA = """
CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  emp_code TEXT DEFAULT '', title TEXT DEFAULT '', role TEXT DEFAULT 'employee', active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, emp INTEGER NOT NULL, kind TEXT, type TEXT,
  start_date TEXT, end_date TEXT, part TEXT, days REAL, reason TEXT, status TEXT, decided_by INTEGER,
  note TEXT, over_quota INTEGER DEFAULT 0, ot_hours_used REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS overtime_requests(
  id INTEGER PRIMARY KEY,
  emp INTEGER NOT NULL,
  date TEXT NOT NULL,
  hours REAL NOT NULL,
  work_description TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  decided_by INTEGER,
  decided_at TEXT,
  note TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
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
CREATE INDEX IF NOT EXISTS idx_requests_emp ON requests(emp);
CREATE INDEX IF NOT EXISTS idx_requests_dates ON requests(start_date, end_date);
CREATE INDEX IF NOT EXISTS idx_adjustments_emp ON adjustments(emp);
CREATE INDEX IF NOT EXISTS idx_quotas_emp ON quotas(emp);
CREATE INDEX IF NOT EXISTS idx_overtime_emp ON overtime_requests(emp);
CREATE INDEX IF NOT EXISTS idx_overtime_status ON overtime_requests(status);
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


def export_database_dict(c) -> dict:
    return {
        "version": 1,
        "exported_at": datetime.now(TZ).isoformat(),
        "employees": [dict(r) for r in c.execute("SELECT * FROM employees")],
        "requests": [dict(r) for r in c.execute("SELECT * FROM requests")],
        "overtime_requests": [dict(r) for r in c.execute("SELECT * FROM overtime_requests")],
        "quotas": [dict(r) for r in c.execute("SELECT * FROM quotas")],
        "adjustments": [dict(r) for r in c.execute("SELECT * FROM adjustments")],
        "leave_types": [dict(r) for r in c.execute("SELECT * FROM leave_types")],
        "holidays": [dict(r) for r in c.execute("SELECT * FROM holidays")],
        "policy": [dict(r) for r in c.execute("SELECT * FROM policy")],
    }


def import_database_dict(c, data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Invalid backup format")

    restored = {"employees": 0, "requests": 0, "overtime": 0}

    # 1. Employees: upsert by email
    for e in data.get("employees", []):
        email = str(e.get("email", "")).strip().lower()
        if not email:
            continue
        ex = c.execute("SELECT id FROM employees WHERE email=?", (email,)).fetchone()
        p_hash = e.get("password_hash", "") or ""
        code = e.get("emp_code", "") or ""
        name = e.get("name", "") or email.split("@")[0]
        title = e.get("title", "") or ""
        role = e.get("role", "employee")
        active = int(e.get("active", 1))
        if ex:
            c.execute("""
                UPDATE employees
                SET name=?, emp_code=?, title=?, role=?, active=?, password_hash=?
                WHERE id=?
            """, (name, code, title, role, active, p_hash, ex["id"]))
        else:
            c.execute("""
                INSERT INTO employees(name, email, emp_code, title, role, active, password_hash)
                VALUES(?,?,?,?,?,?,?)
            """, (name, email, code, title, role, active, p_hash))
        restored["employees"] += 1

    # 2. Leave Types
    for lt in data.get("leave_types", []):
        code = lt.get("code")
        if code:
            c.execute("""
                INSERT OR REPLACE INTO leave_types(code, name, quota, tracked, active)
                VALUES(?,?,?,?,?)
            """, (code, lt.get("name", code), lt.get("quota", 0), lt.get("tracked", 1), lt.get("active", 1)))

    # 3. Quotas
    for q in data.get("quotas", []):
        if q.get("emp") and q.get("type"):
            c.execute("INSERT OR REPLACE INTO quotas(emp, type, days) VALUES(?,?,?)",
                      (q["emp"], q["type"], q.get("days", 0)))

    # 4. Holidays
    for h in data.get("holidays", []):
        if h.get("date") and h.get("name"):
            c.execute("INSERT OR REPLACE INTO holidays(date, name) VALUES(?,?)", (h["date"], h["name"]))

    # 5. Policy
    pol = data.get("policy", [])
    if pol and isinstance(pol, list) and len(pol) > 0:
        p = pol[0]
        c.execute("UPDATE policy SET quota=?, max_remote=?, max_off=? WHERE id=1",
                  (p.get("quota", 4), p.get("max_remote", 3), p.get("max_off", 2)))

    # 6. Overtime Requests
    for ot in data.get("overtime_requests", []):
        if ot.get("emp") and ot.get("date") and ot.get("hours"):
            c.execute("""
                INSERT OR REPLACE INTO overtime_requests(id, emp, date, hours, work_description, status, decided_by, decided_at, note, created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (ot.get("id"), ot["emp"], ot["date"], ot["hours"], ot.get("work_description", ""),
                  ot.get("status", "pending"), ot.get("decided_by"), ot.get("decided_at"), ot.get("note"), ot.get("created_at", "")))
            restored["overtime"] += 1

    # 7. Leave Requests
    for r in data.get("requests", []):
        if r.get("emp") and r.get("start_date") and r.get("end_date"):
            c.execute("""
                INSERT OR REPLACE INTO requests(id, emp, kind, type, start_date, end_date, part, days, reason, status, decided_by, note, over_quota, ot_hours_used)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (r.get("id"), r["emp"], r.get("kind", "leave"), r.get("type"), r["start_date"], r["end_date"],
                  r.get("part", "full"), r.get("days", 1.0), r.get("reason", ""), r.get("status", "pending"),
                  r.get("decided_by"), r.get("note"), r.get("over_quota", 0), r.get("ot_hours_used", 0.0)))
            restored["requests"] += 1

    # 8. Adjustments
    for a in data.get("adjustments", []):
        if a.get("emp") and a.get("type") and a.get("days"):
            c.execute("""
                INSERT OR REPLACE INTO adjustments(id, emp, type, days, reason, by_id, at, year)
                VALUES(?,?,?,?,?,?,?,?)
            """, (a.get("id"), a["emp"], a["type"], a["days"], a.get("reason", ""), a.get("by_id"), a.get("at"), a.get("year", today().year)))

    return restored


with db() as c:
    try:
        c.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    c.executescript(SCHEMA)
    for stmt in (
        "ALTER TABLE policy ADD COLUMN max_off INTEGER DEFAULT 2",
        "ALTER TABLE adjustments ADD COLUMN year INTEGER",
        "ALTER TABLE employees ADD COLUMN password_hash TEXT DEFAULT ''",
        "ALTER TABLE employees ADD COLUMN emp_code TEXT DEFAULT ''",
        "ALTER TABLE requests ADD COLUMN ot_hours_used REAL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS idx_requests_emp ON requests(emp)",
        "CREATE INDEX IF NOT EXISTS idx_requests_dates ON requests(start_date, end_date)",
        "CREATE INDEX IF NOT EXISTS idx_adjustments_emp ON adjustments(emp)",
        "CREATE INDEX IF NOT EXISTS idx_quotas_emp ON quotas(emp)",
        "CREATE INDEX IF NOT EXISTS idx_overtime_emp ON overtime_requests(emp)",
        "CREATE INDEX IF NOT EXISTS idx_overtime_status ON overtime_requests(status)",
    ):
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    c.execute("UPDATE adjustments SET year=? WHERE year IS NULL", (today().year,))
    c.executemany("INSERT OR IGNORE INTO leave_types(code,name,quota,tracked,active) VALUES(?,?,?,?,1)", DEFAULT_TYPES)
    c.execute("UPDATE leave_types SET name='Comp-off (Overtime)' WHERE code='CO'")
    c.execute("INSERT OR IGNORE INTO policy(id,quota,max_remote,max_off) VALUES(1,4,3,2)")
    c.execute("INSERT OR IGNORE INTO employees(name,email,title,role,active,emp_code) VALUES('Admin',?,'Administrator','admin',1,'ADM001')", (ADMIN_EMAIL,))
    c.execute("UPDATE employees SET role='admin', active=1 WHERE email=?", (ADMIN_EMAIL,))
    c.execute("UPDATE employees SET emp_code='ADM001' WHERE email=? AND (emp_code IS NULL OR emp_code='')", (ADMIN_EMAIL,))
    c.execute("UPDATE employees SET emp_code = 'EMP' || printf('%03d', id) WHERE (emp_code IS NULL OR emp_code='')")

    # Auto-restore data from leave_backup.json on startup if present and database is freshly initialized
    backup_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leave_backup.json")
    if os.path.exists(backup_file):
        try:
            emp_cnt = c.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
            req_cnt = c.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            if emp_cnt <= 1 and req_cnt == 0:
                with open(backup_file, "r", encoding="utf-8") as bf:
                    b_data = json.load(bf)
                    res_cnt = import_database_dict(c, b_data)
                    print(f"[Persistence] Automatically restored database from leave_backup.json: {res_cnt}")
        except Exception as err:
            print(f"[Persistence] Auto-restore notice: {err}")

if ADMIN_PASSWORD in ("admin", "password", "123456", "admin123"):
    print("[SECURITY NOTICE] ADMIN_PASSWORD is set to a common default. Please configure a strong password in production!")
if SECRET == "leaf-secret-key-change-me":
    print("[SECURITY NOTICE] SECRET_KEY is set to default. Please configure a strong random key in production!")


class RequestRateLimiter:
    def __init__(self, max_requests=120, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}
        self.last_cleanup = time.time()

    def check(self, ip: str) -> bool:
        now = time.time()
        if now - self.last_cleanup > 30:
            self.last_cleanup = now
            cutoff = now - self.window_seconds
            for k in list(self.requests.keys()):
                self.requests[k] = [t for t in self.requests[k] if t > cutoff]
                if not self.requests[k]:
                    del self.requests[k]
        cutoff = now - self.window_seconds
        history = [t for t in self.requests.get(ip, []) if t > cutoff]
        if len(history) >= self.max_requests:
            return False
        history.append(now)
        self.requests[ip] = history
        return True


api_limiter = RequestRateLimiter(max_requests=120, window_seconds=60)


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"

        # 1. API Rate Limiting (120 req/min per IP) to prevent DoS & automated abuse
        if request.url.path.startswith("/api/") and not api_limiter.check(client_ip):
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})

        # 2. CSRF Protection for state-changing requests (Origin & Referer validation)
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            host = request.headers.get("host")
            origin = request.headers.get("origin")
            if origin:
                origin_host = origin.split("://")[-1].rstrip("/")
                if host and origin_host != host:
                    return JSONResponse(status_code=403, content={"detail": "Cross-origin request rejected"})
            else:
                referer = request.headers.get("referer")
                if referer:
                    ref_host = referer.split("://")[-1].split("/")[0]
                    if host and ref_host != host:
                        return JSONResponse(status_code=403, content={"detail": "Cross-origin referer rejected"})

        # 3. Process request
        response: Response = await call_next(request)

        # 4. Comprehensive Security Headers
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
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
        if os.getenv("COOKIE_SECURE", "false").lower() == "true":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response


# Disable docs, redoc, and openapi.json in production
app = FastAPI(title="Leaf – Leave & WFH", docs_url=None, redoc_url=None, openapi_url=None)
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

    @field_validator("reason")
    def sanitize_reason(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid character in reason")
        return v.strip()


class DecideIn(BaseModel):
    action: str = Field(..., max_length=20)
    note: str = Field("", max_length=300)
    force: bool = False

    @field_validator("note")
    def sanitize_note(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid character in note")
        return v.strip()


class AdjIn(BaseModel):
    emp: int
    type: str = Field(..., max_length=20)
    days: float
    reason: str = Field(..., min_length=1, max_length=500)

    @field_validator("reason")
    def sanitize_adj_reason(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid character in reason")
        return v.strip()

    @field_validator("days")
    def check_days(cls, v):
        if not math.isfinite(v) or abs(v) > 365 or v == 0:
            raise ValueError("Adjustment days must be a non-zero finite number between -365 and 365")
        return round(v, 2)


class EmpIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=3, max_length=254)
    emp_code: str = Field("", max_length=50)
    title: str = Field("", max_length=100)
    role: str = Field("employee", max_length=20)
    password: Optional[str] = Field(None, max_length=128)

    @field_validator("name", "title", "emp_code")
    def sanitize_person(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid characters detected")
        return v.strip()


class OvertimeIn(BaseModel):
    date: str = Field(..., max_length=10)
    hours: float = Field(..., gt=0, le=24)
    work_description: str = Field(..., min_length=3, max_length=1000)

    @field_validator("work_description")
    def sanitize_work(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid character in work description")
        return v.strip()

    @field_validator("hours")
    def validate_hours(cls, v):
        if not math.isfinite(v) or v <= 0 or v > 24:
            raise ValueError("Hours must be between 0.5 and 24")
        return round(v, 2)


class OvertimeDecideIn(BaseModel):
    action: str = Field(..., max_length=20)
    note: str = Field("", max_length=300)

    @field_validator("note")
    def sanitize_note(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid character in note")
        return v.strip()


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

    @field_validator("name")
    def sanitize_name(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid characters detected")
        return v.strip()

    @field_validator("quota")
    def check_quota(cls, v):
        if not math.isfinite(v) or v < 0 or v > 365:
            raise ValueError("Quota must be a finite number between 0 and 365")
        return round(v, 2)


class HolIn(BaseModel):
    date: str = Field(..., max_length=10)
    name: str = Field(..., min_length=1, max_length=100)

    @field_validator("name")
    def sanitize_hol_name(cls, v):
        if "\x00" in v:
            raise ValueError("Invalid characters detected")
        return v.strip()


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
    ip = req.client.host if req.client else "unknown"
    allowed, wait_secs = rate_limiter.check(ip, "google_login")
    if not allowed:
        raise HTTPException(429, f"Too many sign-in attempts. Try again in {max(1, wait_secs // 60)} minutes.")

    if not CLIENT_ID:
        raise HTTPException(403, "Google sign-in isn’t configured")
    try:
        info = id_token.verify_oauth2_token(b.credential, grequests.Request(), CLIENT_ID)
    except Exception:
        rate_limiter.record_failure(ip, "google_login")
        raise HTTPException(403, "Google sign-in failed. Please try again.")

    email = (info.get("email") or "").strip().lower()
    if not info.get("email_verified") or not email:
        rate_limiter.record_failure(ip, "google_login")
        raise HTTPException(403, "Your Google email isn’t verified")

    with db() as c:
        u = c.execute("SELECT * FROM employees WHERE email=? AND active=1", (email,)).fetchone()
    if not u:
        rate_limiter.record_failure(ip, "google_login")
        raise HTTPException(403, f"{email} hasn’t been given access. Ask your admin to add it.")

    rate_limiter.reset(ip, "google_login")
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
def update_password(b: PasswordSetIn, req: Request, u=Depends(user)):
    ip = req.client.host if req.client else "unknown"
    allowed, wait_secs = rate_limiter.check(ip, f"pwd_{u['id']}")
    if not allowed:
        raise HTTPException(429, f"Too many password changes. Try again in {max(1, wait_secs // 60)} minutes.")

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


def get_overtime_summary(c, emp_id: int):
    earned = c.execute("SELECT COALESCE(SUM(hours), 0) FROM overtime_requests WHERE emp=? AND status='approved'", (emp_id,)).fetchone()[0] or 0.0
    pending_claims = c.execute("SELECT COALESCE(SUM(hours), 0) FROM overtime_requests WHERE emp=? AND status='pending'", (emp_id,)).fetchone()[0] or 0.0
    used_approved = c.execute("SELECT COALESCE(SUM(CASE WHEN ot_hours_used > 0 THEN ot_hours_used ELSE days * 8.0 END), 0) FROM requests WHERE emp=? AND kind='leave' AND type='CO' AND status IN ('approved','cancellation_requested')", (emp_id,)).fetchone()[0] or 0.0
    used_pending = c.execute("SELECT COALESCE(SUM(CASE WHEN ot_hours_used > 0 THEN ot_hours_used ELSE days * 8.0 END), 0) FROM requests WHERE emp=? AND kind='leave' AND type='CO' AND status='pending'", (emp_id,)).fetchone()[0] or 0.0
    available = max(0.0, round(earned - used_approved - used_pending, 2))
    return {
        "earned_hours": round(earned, 2),
        "pending_hours": round(pending_claims, 2),
        "used_hours": round(used_approved, 2),
        "locked_hours": round(used_pending, 2),
        "available_hours": available,
    }


def get_emp_approved_overtime(c, emp_id: int):
    rows = c.execute("""
        SELECT id, date, hours, work_description, created_at
        FROM overtime_requests
        WHERE emp=? AND status='approved'
        ORDER BY date DESC LIMIT 8
    """, (emp_id,)).fetchall()
    return [dict(id=r["id"], date=r["date"], hours=r["hours"], desc=r["work_description"], at=r["created_at"]) for r in rows]


def quota(c, emp, t):
    o = c.execute("SELECT days FROM quotas WHERE emp=? AND type=?", (emp, t)).fetchone()
    if o:
        return o[0]
    row = c.execute("SELECT quota FROM leave_types WHERE code=?", (t,)).fetchone()
    return row[0] if row else 0


def avail(c, emp, t, year):
    if t == "CO":
        ot = get_overtime_summary(c, emp)
        return round(ot["available_hours"] / 8.0, 2)
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


def rq(r, c=None):
    d = dict(id=r["id"], emp=r["emp"], kind=r["kind"], type=r["type"], start=r["start_date"], end=r["end_date"],
             part=r["part"], days=r["days"], reason=r["reason"], status=r["status"], by=r["decided_by"],
             note=r["note"], over=bool(r["over_quota"]),
             ot_hours=r["ot_hours_used"] if ("ot_hours_used" in r.keys() and r["ot_hours_used"]) else (round(r["days"] * 8.0, 2) if r["type"] == "CO" else 0.0))
    if r["type"] == "CO" and c:
        d["ot_history"] = get_emp_approved_overtime(c, r["emp"])
        d["ot_summary"] = get_overtime_summary(c, r["emp"])
    return d


def n_admins(c):
    return c.execute("SELECT COUNT(*) FROM employees WHERE role='admin' AND active=1").fetchone()[0]


# ---------- data ----------
@app.get("/api/state")
def state(u=Depends(user)):
    adm = u["role"] == "admin"
    with db() as c:
        emps = [dict(id=e["id"], code=e["emp_code"] or f"EMP{e['id']:03d}", n=e["name"], role=e["role"], t=e["title"], on=e["active"],
                     ot_hours=get_overtime_summary(c, e["id"])["available_hours"],
                     **({"email": e["email"]} if adm else {}))
                for e in c.execute("SELECT * FROM employees ORDER BY id")]
        q = "SELECT * FROM requests" + ("" if adm else " WHERE emp=?") + " ORDER BY id"
        reqs = [rq(r, c) for r in c.execute(q, () if adm else (u["id"],))]
        adj = {f'{a["emp"]}{a["type"]}': a["d"] for a in c.execute("SELECT emp,type,SUM(days) d FROM adjustments WHERE year=? GROUP BY emp,type", (today().year,))
               if adm or a["emp"] == u["id"]}
        quotas = {f'{x["emp"]}{x["type"]}': x["days"] for x in c.execute("SELECT * FROM quotas") if adm or x["emp"] == u["id"]}
        types = [[t["code"], t["name"], t["quota"], t["tracked"]] for t in c.execute("SELECT * FROM leave_types WHERE active=1")]
        hol = [dict(d=h["date"], n=h["name"]) for h in c.execute("SELECT * FROM holidays ORDER BY date")]
        p = c.execute("SELECT * FROM policy").fetchone()
        aud = [dict(t=a["at"], who=a["who"], a=a["action"]) for a in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 60")] if adm else []

        ot_sql = """
            SELECT o.*, e.name as emp_name, e.emp_code
            FROM overtime_requests o
            JOIN employees e ON o.emp = e.id
        """ + ("" if adm else " WHERE o.emp=?") + " ORDER BY o.id DESC LIMIT 100"
        ot_claims = [
            dict(
                id=row["id"], emp=row["emp"], emp_name=row["emp_name"],
                emp_code=row["emp_code"] or f"EMP{row['emp']:03d}",
                date=row["date"], hours=row["hours"], desc=row["work_description"],
                status=row["status"], by=row["decided_by"], note=row["note"] or "",
                at=row["created_at"]
            )
            for row in c.execute(ot_sql, () if adm else (u["id"],))
        ]
        my_ot = get_overtime_summary(c, u["id"])

    is_master = bool(ADMIN_EMAIL and u.get("email", "").strip().lower() == ADMIN_EMAIL.strip().lower() and ADMIN_PASSWORD)
    has_pwd = bool(u.get("password_hash")) or is_master
    return dict(me=u["id"], has_password=has_pwd, employees=emps, requests=reqs, adj=adj, quotas=quotas, types=types, holidays=hol,
                policy=dict(q=p["quota"], max=p["max_remote"], off=p["max_off"]), audit=aud,
                overtime=ot_claims, my_ot=my_ot)


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
        ot_hours_used = 0.0
        if ty and ty["code"] == "CO":
            ot = get_overtime_summary(c, tid)
            req_hours = round(n * 8.0, 2)
            if req_hours > ot["available_hours"]:
                raise HTTPException(409, f"Not enough overtime credit. {tgt['name']} has {ot['available_hours']:g} overtime hours ({round(ot['available_hours'] / 8.0, 1):g} days), but {req_hours:g} hours are required for this leave.")
            ot_hours_used = req_hours
        elif ty and ty["tracked"]:
            left = avail(c, tid, ty["code"], s.year)
            if n > left:
                raise HTTPException(409, f"Not enough balance. {tgt['name']} has {left:g} days left.")
        over = 0
        if b.kind == "wfh":
            qt = c.execute("SELECT quota FROM policy").fetchone()[0]
            used = c.execute("SELECT COALESCE(SUM(days),0) FROM requests WHERE emp=? AND kind='wfh' AND status IN ('approved','cancellation_requested') AND start_date LIKE ?", (tid, b.start[:7] + "%")).fetchone()[0]
            over = int(used + n > qt)
        status, by, note = ("approved", u["id"], "Recorded by admin") if on_behalf else ("pending", None, None)
        c.execute("""INSERT INTO requests(emp,kind,type,start_date,end_date,part,days,reason,status,decided_by,note,over_quota,ot_hours_used)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (tid, b.kind, ty["code"] if ty else None, b.start, b.end, part, n, b.reason.strip()[:500], status, by, note, over, ot_hours_used))
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
            if r["type"] == "CO":
                ot = get_overtime_summary(c, r["emp"])
                hours_needed = r["ot_hours_used"] or (r["days"] * 8.0)
                if ot["available_hours"] + ot["locked_hours"] < hours_needed:
                    raise HTTPException(409, f"Not enough overtime hours to approve this request (Needs: {hours_needed:g} hrs).")
            else:
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


# ---------- overtime endpoints ----------
@app.post("/api/overtime")
def claim_overtime(b: OvertimeIn, u=Depends(user)):
    try:
        d = date.fromisoformat(b.date)
    except ValueError:
        raise HTTPException(400, "Invalid date (YYYY-MM-DD)")

    min_d = today() - timedelta(days=90)
    max_d = today() + timedelta(days=1)
    if d < min_d or d > max_d:
        raise HTTPException(400, "Overtime date must be within the last 90 days")

    now_str = datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
    with db() as c:
        c.execute("""
            INSERT INTO overtime_requests(emp, date, hours, work_description, status, created_at)
            VALUES(?,?,?,?,?,?)
        """, (u["id"], b.date, b.hours, b.work_description, "pending", now_str))
        log(c, u["name"], f"Claimed {b.hours:g} hrs overtime for {b.date}: {b.work_description[:80]}")
    return {"ok": True}


@app.post("/api/overtime/{oid}/decide")
def decide_overtime(oid: int, b: OvertimeDecideIn, u=Depends(admin)):
    if b.action not in ("approve", "reject"):
        raise HTTPException(400, "Action must be approve or reject")

    now_str = datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
    with db() as c:
        ot = c.execute("SELECT * FROM overtime_requests WHERE id=?", (oid,)).fetchone()
        if not ot:
            raise HTTPException(404, "Overtime claim not found")
        if ot["status"] != "pending":
            raise HTTPException(409, f"This overtime claim was already {ot['status']}")

        new_status = "approved" if b.action == "approve" else "rejected"
        c.execute("""
            UPDATE overtime_requests
            SET status=?, decided_by=?, decided_at=?, note=?
            WHERE id=?
        """, (new_status, u["id"], now_str, b.note.strip()[:300], oid))

        emp = c.execute("SELECT name FROM employees WHERE id=?", (ot["emp"],)).fetchone()
        emp_name = emp["name"] if emp else f"Employee #{ot['emp']}"
        log(c, u["name"], f"{new_status.capitalize()} {emp_name}’s overtime claim #{oid} of {ot['hours']:g} hrs")
    return {"ok": True}


@app.post("/api/overtime/{oid}/cancel")
def cancel_overtime(oid: int, u=Depends(user)):
    with db() as c:
        ot = c.execute("SELECT * FROM overtime_requests WHERE id=? AND emp=?", (oid, u["id"])).fetchone()
        if not ot:
            raise HTTPException(404, "Overtime claim not found")
        if ot["status"] != "pending":
            raise HTTPException(409, "Only pending overtime claims can be cancelled")

        c.execute("UPDATE overtime_requests SET status='cancelled' WHERE id=?", (oid,))
        log(c, u["name"], f"Cancelled overtime claim #{oid} of {ot['hours']:g} hrs")
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
    code = b.emp_code.strip()
    p_hash = hash_password(b.password) if b.password else ""
    with db() as c:
        ex = c.execute("SELECT * FROM employees WHERE email=?", (email,)).fetchone()
        if ex and ex["active"]:
            raise HTTPException(409, "That email already has access")
        if ex:
            if p_hash:
                c.execute("UPDATE employees SET name=?, emp_code=?, title=?, role=?, active=1, password_hash=? WHERE id=?", (name, code, b.title.strip()[:100], b.role, p_hash, ex["id"]))
            else:
                c.execute("UPDATE employees SET name=?, emp_code=?, title=?, role=?, active=1 WHERE id=?", (name, code, b.title.strip()[:100], b.role, ex["id"]))
            eid = ex["id"]
        else:
            c.execute("INSERT INTO employees(name,email,emp_code,title,role,password_hash) VALUES(?,?,?,?,?,?)", (name, email, code, b.title.strip()[:100], b.role, p_hash))
            eid = c.execute("SELECT last_insert_rowid()").fetchone()[0]

        if not code:
            prefix = "ADM" if b.role == "admin" else "EMP"
            c.execute("UPDATE employees SET emp_code=? WHERE id=?", (f"{prefix}{eid:03d}", eid))

        log(c, u["name"], f"Gave {name} ({email}" + (f", ID: {code}" if code else "") + f") access as {b.role}")
    return {"ok": True}


@app.put("/api/employees/{eid}")
def edit_employee(eid: int, b: EmpEditIn, u=Depends(admin)):
    email, name = b.email.strip().lower(), b.name.strip()
    check_person(name, email, b.role)
    code = b.emp_code.strip()
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
            c.execute("UPDATE employees SET name=?, email=?, emp_code=?, title=?, role=?, password_hash=? WHERE id=?", (name, email, code, b.title.strip()[:100], b.role, p_hash, eid))
        else:
            c.execute("UPDATE employees SET name=?, email=?, emp_code=?, title=?, role=? WHERE id=?", (name, email, code, b.title.strip()[:100], b.role, eid))
        changes = []
        for l_code, v in b.quotas.items():
            if not c.execute("SELECT 1 FROM leave_types WHERE code=? AND tracked=1", (l_code,)).fetchone():
                continue
            if v is None:
                c.execute("DELETE FROM quotas WHERE emp=? AND type=?", (eid, l_code))
            elif v < 0 or not math.isfinite(v):
                raise HTTPException(400, "Leave days must be non-negative finite number")
            else:
                c.execute("INSERT OR REPLACE INTO quotas(emp,type,days) VALUES(?,?,?)", (eid, l_code, round(v, 2)))
                changes.append(f"{l_code}={v:g}")
        log(c, u["name"], f"Edited {name}" + (f" (yearly quota: {', '.join(changes)})" if changes else ""))
    return {"ok": True}


@app.post("/api/employees/{eid}/toggle")
def toggle_employee(eid: int, u=Depends(admin)):
    with db() as c:
        e = c.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
        if not e:
            raise HTTPException(404, "Employee not found")
        if eid == u["id"] or e["email"] == ADMIN_EMAIL:
            raise HTTPException(400, "You cannot remove yourself or the main admin")
        if e["role"] == "admin" and e["active"] and n_admins(c) < 2:
            raise HTTPException(400, "Cannot remove the only remaining active administrator")
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


# ---------- data management: backup & restore ----------
@app.get("/api/backup")
def download_backup(u=Depends(admin)):
    with db() as c:
        data = export_database_dict(c)
        log(c, u["name"], "Downloaded full database backup")
    filename = f"leaf-backup-{today().isoformat()}.json"
    content = json.dumps(data, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.post("/api/restore")
async def restore_backup(req: Request, u=Depends(admin)):
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")

    if not isinstance(body, dict):
        raise HTTPException(400, "Backup file must be a JSON object")

    with db() as c:
        try:
            res = import_database_dict(c, body)
            log(c, u["name"], f"Restored database backup ({res['employees']} employees, {res['requests']} requests, {res['overtime']} overtime records)")
        except Exception as err:
            raise HTTPException(400, f"Failed to restore backup: {str(err)}")

    return {"ok": True, "restored": res}


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)

