# main.py
import hashlib
import hmac
import json
import os
import random
import time
from pathlib import Path
import secrets
import shutil
import psycopg2
import bcrypt
from psycopg2.extras import DictCursor
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Header, Depends, Cookie, Request, Response
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, EmailStr

app = FastAPI(title="I.B.E.X.", version="4.1.0")

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
# Uploads are stored outside the app's static/served root and are only ever
# reachable through the authenticated /api/uploads/{filename} endpoint below -
# there is no longer a public StaticFiles mount for this directory.
UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "private_uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

SESSION_LIFETIME_DAYS = 7
SESSION_COOKIE_NAME = "alg_session"
IS_PRODUCTION = os.getenv("ENV", "production").lower() != "development"
PBKDF2_ITERATIONS = 200_000  # legacy - kept only to verify/upgrade old hashes
ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}
ALLOWED_UPLOAD_MIME_TYPES = {
    "application/pdf", "image/jpeg", "image/png",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

# ---------------------------------------------------------------------------
# Login rate limiting (in-memory, per process). Keyed by client IP + email so
# one abusive account can't be used to lock out a shared office IP, and vice
# versa. Swap for a Redis-backed limiter if you run multiple worker processes.
# ---------------------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _rate_limit_key(request: "Request", email: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{email.strip().lower()}"


def check_login_rate_limit(request: "Request", email: str):
    key = _rate_limit_key(request, email)
    now = time.time()
    attempts = [t for t in _login_attempts[key] if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[key] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many login attempts. Please wait 15 minutes and try again.")


def record_failed_login(request: "Request", email: str):
    key = _rate_limit_key(request, email)
    _login_attempts[key].append(time.time())


def clear_login_attempts(request: "Request", email: str):
    _login_attempts.pop(_rate_limit_key(request, email), None)


def set_session_cookie(response: "Response", token: str):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="strict",
        max_age=SESSION_LIFETIME_DAYS * 86400,
        path="/",
    )


def clear_session_cookie(response: "Response"):
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")

VALID_MODULES = ['students', 'teachers', 'classrooms', 'syllabus', 'attendance', 'invigilation', 'fees']
SEATING_MODULE = 'seating'

# 'timetables' isn't a generic /api/records table (it has its own dedicated
# endpoints below) but it IS a sidebar module a staff designation can be
# granted or denied access to, so it's included here for permission checks.
ACCESS_HEADS = ['homepage', 'administrations', 'examination']
MODULE_HEAD = {
    'analytics': 'homepage', 'assistant': 'homepage', 'students': 'homepage',
    'teachers': 'homepage', 'classrooms': 'homepage', 'users': 'homepage',
    'attendance': 'administrations', 'syllabus': 'administrations',
    'timetables': 'administrations', 'fees': 'administrations',
    'seating': 'examination', 'invigilation': 'examination',
}
ALL_ACCESS_MODULES = ACCESS_HEADS

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

DESIGNATION_PRESETS = ['Admin', 'Accountant', 'Teacher', 'Head', 'Clerk', 'Custom']


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required. Configure a PostgreSQL database in Render.")
    kwargs = {"cursor_factory": DictCursor}
    if "sslmode=" not in DATABASE_URL and "localhost" not in DATABASE_URL and "127.0.0.1" not in DATABASE_URL:
        kwargs["sslmode"] = "require"
    return psycopg2.connect(DATABASE_URL, **kwargs)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    statements = [
        """CREATE TABLE IF NOT EXISTS institutes (id SERIAL PRIMARY KEY, institute_name TEXT NOT NULL, full_name TEXT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS branches (id SERIAL PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, tenant_id INTEGER NOT NULL, name TEXT NOT NULL, UNIQUE(institute_id, name))""",
        """CREATE TABLE IF NOT EXISTS staff_users (id SERIAL PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, permission TEXT NOT NULL DEFAULT 'read_only', designation TEXT, module_access TEXT, created_at TIMESTAMPTZ NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, institute_id INTEGER NOT NULL REFERENCES institutes(id) ON DELETE CASCADE, staff_user_id INTEGER REFERENCES staff_users(id) ON DELETE CASCADE, expires_at TIMESTAMPTZ NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS students (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, name TEXT, email TEXT, batch TEXT, status TEXT, document TEXT, roll_number TEXT, parent_contact TEXT)""",
        """CREATE TABLE IF NOT EXISTS teachers (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, name TEXT, subject TEXT, department TEXT, document TEXT, contact_number TEXT)""",
        """CREATE TABLE IF NOT EXISTS classrooms (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, room_no TEXT, capacity INTEGER, building TEXT, document TEXT)""",
        """CREATE TABLE IF NOT EXISTS syllabus (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, subject TEXT, semester TEXT, units INTEGER, document TEXT, topic TEXT, teacher_name TEXT, num_lectures INTEGER, lecture_date TEXT)""",
        """CREATE TABLE IF NOT EXISTS attendance (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, student_name TEXT, date TEXT, status TEXT, document TEXT)""",
        """CREATE TABLE IF NOT EXISTS timetables_slots (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, batch_name TEXT, day TEXT, time_slot TEXT, lecture_number INTEGER, subject TEXT, teacher TEXT, room TEXT)""",
        """CREATE TABLE IF NOT EXISTS timetable_configs (id SERIAL PRIMARY KEY, branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE, batch_name TEXT NOT NULL, timings_json TEXT NOT NULL, teachers_config_json TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL, UNIQUE(branch_id, batch_name))""",
        """CREATE TABLE IF NOT EXISTS exam_seatings (id SERIAL PRIMARY KEY, branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE, exam_date TEXT NOT NULL, room_number TEXT NOT NULL, rows INTEGER NOT NULL, columns INTEGER NOT NULL, assignments_json TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS invigilation (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, teacher_name TEXT, exam_date TEXT, room TEXT, document TEXT)""",
        """CREATE TABLE IF NOT EXISTS fees (id SERIAL PRIMARY KEY, branch_id INTEGER REFERENCES branches(id) ON DELETE CASCADE, student_name TEXT, amount_inr NUMERIC(12,2), status TEXT, due_date TEXT, document TEXT, utr_reference TEXT, paid_at TIMESTAMPTZ, paid_by INTEGER)""",
        """CREATE TABLE IF NOT EXISTS audit_log (id BIGSERIAL PRIMARY KEY, timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(), user_id INTEGER, branch_id INTEGER, action_type TEXT NOT NULL, before_after_payload JSONB NOT NULL DEFAULT '{}'::jsonb)""",
    ]
    for stmt in statements:
        cur.execute(stmt)
    # Safe additive migrations for databases created by earlier builds.
    for stmt in [
        "ALTER TABLE branches ADD COLUMN IF NOT EXISTS tenant_id INTEGER",
        "UPDATE branches SET tenant_id = institute_id WHERE tenant_id IS NULL",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS permission TEXT NOT NULL DEFAULT 'read_only'",
        """DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'staff_users' AND column_name = 'permissions') THEN
                EXECUTE $sql$UPDATE staff_users SET permission = CASE
                    WHEN lower(COALESCE(permissions::text, '')) LIKE '%read_only%' THEN 'read_only'
                    WHEN lower(COALESCE(permissions::text, '')) LIKE '%edit%' THEN 'edit'
                    ELSE permission
                END WHERE permission IS NULL OR permission = 'read_only'$sql$;
            END IF;
        END $$;""",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS designation TEXT",
        "ALTER TABLE staff_users ADD COLUMN IF NOT EXISTS module_access TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS email TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS batch TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS roll_number TEXT",
        "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_contact TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS name TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS department TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS contact_number TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS room_no TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS capacity INTEGER",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS building TEXT",
        "ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS semester TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS units INTEGER",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS topic TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS teacher_name TEXT",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS num_lectures INTEGER",
        "ALTER TABLE syllabus ADD COLUMN IF NOT EXISTS lecture_date TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS student_name TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS date TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE attendance ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS batch_name TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS day TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS time_slot TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS lecture_number INTEGER",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS subject TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS teacher TEXT",
        "ALTER TABLE timetables_slots ADD COLUMN IF NOT EXISTS room TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS timings_json TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS teachers_config_json TEXT",
        "ALTER TABLE timetable_configs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ",
        """DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'timetable_configs'
                  AND column_name = 'config'
            ) THEN
                EXECUTE 'ALTER TABLE timetable_configs ALTER COLUMN config DROP NOT NULL';
            END IF;
        END $$;""",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS exam_date TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS room_number TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS rows INTEGER",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS columns INTEGER",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS assignments_json TEXT",
        "ALTER TABLE exam_seatings ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS teacher_name TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS exam_date TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS room TEXT",
        "ALTER TABLE invigilation ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS student_name TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS amount_inr NUMERIC(12,2)",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS status TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS due_date TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS document TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS utr_reference TEXT",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ",
        "ALTER TABLE fees ADD COLUMN IF NOT EXISTS paid_by INTEGER",
    ]:
        cur.execute(stmt)
    for stmt in [
        "CREATE INDEX IF NOT EXISTS idx_branches_institute ON branches(institute_id)",
        "CREATE INDEX IF NOT EXISTS idx_students_branch ON students(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_teachers_branch ON teachers(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_classrooms_branch ON classrooms(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_syllabus_branch ON syllabus(branch_id)",
        "CREATE INDEX IF NOT EXISTS idx_attendance_branch_date ON attendance(branch_id, date)",
        "CREATE INDEX IF NOT EXISTS idx_timetable_branch_day_slot ON timetables_slots(branch_id, day, time_slot)",
        "CREATE INDEX IF NOT EXISTS idx_fees_branch_status ON fees(branch_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_audit_branch_timestamp ON audit_log(branch_id, timestamp DESC)",
    ]:
        cur.execute(stmt)
    conn.commit()
    cur.close(); conn.close()

init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _legacy_pbkdf2_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()


def hash_password(password: str) -> str:
    """Bcrypt with a per-password random salt baked into the hash string
    itself - no separate salt column needed for new accounts."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str, legacy_salt: str | None) -> tuple[bool, str | None]:
    """Returns (is_valid, upgraded_hash). upgraded_hash is non-None when a
    legacy PBKDF2 hash just verified successfully and should be rewritten to
    bcrypt by the caller (transparent password-hash migration on login)."""
    if password_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")), None
        except ValueError:
            return False, None
    # Legacy PBKDF2 record - verify against it, then flag for upgrade.
    if not legacy_salt:
        return False, None
    computed = _legacy_pbkdf2_hash(password, legacy_salt)
    if secrets.compare_digest(computed, password_hash):
        return True, hash_password(password)
    return False, None


def create_session(institute_id: int, staff_user_id: int = None) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(days=SESSION_LIFETIME_DAYS)).isoformat()
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (token, institute_id, staff_user_id, expires_at) VALUES (%s, %s, %s, %s)",
        (token, institute_id, staff_user_id, expires_at),
    )
    conn.commit()
    conn.close()
    audit_system(institute_id, None, "CREATE_SESSION", None, {"staff_user_id": staff_user_id})
    return token


class CurrentInstitute(BaseModel):
    user_id: int | None = None
    id: int  # institute_id - used for all data scoping, whether owner or staff
    institute_name: str
    full_name: str
    email: str
    is_owner: bool
    permission: str  # 'owner' | 'edit' | 'read_only'
    designation: str = "Owner"
    allowed_modules: list = ALL_ACCESS_MODULES  # modules this login may open in the sidebar


def check_module_access(institute: "CurrentInstitute", module: str):
    # Owners can use everything. Staff receive only category privileges.
    if institute.is_owner:
        return
    head = MODULE_HEAD.get(module, module)
    if head not in institute.allowed_modules:
        raise HTTPException(status_code=403, detail=f"Your account does not have access to the {module.title()} module")


def get_current_institute(alg_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> CurrentInstitute:
    """Session token now travels exclusively as an HttpOnly, Secure,
    SameSite=Strict cookie - never in JS-readable storage or a header the
    frontend has to manage, so it can't be exfiltrated via XSS."""
    if not alg_session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = alg_session

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
    session = cursor.fetchone()
    if not session:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    expires_at = session["expires_at"]
    if not isinstance(expires_at, datetime):
        expires_at = datetime.fromisoformat(expires_at)
    now_utc = datetime.now(timezone.utc) if expires_at.tzinfo else datetime.utcnow()
    if expires_at < now_utc:
        cursor.execute("DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        conn.close()
        audit_system(session["institute_id"], None, "EXPIRE_SESSION", {"token": "redacted"}, None)
        raise HTTPException(status_code=401, detail="Session expired, please log in again")

    cursor.execute("SELECT * FROM institutes WHERE id = %s", (session["institute_id"],))
    institute = cursor.fetchone()

    if not institute:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid session")

    if session["staff_user_id"] is not None:
        cursor.execute("SELECT * FROM staff_users WHERE id = %s", (session["staff_user_id"],))
        staff = cursor.fetchone()
        conn.close()
        if not staff:
            raise HTTPException(status_code=401, detail="Invalid session")
        raw_access = staff["module_access"] if "module_access" in staff.keys() else None
        try:
            allowed = json.loads(raw_access) if raw_access else []
        except (TypeError, ValueError):
            allowed = []
        return CurrentInstitute(
            user_id=staff["id"],
            id=institute["id"],
            institute_name=institute["institute_name"],
            full_name=staff["full_name"],
            email=staff["email"],
            is_owner=False,
            permission=staff["permission"],
            designation=(staff["designation"] if "designation" in staff.keys() and staff["designation"] else "Staff"),
            allowed_modules=allowed,
        )

    conn.close()
    return CurrentInstitute(
        user_id=institute["id"],
        id=institute["id"],
        institute_name=institute["institute_name"],
        full_name=institute["full_name"] or "",
        email=institute["email"],
        is_owner=True,
        permission="owner",
    )


def require_write_access(institute: CurrentInstitute = Depends(get_current_institute)) -> CurrentInstitute:
    """Blocks any mutating request from a staff login flagged read-only."""
    if institute.permission == "read_only":
        raise HTTPException(status_code=403, detail="Your account has read-only access")
    return institute


def require_owner(institute: CurrentInstitute = Depends(get_current_institute)) -> CurrentInstitute:
    """Manage Users, and other owner-exclusive actions, check this."""
    if not institute.is_owner:
        raise HTTPException(status_code=403, detail="Only the institute owner can do this")
    return institute


def verify_branch_ownership(branch_id: int, institute_id: int):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM branches WHERE id = %s AND tenant_id = %s", (branch_id, institute_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Branch not found")


def verify_branch_read_access(branch_id: int, institute_id: int):
    """Branch 0 is the synthetic Centralized HQ read-only view."""
    if branch_id == 0:
        return
    verify_branch_ownership(branch_id, institute_id)


def audit_write(institute: CurrentInstitute, branch_id: int | None, action_type: str, before=None, after=None):
    """Durable audit event for every application-level DB mutation."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (timestamp, user_id, branch_id, action_type, before_after_payload) VALUES (NOW(), %s, %s, %s, %s::jsonb)",
            (institute.user_id, branch_id, action_type, json.dumps({"before": before, "after": after}, default=str)),
        )
        conn.commit()
    finally:
        conn.close()


def audit_system(user_id: int | None, branch_id: int | None, action_type: str, before=None, after=None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (timestamp, user_id, branch_id, action_type, before_after_payload) VALUES (NOW(), %s, %s, %s, %s::jsonb)",
            (user_id, branch_id, action_type, json.dumps({"before": before, "after": after}, default=str)),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    institute_name: str
    full_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/signup")
def signup(req: SignupRequest, response: Response):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    password_hash = hash_password(req.password)

    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO institutes (institute_name, full_name, email, password_hash, password_salt, created_at)
               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
            (req.institute_name, req.full_name, req.email.lower(), password_hash, "", datetime.utcnow().isoformat()),
        )
        institute_id = cursor.fetchone()[0]
        # every new institute gets one starter branch
        cursor.execute(
            "INSERT INTO branches (institute_id, tenant_id, name) VALUES (%s, %s, %s)",
            (institute_id, institute_id, "Main Campus"),
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this email already exists")
    conn.close()
    audit_system(institute_id, None, "CREATE_INSTITUTE", None, {"institute_id": institute_id, "starter_branch": "Main Campus"})

    token = create_session(institute_id)
    set_session_cookie(response, token)
    return {
        "institute_name": req.institute_name,
        "full_name": req.full_name,
        "is_owner": True,
        "permission": "owner",
        "designation": "Owner",
        "allowed_modules": ALL_ACCESS_MODULES,
    }


@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, response: Response):
    check_login_rate_limit(request, req.email)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM institutes WHERE email = %s", (req.email.lower(),))
    institute = cursor.fetchone()

    # Deliberately same error for "no such email" and "wrong password" so
    # attackers can't use this endpoint to find out which emails are registered.
    invalid = HTTPException(status_code=401, detail="Invalid email or password")

    if institute:
        valid, upgraded = verify_password(req.password, institute["password_hash"], institute["password_salt"])
        if valid:
            if upgraded:
                cursor.execute("UPDATE institutes SET password_hash=%s, password_salt='' WHERE id=%s", (upgraded, institute["id"]))
                conn.commit()
            conn.close()
            clear_login_attempts(request, req.email)
            token = create_session(institute["id"])
            set_session_cookie(response, token)
            return {
                "institute_name": institute["institute_name"],
                "full_name": institute["full_name"] or "",
                "is_owner": True,
                "permission": "owner",
                "designation": "Owner",
                "allowed_modules": ALL_ACCESS_MODULES,
            }

    # Not an owner account (or wrong password) - check staff logins.
    cursor.execute("SELECT * FROM staff_users WHERE email = %s", (req.email.lower(),))
    staff = cursor.fetchone()
    if staff:
        valid, upgraded = verify_password(req.password, staff["password_hash"], staff["password_salt"])
        if valid:
            if upgraded:
                cursor.execute("UPDATE staff_users SET password_hash=%s, password_salt='' WHERE id=%s", (upgraded, staff["id"]))
                conn.commit()
            cursor.execute("SELECT * FROM institutes WHERE id = %s", (staff["institute_id"],))
            parent_institute = cursor.fetchone()
            conn.close()
            clear_login_attempts(request, req.email)
            token = create_session(staff["institute_id"], staff_user_id=staff["id"])
            set_session_cookie(response, token)
            try:
                staff_modules = json.loads(staff["module_access"]) if staff["module_access"] else []
            except (TypeError, ValueError):
                staff_modules = []
            return {
                "institute_name": parent_institute["institute_name"] if parent_institute else "",
                "full_name": staff["full_name"],
                "is_owner": False,
                "permission": staff["permission"],
                "designation": staff["designation"] or "Staff",
                "allowed_modules": staff_modules,
            }

    conn.close()
    record_failed_login(request, req.email)
    raise invalid


@app.get("/api/auth/me")
def whoami(institute: CurrentInstitute = Depends(get_current_institute)):
    return {
        "user_id": institute.user_id,
        "institute_id": institute.id,
        "institute_name": institute.institute_name,
        "full_name": institute.full_name,
        "is_owner": institute.is_owner,
        "permission": institute.permission,
        "designation": institute.designation,
        "allowed_modules": institute.allowed_modules,
    }


@app.post("/api/auth/logout")
def logout(response: Response, alg_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME)):
    if alg_session:
        conn = get_conn()
        cur = conn.cursor(); cur.execute("DELETE FROM sessions WHERE token = %s", (alg_session,))
        conn.commit()
        conn.close()
        audit_system(None, None, "LOGOUT_SESSION", None, {"token": "redacted"})
    clear_session_cookie(response)
    return {"status": "logged out"}


# ---------------------------------------------------------------------------
# Institute profile
# ---------------------------------------------------------------------------

class InstituteNameUpdate(BaseModel):
    institute_name: str


@app.patch("/api/institute/name")
def update_institute_name(req: InstituteNameUpdate, institute: CurrentInstitute = Depends(require_write_access)):
    name = req.institute_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Institute name cannot be empty")
    conn = get_conn()
    cur = conn.cursor(); cur.execute("SELECT institute_name FROM institutes WHERE id = %s", (institute.id,)); before = cur.fetchone()
    conn.cursor().execute("UPDATE institutes SET institute_name = %s WHERE id = %s", (name, institute.id))
    conn.commit(); conn.close()
    audit_write(institute, None, "UPDATE_INSTITUTE", {"institute_name": before[0] if before else None}, {"institute_name": name})
    return {"institute_name": name}


# ---------------------------------------------------------------------------
# Staff users ("Manage Users") - owner-only administration
# ---------------------------------------------------------------------------

class StaffUserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    permission: str  # 'edit' | 'read_only'
    designation: str  # e.g. 'Admin', 'Accountant', 'Teacher', 'Head', 'Clerk', 'Custom'
    modules: list = []  # which sidebar modules this designation may open


class StaffPermissionUpdate(BaseModel):
    permission: str | None = None
    designation: str | None = None
    modules: list | None = None


def _validate_modules(modules: list):
    if not isinstance(modules, list):
        raise HTTPException(status_code=400, detail="Module privileges must be a list")
    bad = [m for m in modules if m not in ACCESS_HEADS]
    if bad:
        raise HTTPException(status_code=400, detail="Module privileges must be Homepage, Administrations, or Examination")


@app.get("/api/users")
def list_staff_users(institute: CurrentInstitute = Depends(require_owner)):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, full_name, email, permissions, designation, module_access, created_at FROM staff_users WHERE institute_id = %s",
            (institute.id,),
        )
        users = []
        for row in cursor.fetchall():
            u = dict(row)
            raw_access = u.pop("module_access", None)
            try:
                u["modules"] = json.loads(raw_access) if raw_access else []
            except (TypeError, ValueError):
                u["modules"] = []
            u["designation"] = u.get("designation") or "Staff"
            users.append(u)
        conn.close()
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load users: {e}")


@app.post("/api/users")
def add_staff_user(req: StaffUserCreate, institute: CurrentInstitute = Depends(require_owner)):
    if req.permission not in ("edit", "read_only"):
        raise HTTPException(status_code=400, detail="Permission must be 'edit' or 'read_only'")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not req.designation.strip():
        raise HTTPException(status_code=400, detail="Designation is required")
    _validate_modules(req.modules)

    password_hash = hash_password(req.password)

    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO staff_users (institute_id, full_name, email, password_hash, password_salt, permission, designation, module_access, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (institute.id, req.full_name, req.email.lower(), password_hash, "", req.permission,
             req.designation.strip(), json.dumps(req.modules), datetime.utcnow().isoformat()),
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
    except psycopg2.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    conn.close()
    audit_write(institute, None, "CREATE_USER", None, {"id": user_id, "full_name": req.full_name, "email": req.email.lower(), "permission": req.permission, "designation": req.designation.strip(), "modules": req.modules})
    return {"id": user_id, "full_name": req.full_name, "email": req.email.lower(), "permission": req.permission,
            "designation": req.designation.strip(), "modules": req.modules}


def verify_staff_ownership(user_id: int, institute_id: int):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM staff_users WHERE id = %s AND institute_id = %s", (user_id, institute_id))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")


@app.patch("/api/users/{user_id}")
def update_staff_permission(user_id: int, req: StaffPermissionUpdate, institute: CurrentInstitute = Depends(require_owner)):
    """Partial update - the boss can change permission, designation, and/or
    module access (grant/revoke) independently or all at once."""
    verify_staff_ownership(user_id, institute.id)
    pre_conn = get_conn(); pre_cur = pre_conn.cursor(); pre_cur.execute("SELECT permission, designation, module_access FROM staff_users WHERE id = %s", (user_id,)); before_user = pre_cur.fetchone(); pre_conn.close()

    updates, params = [], []
    if req.permission is not None:
        if req.permission not in ("edit", "read_only"):
            raise HTTPException(status_code=400, detail="Permission must be 'edit' or 'read_only'")
        updates.append("permission = %s")
        params.append(req.permission)
    if req.designation is not None:
        if not req.designation.strip():
            raise HTTPException(status_code=400, detail="Designation cannot be empty")
        updates.append("designation = %s")
        params.append(req.designation.strip())
    if req.modules is not None:
        _validate_modules(req.modules)
        updates.append("module_access = %s")
        params.append(json.dumps(req.modules))

    if not updates:
        raise HTTPException(status_code=400, detail="Nothing to update")

    conn = get_conn()
    conn.cursor().execute(f"UPDATE staff_users SET {', '.join(updates)} WHERE id = %s", (*params, user_id))
    conn.commit()
    conn.close()
    audit_write(institute, None, "UPDATE_USER", dict(before_user) if before_user else None, {"permission": req.permission, "designation": req.designation, "modules": req.modules})
    return {"id": user_id, "status": "updated"}


@app.delete("/api/users/{user_id}")
def remove_staff_user(user_id: int, institute: CurrentInstitute = Depends(require_owner)):
    verify_staff_ownership(user_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_name, email, permissions, designation, module_access FROM staff_users WHERE id = %s", (user_id,))
    before_user = cursor.fetchone()
    cursor.execute("DELETE FROM staff_users WHERE id = %s", (user_id,))
    cursor.execute("DELETE FROM sessions WHERE staff_user_id = %s", (user_id,))
    conn.commit()
    conn.close()
    audit_write(institute, None, "DELETE_USER", dict(before_user) if before_user else None, None)
    return {"status": "removed"}


# ---------------------------------------------------------------------------
# Branches
# ---------------------------------------------------------------------------

class BranchCreate(BaseModel):
    name: str


@app.get("/api/branches")
def get_branches(institute: CurrentInstitute = Depends(get_current_institute)):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM branches WHERE tenant_id = %s ORDER BY id", (institute.id,))
    branches = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return branches


@app.post("/api/branches")
def add_branch(branch: BranchCreate, institute: CurrentInstitute = Depends(require_write_access)):
    conn = get_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO branches (institute_id, tenant_id, name) VALUES (%s, %s, %s) RETURNING id",
            (institute.id, institute.id, branch.name),
        )
        conn.commit()
        branch_id = cursor.fetchone()[0]
    except psycopg2.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Branch already exists")
    conn.close()
    audit_write(institute, branch_id, "CREATE_BRANCH", None, {"id": branch_id, "name": branch.name})
    return {"id": branch_id, "name": branch.name}


# ---------------------------------------------------------------------------
# Generic records (students / teachers / classrooms / syllabus / attendance / invigilation / fees)
# ---------------------------------------------------------------------------

@app.patch("/api/branches/{branch_id}")
def edit_branch(branch_id: int, branch: BranchCreate, institute: CurrentInstitute = Depends(require_write_access)):
    verify_branch_ownership(branch_id, institute.id)
    name=branch.name.strip()
    if not name: raise HTTPException(status_code=400, detail="Branch name cannot be empty")
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("SELECT id,name FROM branches WHERE id=%s AND tenant_id=%s",(branch_id,institute.id))
        if not cur.fetchone(): raise HTTPException(status_code=404, detail="Branch not found")
        cur.execute("UPDATE branches SET name=%s WHERE id=%s AND tenant_id=%s RETURNING id,name",(name,branch_id,institute.id)); row=cur.fetchone(); conn.commit(); return {"id":row[0],"name":row[1]}
    except psycopg2.IntegrityError:
        conn.rollback(); raise HTTPException(status_code=400, detail="A branch with that name already exists")
    finally: conn.close()

@app.delete("/api/branches/{branch_id}")
def delete_branch(branch_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    verify_branch_ownership(branch_id, institute.id)
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("SELECT id,name FROM branches WHERE id=%s AND tenant_id=%s",(branch_id,institute.id)); row=cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Branch not found")
        name=row["name"]; cur.execute("DELETE FROM branches WHERE id=%s AND tenant_id=%s",(branch_id,institute.id))
        if cur.rowcount!=1: raise HTTPException(status_code=404, detail="Branch not found")
        conn.commit(); return {"status":"deleted","id":branch_id,"name":name,"data_wiped":True}
    except Exception:
        conn.rollback(); raise
    finally: conn.close()

@app.get("/api/records/{module}/{branch_id}")
def get_records(module: str, branch_id: int, search: str = "", sort: str = "id", direction: str = "desc", page: int = 1, page_size: int = 200, institute: CurrentInstitute = Depends(get_current_institute)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_read_access(branch_id, institute.id)
    page = max(1, min(page, 10000)); page_size = max(1, min(page_size, 500))
    allowed_sort = {"id", *RECORD_FIELDS[module]}
    if sort not in allowed_sort: sort = "id"
    direction = "ASC" if direction.lower() == "asc" else "DESC"
    conn = get_conn(); cursor = conn.cursor()
    params = [institute.id if branch_id == 0 else branch_id]
    where = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
    search_fields = RECORD_FIELDS[module]
    if search.strip():
        clauses = [f"CAST({f} AS TEXT) ILIKE %s" for f in search_fields]
        where += " AND (" + " OR ".join(clauses) + ")"
        params.extend([f"%{search.strip()}%"] * len(clauses))
    offset = (page - 1) * page_size
    cursor.execute(f"SELECT * FROM {module} WHERE {where} ORDER BY {sort} {direction}, id DESC LIMIT %s OFFSET %s", (*params, page_size, offset))
    records = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return records


def _sniff_mime(contents: bytes, ext: str) -> str:
    """Cheap magic-byte sniff so a renamed .exe with a .pdf extension is
    caught server-side, not trusted off the client-supplied extension alone."""
    if contents[:4] == b"%PDF":
        return "application/pdf"
    if contents[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if contents[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if contents[:4] == b"PK\x03\x04":  # .docx is a zip container
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if contents[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":  # legacy .doc (OLE)
        return "application/msword"
    return "application/octet-stream"


def save_upload(file: UploadFile) -> str:
    """Validates extension, size, and actual file content (not just the
    client-declared extension/content-type), then stores the file under a
    random UUID name - never the original filename - inside UPLOAD_DIR, which
    sits outside any publicly served static root. Files are only ever handed
    back out through the authenticated /api/uploads/{filename} endpoint."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}",
        )
    contents = file.file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (max 5 MB)")
    if not contents:
        raise HTTPException(status_code=400, detail="File is empty")

    sniffed = _sniff_mime(contents, ext)
    if sniffed not in ALLOWED_UPLOAD_MIME_TYPES:
        raise HTTPException(status_code=400, detail="File content does not match an allowed file type")

    filename = f"{secrets.token_hex(16)}{ext}"
    dest = os.path.join(UPLOAD_DIR, filename)
    # Defense in depth: refuse to write anywhere outside UPLOAD_DIR even if
    # filename generation above were ever changed to something less strict.
    if os.path.commonpath([UPLOAD_DIR, os.path.abspath(dest)]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    with open(dest, "wb") as buffer:
        buffer.write(contents)
    return filename


# Every table that can carry an uploaded document, used to confirm a
# requested file actually belongs to the requesting institute's tenant
# before it's served back out.
DOCUMENT_TABLES = ["classrooms", "attendance", "invigilation", "fees", "students", "teachers", "syllabus"]


@app.get("/api/uploads/{filename}")
def get_uploaded_file(filename: str, institute: CurrentInstitute = Depends(get_current_institute)):
    """Uploads are no longer served by a public static mount. Any logged-in
    member of the tenant that owns the record the file is attached to can
    fetch it; everyone else gets a 404 (not a 403, so we don't confirm the
    file even exists to an unauthorized caller)."""
    safe_name = os.path.basename(filename)
    if safe_name != filename or not safe_name:
        raise HTTPException(status_code=404, detail="File not found")
    path = os.path.join(UPLOAD_DIR, safe_name)
    if os.path.commonpath([UPLOAD_DIR, os.path.abspath(path)]) != UPLOAD_DIR or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")

    conn = get_conn()
    try:
        cur = conn.cursor()
        owned = False
        for table in DOCUMENT_TABLES:
            cur.execute(
                f"""SELECT 1 FROM {table} t JOIN branches b ON b.id = t.branch_id
                    WHERE t.document = %s AND b.tenant_id = %s LIMIT 1""",
                (safe_name, institute.id),
            )
            if cur.fetchone():
                owned = True
                break
    finally:
        conn.close()
    if not owned:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path)


# Non-document columns each module accepts from the client, in the order
# they're bound into INSERT/UPDATE statements. Shared by add_record and
# edit_record so the two can never drift out of sync with each other.
RECORD_FIELDS = {
    "students": ["name", "batch", "roll_number", "parent_contact"],
    "teachers": ["name", "subject", "contact_number"],
    "classrooms": ["room_no", "capacity", "building"],
    "syllabus": ["subject", "topic", "teacher_name", "num_lectures", "lecture_date"],
    "attendance": ["student_name", "date", "status"],
    "invigilation": ["teacher_name", "exam_date", "room"],
    "fees": ["student_name", "amount_inr", "status", "due_date", "utr_reference"],
}
# Modules whose table has a 'document' column that a file upload fills in.
RECORD_HAS_DOCUMENT = {"classrooms", "attendance", "invigilation", "fees"}


@app.post("/api/records/{module}")
async def add_record(
    module: str,
    branch_id: int = Form(...),
    data_json: str = Form(...),
    file: UploadFile = File(None),
    institute: CurrentInstitute = Depends(require_write_access),
):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_ownership(branch_id, institute.id)

    data = json.loads(data_json)
    doc_filename = save_upload(file) if file else None

    fields = RECORD_FIELDS[module]
    columns = ["branch_id"] + fields + (["document"] if module in RECORD_HAS_DOCUMENT else [])
    values = [branch_id] + [data.get(f) for f in fields] + ([doc_filename] if module in RECORD_HAS_DOCUMENT else [])
    placeholders = ", ".join("%s" for _ in columns)

    conn = get_conn()
    cursor = conn.cursor()
    # module/columns come from our own fixed RECORD_FIELDS map, never from the
    # request, so building the column list this way is not injectable.
    cursor.execute(f"INSERT INTO {module} ({', '.join(columns)}) VALUES ({placeholders}) RETURNING id", values)
    conn.commit()
    record_id = cursor.fetchone()[0]
    conn.close()
    audit_write(institute, branch_id, "CREATE", None, {"module": module, "id": record_id, **data})
    return {"id": record_id, "status": "success"}


@app.patch("/api/records/{module}/{record_id}")
async def edit_record(
    module: str,
    record_id: int,
    data_json: str = Form(...),
    file: UploadFile = File(None),
    institute: CurrentInstitute = Depends(require_write_access),
):
    """Generic edit for any module - lets the user change any field on an
    existing record, and optionally replace its attached document."""
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        f"""SELECT {module}.* FROM {module}
            JOIN branches ON branches.id = {module}.branch_id
            WHERE {module}.id = %s AND branches.tenant_id = %s""",
        (record_id, institute.id),
    )
    before_row = cursor.fetchone()
    if not before_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Record not found")

    data = json.loads(data_json)
    fields = RECORD_FIELDS[module]
    set_clauses = [f"{f} = %s" for f in fields]
    values = [data.get(f) for f in fields]

    if module in RECORD_HAS_DOCUMENT and file:
        set_clauses.append("document = %s")
        values.append(save_upload(file))

    cursor.execute(f"UPDATE {module} SET {', '.join(set_clauses)} WHERE id = %s", (*values, record_id))
    conn.commit()
    conn.close()
    audit_write(institute, before_row["branch_id"], "UPDATE", dict(before_row), {"module": module, "id": record_id, **data})
    return {"id": record_id, "status": "updated"}


@app.delete("/api/records/{module}/{record_id}")
def delete_record(module: str, record_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)

    conn = get_conn()
    cursor = conn.cursor()
    # Confirm the record belongs to a branch owned by this institute before deleting.
    cursor.execute(
        f"""SELECT {module}.* FROM {module}
            JOIN branches ON branches.id = {module}.branch_id
            WHERE {module}.id = %s AND branches.tenant_id = %s""",
        (record_id, institute.id),
    )
    before_row = cursor.fetchone()
    if not before_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Record not found")

    cursor.execute(f"DELETE FROM {module} WHERE id = %s", (record_id,))
    conn.commit()
    conn.close()
    audit_write(institute, before_row["branch_id"], "DELETE", dict(before_row), None)
    return {"status": "deleted"}


# Column layout expected in a bulk-import CSV for each module (document/email
# intentionally excluded - those are handled per-record, not in bulk).
BULK_IMPORT_COLUMNS = {
    "students": ["name", "batch", "roll_number", "parent_contact"],
    "teachers": ["name", "subject", "contact_number"],
    "classrooms": ["room_no", "capacity"],
    "syllabus": ["subject", "topic", "teacher_name", "num_lectures", "lecture_date"],
    "attendance": ["student_name", "date", "status"],
    "invigilation": ["teacher_name", "exam_date", "room"],
    "fees": ["student_name", "amount_inr", "status", "due_date", "utr_reference"],
}


@app.post("/api/records/{module}/bulk")
async def bulk_import_records(
    module: str,
    branch_id: int = Form(...),
    file: UploadFile = File(...),
    institute: CurrentInstitute = Depends(require_write_access),
):
    """Lets a user drop in a CSV of many rows at once, instead of typing each
    record in individually through the Add Record form."""
    if module not in VALID_MODULES:
        raise HTTPException(status_code=400, detail="Invalid module")
    check_module_access(institute, module)
    verify_branch_ownership(branch_id, institute.id)

    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a .csv file")

    import csv
    import io

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (max 5 MB)")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Could not read file - please save it as UTF-8 CSV")

    reader = csv.DictReader(io.StringIO(text))
    expected_cols = BULK_IMPORT_COLUMNS[module]
    if not reader.fieldnames or not set(expected_cols).issubset(set(c.strip() for c in reader.fieldnames)):
        raise HTTPException(
            status_code=400,
            detail=f"CSV must have these column headers: {', '.join(expected_cols)}",
        )

    conn = get_conn()
    cursor = conn.cursor()
    inserted = 0
    for row in reader:
        row = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
        if not any(row.values()):
            continue  # skip blank rows

        if module == 'students':
            cursor.execute("INSERT INTO students (branch_id, name, batch, roll_number, parent_contact) VALUES (%s, %s, %s, %s, %s)",
                           (branch_id, row.get('name'), row.get('batch'), row.get('roll_number'), row.get('parent_contact')))
        elif module == 'teachers':
            cursor.execute("INSERT INTO teachers (branch_id, name, subject, contact_number) VALUES (%s, %s, %s, %s)",
                           (branch_id, row.get('name'), row.get('subject'), row.get('contact_number')))
        elif module == 'classrooms':
            cursor.execute("INSERT INTO classrooms (branch_id, room_no, capacity, building, document) VALUES (%s, %s, %s, %s, %s)",
                           (branch_id, row.get('room_no'), row.get('capacity'), None, None))
        elif module == 'syllabus':
            cursor.execute("INSERT INTO syllabus (branch_id, subject, topic, teacher_name, num_lectures, lecture_date) VALUES (%s, %s, %s, %s, %s, %s)",
                           (branch_id, row.get('subject'), row.get('topic'), row.get('teacher_name'), row.get('num_lectures'), row.get('lecture_date')))
        elif module == 'attendance':
            cursor.execute("INSERT INTO attendance (branch_id, student_name, date, status, document) VALUES (%s, %s, %s, %s, %s)",
                           (branch_id, row.get('student_name'), row.get('date'), row.get('status'), None))
        elif module == 'invigilation':
            cursor.execute("INSERT INTO invigilation (branch_id, teacher_name, exam_date, room, document) VALUES (%s, %s, %s, %s, %s)",
                           (branch_id, row.get('teacher_name'), row.get('exam_date'), row.get('room'), None))
        elif module == 'fees':
            cursor.execute("INSERT INTO fees (branch_id, student_name, amount_inr, status, due_date, document, utr_reference) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                           (branch_id, row.get('student_name'), row.get('amount_inr'), row.get('status'), row.get('due_date'), None, row.get('utr_reference')))
        inserted += 1

    conn.commit()
    conn.close()
    if inserted == 0:
        raise HTTPException(status_code=400, detail="No valid rows found in that file")
    audit_write(institute, branch_id, "BULK_IMPORT", None, {"module": module, "inserted": inserted})
    return {"status": "success", "inserted": inserted}


# ---------------------------------------------------------------------------
# Attendance (batchwise present/absent marking, sourced from Student Department)
# ---------------------------------------------------------------------------

class AttendanceMarkRequest(BaseModel):
    branch_id: int
    student_name: str
    date: str
    status: str  # 'Present' or 'Absent'


@app.post("/api/attendance/mark")
def mark_attendance(req: AttendanceMarkRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "attendance")
    verify_branch_ownership(req.branch_id, institute.id)
    if req.status not in ("Present", "Absent"):
        raise HTTPException(status_code=400, detail="Status must be 'Present' or 'Absent'")

    conn = get_conn()
    cursor = conn.cursor()
    # Re-marking the same student on the same day replaces the old mark
    # instead of piling up duplicate attendance rows.
    cursor.execute(
        "DELETE FROM attendance WHERE branch_id = %s AND student_name = %s AND date = %s",
        (req.branch_id, req.student_name, req.date),
    )
    cursor.execute(
        "INSERT INTO attendance (branch_id, student_name, date, status) VALUES (%s, %s, %s, %s)",
        (req.branch_id, req.student_name, req.date, req.status),
    )
    conn.commit()
    conn.close()
    audit_write(institute, req.branch_id, "MARK_ATTENDANCE", None, {"student_name": req.student_name, "date": req.date, "status": req.status})
    return {"status": "success"}


@app.get("/api/attendance/{branch_id}/{date}")
def get_attendance_for_date(branch_id: int, date: str, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "attendance")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    if branch_id == 0:
        cursor.execute("SELECT student_name, status FROM attendance WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND date = %s", (institute.id, date))
    else:
        cursor.execute("SELECT student_name, status FROM attendance WHERE branch_id = %s AND date = %s", (branch_id, date))
    marks = {row["student_name"]: row["status"] for row in cursor.fetchall()}
    conn.close()
    return marks


@app.get("/api/attendance/history/{branch_id}")
def get_attendance_history(branch_id: int, student_name: str, institute: CurrentInstitute = Depends(get_current_institute)):
    """Full past attendance record for one student, most recent date first -
    the 'view attendance report for each student' feature."""
    check_module_access(institute, "attendance")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    if branch_id == 0:
        cursor.execute(
            "SELECT date, status FROM attendance WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND student_name = %s ORDER BY date DESC",
            (institute.id, student_name),
        )
    else:
        cursor.execute(
            "SELECT date, status FROM attendance WHERE branch_id = %s AND student_name = %s ORDER BY date DESC",
            (branch_id, student_name),
        )
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    present = sum(1 for h in history if h["status"] == "Present")
    return {
        "student_name": student_name,
        "history": history,
        "total_marked": len(history),
        "present_count": present,
        "absent_count": len(history) - present,
    }


# ---------------------------------------------------------------------------
# Timetable generation
# ---------------------------------------------------------------------------

@app.get("/api/timetable/slots/{branch_id}")
def get_timetable_slots(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "timetables")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    if branch_id == 0:
        cursor.execute("SELECT * FROM timetables_slots WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY branch_id, batch_name, lecture_number", (institute.id,))
    else:
        cursor.execute("SELECT * FROM timetables_slots WHERE branch_id = %s ORDER BY batch_name, lecture_number", (branch_id,))
    slots = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return slots


@app.get("/api/timetable/configs/{branch_id}")
def list_timetable_configs(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    """The saved prerequisites (timings + per-teacher lectures/unavailable
    days) for every batch that's had a timetable generated, so the frontend
    can offer 'load this batch to edit & regenerate' without the user
    retyping anything."""
    check_module_access(institute, "timetables")
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    if branch_id == 0:
        cursor.execute("SELECT branch_id, batch_name, timings_json, teachers_config_json FROM timetable_configs WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY branch_id, batch_name", (institute.id,))
    else:
        cursor.execute("SELECT branch_id, batch_name, timings_json, teachers_config_json FROM timetable_configs WHERE branch_id = %s ORDER BY batch_name", (branch_id,))
    configs = []
    for row in cursor.fetchall():
        try:
            timings = json.loads(row["timings_json"] or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            timings = []
        try:
            teachers_config = json.loads(row["teachers_config_json"] or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            teachers_config = []
        configs.append({
            "batch_name": row["batch_name"],
            "timings": timings if isinstance(timings, list) else [],
            "teachers_config": teachers_config if isinstance(teachers_config, list) else [],
        })
    conn.close()
    return configs


class TimingSlot(BaseModel):
    lecture_number: int
    time_slot: str  # e.g. "09:00 AM - 10:00 AM"


class TimetableGenerateRequest(BaseModel):
    branch_id: int
    batch_name: str
    teachers_config: list  # [{name, subject, lectures_per_week, unavailable_days: []}]
    timings: list[TimingSlot]


@app.post("/api/timetable/generate")
def generate_timetable(req: TimetableGenerateRequest, institute: CurrentInstitute = Depends(require_write_access)):
    """Generate one batch timetable while deliberately spreading each teacher's
    weekly lectures across the week whenever the constraints allow it.

    Preferred weekdays are evenly spaced (for example Mon/Wed/Fri for three
    lectures), then batch, teacher and room conflicts are checked.
    """
    try:
        return _generate_timetable_impl(req, institute)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Timetable generation failed: {e}")


def _generate_timetable_impl(req: "TimetableGenerateRequest", institute: "CurrentInstitute"):
    check_module_access(institute, "timetables")
    verify_branch_ownership(req.branch_id, institute.id)
    if not req.timings:
        raise HTTPException(status_code=400, detail="Add at least one lecture timing")

    conn = get_conn()
    cursor = conn.cursor()

    # Regenerate exactly this batch; other batches remain available for teacher
    # and room conflict checks.
    cursor.execute(
        "DELETE FROM timetables_slots WHERE branch_id = %s AND batch_name = %s",
        (req.branch_id, req.batch_name),
    )

    cursor.execute("SELECT room_no, capacity FROM classrooms WHERE branch_id = %s AND COALESCE(capacity, 0) > 0 ORDER BY capacity, id", (req.branch_id,))
    available_rooms = [(row[0], int(row[1])) for row in cursor.fetchall() if row[0]]
    cursor.execute("SELECT COUNT(*) FROM students WHERE branch_id = %s AND batch = %s", (req.branch_id, req.batch_name))
    batch_size = int(cursor.fetchone()[0] or 0)
    if batch_size and not any(capacity >= batch_size for _, capacity in available_rooms):
        conn.close()
        raise HTTPException(status_code=400, detail=f"Batch has {batch_size} students, but no registered classroom has enough capacity.")

    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    day_index = {day: i for i, day in enumerate(days)}
    timings_sorted = sorted(req.timings, key=lambda t: t.lecture_number)
    generated_slots = []
    warnings = []

    # Current batch load is kept in memory so scoring is cheap.
    batch_load = {day: 0 for day in days}

    def slot_is_free(day, timing, teacher_name):
        slot_time = timing.time_slot
        cursor.execute(
            "SELECT time_slot, teacher FROM timetables_slots WHERE branch_id = %s AND day = %s AND (batch_name = %s OR teacher = %s)",
            (req.branch_id, day, req.batch_name, teacher_name),
        )
        for existing in cursor.fetchall():
            if _time_ranges_overlap(slot_time, existing[0]):
                return False
        return True

    def free_room(day, slot_time):
        for candidate_room, capacity in available_rooms:
            if batch_size and capacity < batch_size:
                continue
            cursor.execute("SELECT time_slot FROM timetables_slots WHERE branch_id = %s AND day = %s AND room = %s", (req.branch_id, day, candidate_room))
            if all(not _time_ranges_overlap(slot_time, row[0]) for row in cursor.fetchall()):
                return candidate_room
        return "Unassigned (no room with sufficient capacity)" if available_rooms else "Unassigned (add a classroom)"

    for t_config in req.teachers_config:
        teacher_name = str(t_config.get('name', '')).strip()
        subject = str(t_config.get('subject', '')).strip()
        target_lectures = max(0, int(t_config.get('lectures_per_week', 0)))
        unavailable = {str(d).strip() for d in t_config.get('unavailable_days', [])}

        if not teacher_name or target_lectures == 0:
            continue

        assigned_count = 0
        used_days = []
        eligible_days = [d for d in days if d not in unavailable]

        # Evenly distribute the requested weekly lectures: 2 -> Mon/Fri,
        # 3 -> Mon/Wed/Fri, 4 -> Mon/Tue/Thu/Fri, 5 -> every weekday.
        if target_lectures <= 1:
            preferred_day_indices = [0] if eligible_days else []
        elif target_lectures <= len(eligible_days):
            preferred_day_indices = [
                round(i * (len(eligible_days) - 1) / (target_lectures - 1))
                for i in range(target_lectures)
            ]
        else:
            preferred_day_indices = [i % len(eligible_days) for i in range(target_lectures)] if eligible_days else []

        # Each lecture is chosen from ALL free day/time candidates. The scoring
        # strongly prefers the next evenly-spaced weekday, then an unused day,
        # then a lightly loaded day/time. Conflicts can still force a fallback.
        for lecture_index in range(target_lectures):
            candidates = []
            desired_idx = preferred_day_indices[lecture_index] if preferred_day_indices else 0
            desired_day = eligible_days[desired_idx] if eligible_days else None
            for day in days:
                if day in unavailable:
                    continue
                for timing in timings_sorted:
                    if not slot_is_free(day, timing, teacher_name):
                        continue
                    room = free_room(day, timing.time_slot)
                    idx = day_index[day]
                    min_distance = min((abs(idx - used) for used in used_days), default=5)
                    same_day_penalty = 1000 if idx in used_days and len(set(used_days)) < len(eligible_days) else 0
                    preferred_distance = abs(idx - day_index[desired_day]) if desired_day else 0
                    # Lower score wins. Preferred weekdays dominate, while
                    # day load and distance provide sensible tie-breaking.
                    score = (
                        preferred_distance * 100
                        + same_day_penalty
                        + batch_load[day] * 25
                        - min_distance * 2
                        + idx * 0.01
                        + timing.lecture_number * 0.001
                    )
                    candidates.append((score, day, timing, room))

            if not candidates:
                break

            _, day, timing, room = min(candidates, key=lambda x: x[0])
            cursor.execute(
                """INSERT INTO timetables_slots
                   (branch_id, batch_name, day, time_slot, lecture_number, subject, teacher, room)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (req.branch_id, req.batch_name, day, timing.time_slot,
                 timing.lecture_number, subject, teacher_name, room),
            )
            generated_slots.append({
                "day": day, "time_slot": timing.time_slot,
                "lecture_number": timing.lecture_number,
                "subject": subject, "teacher": teacher_name, "room": room,
            })
            assigned_count += 1
            batch_load[day] += 1
            used_days.append(day_index[day])

        if assigned_count < target_lectures:
            warnings.append(
                f"{teacher_name}: only scheduled {assigned_count}/{target_lectures} lectures "
                f"(not enough free day/time slots without a conflict)."
            )

    cursor.execute(
        "SELECT id FROM timetable_configs WHERE branch_id = %s AND batch_name = %s",
        (req.branch_id, req.batch_name),
    )
    existing_config = cursor.fetchone()
    timings_json = json.dumps([t.dict() for t in req.timings])
    teachers_config_json = json.dumps(req.teachers_config)
    now_iso = datetime.utcnow().isoformat()
    if existing_config:
        cursor.execute(
            "UPDATE timetable_configs SET timings_json = %s, teachers_config_json = %s, updated_at = %s WHERE id = %s",
            (timings_json, teachers_config_json, now_iso, existing_config[0]),
        )
    else:
        cursor.execute(
            """INSERT INTO timetable_configs (branch_id, batch_name, timings_json, teachers_config_json, updated_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (req.branch_id, req.batch_name, timings_json, teachers_config_json, now_iso),
        )

    conn.commit()
    conn.close()
    audit_write(institute, req.branch_id, "GENERATE_TIMETABLE", None, {"batch_name": req.batch_name, "slots": generated_slots, "warnings": warnings})
    return {"status": "success", "slots": generated_slots, "warnings": warnings}


@app.delete("/api/timetable/all/{branch_id}")
def delete_all_timetables(branch_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    """Completely reset the timetable workspace for the selected branch."""
    check_module_access(institute, "timetables")
    verify_branch_ownership(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM timetables_slots WHERE branch_id = %s", (branch_id,))
    slots_deleted = cursor.rowcount
    cursor.execute("DELETE FROM timetable_configs WHERE branch_id = %s", (branch_id,))
    configs_deleted = cursor.rowcount
    conn.commit()
    conn.close()
    audit_write(institute, branch_id, "DELETE_TIMETABLES", {"slots_deleted": slots_deleted, "configs_deleted": configs_deleted}, None)
    return {"status": "cleared", "slots_deleted": slots_deleted, "configs_deleted": configs_deleted}


class TimetableSlotEdit(BaseModel):
    day: str
    time_slot: str
    subject: str
    teacher: str
    room: str


@app.patch("/api/timetable/slots/{slot_id}")
def edit_timetable_slot(slot_id: int, req: TimetableSlotEdit, institute: CurrentInstitute = Depends(require_write_access)):
    """Manual override with the same teacher/room overlap guarantees as auto-generation."""
    check_module_access(institute, "timetables")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT timetables_slots.* FROM timetables_slots
           JOIN branches ON branches.id = timetables_slots.branch_id
           WHERE timetables_slots.id = %s AND branches.tenant_id = %s""",
        (slot_id, institute.id),
    )
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Slot not found")
    cursor.execute(
        "SELECT COUNT(*) FROM timetables_slots WHERE branch_id = %s AND id <> %s AND day = %s AND time_slot = %s AND teacher = %s",
        (existing["branch_id"], slot_id, req.day, req.time_slot, req.teacher),
    )
    if cursor.fetchone()[0]:
        conn.close(); raise HTTPException(status_code=409, detail="Teacher already has another lecture in this time slot.")
    cursor.execute(
        "SELECT COUNT(*) FROM timetables_slots WHERE branch_id = %s AND id <> %s AND day = %s AND time_slot = %s AND room = %s",
        (existing["branch_id"], slot_id, req.day, req.time_slot, req.room),
    )
    if cursor.fetchone()[0]:
        conn.close(); raise HTTPException(status_code=409, detail="Room is already occupied in this time slot.")
    cursor.execute("SELECT capacity FROM classrooms WHERE branch_id = %s AND room_no = %s", (existing["branch_id"], req.room))
    room_capacity = cursor.fetchone()
    if not room_capacity:
        conn.close(); raise HTTPException(status_code=400, detail="Selected room is not registered in this branch.")
    cursor.execute("SELECT COUNT(*) FROM students WHERE branch_id = %s AND batch = %s", (existing["branch_id"], existing["batch_name"]))
    batch_size = cursor.fetchone()[0]
    if batch_size and int(room_capacity[0] or 0) < batch_size:
        conn.close(); raise HTTPException(status_code=400, detail="Selected room does not have enough capacity for this batch.")
    cursor.execute(
        "UPDATE timetables_slots SET day = %s, time_slot = %s, subject = %s, teacher = %s, room = %s WHERE id = %s",
        (req.day, req.time_slot, req.subject, req.teacher, req.room, slot_id),
    )
    conn.commit()
    conn.close()
    audit_write(institute, existing["branch_id"], "UPDATE_TIMETABLE_SLOT", dict(existing), {"day": req.day, "time_slot": req.time_slot, "subject": req.subject, "teacher": req.teacher, "room": req.room})
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# Exam seating
# ---------------------------------------------------------------------------

class SeatingGenerateRequest(BaseModel):
    branch_id: int
    exam_date: str
    room_number: str
    rows: int
    columns: int


def _build_seating_layout(students, rows, columns):
    capacity=rows*columns; selected=list(students[:capacity])
    if not selected: return []
    buckets=defaultdict(list)
    for st in selected: buckets[str(st.get("batch") or "").strip()].append(st)
    for v in buckets.values(): random.shuffle(v)
    if max(map(len,buckets.values()))>(capacity+1)//2:
        raise HTTPException(status_code=400,detail="The seating constraints cannot be satisfied: one batch has too many students for this grid.")
    grid=[[None]*columns for _ in range(rows)]; pos=[(r,c) for r in range(rows) for c in range(columns)]
    def ok(st,r,c):
        batch=str(st.get("batch") or "").strip()
        left=c and grid[r][c-1] is not None and str(grid[r][c-1].get("batch") or "").strip()==batch
        front=r and grid[r-1][c] is not None and str(grid[r-1][c].get("batch") or "").strip()==batch
        return not (left or front)
    def solve(i=0):
        if i==len(pos): return True
        r,c=pos[i]; choices=[v for v in buckets.values() if v]; random.shuffle(choices); choices.sort(key=len,reverse=True)
        for v in choices:
            st=v.pop()
            if ok(st,r,c):
                grid[r][c]=st
                if solve(i+1): return True
                grid[r][c]=None
            v.append(st)
        return False
    if not solve():
        raise HTTPException(status_code=400,detail="The seating constraints cannot be satisfied with the selected students and grid size. Increase the grid size or use more than one batch.")
    return [{"row":r+1,"column":c+1,"student_id":grid[r][c]["id"],"name":grid[r][c]["name"],"batch":grid[r][c]["batch"],"roll_number":grid[r][c]["roll_number"]} for r in range(rows) for c in range(columns) if grid[r][c] is not None]



@app.get("/api/seating/{branch_id}")
def get_seating_layouts(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, SEATING_MODULE)
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn(); cur = conn.cursor()
    if branch_id == 0:
        cur.execute("SELECT id, branch_id, exam_date, room_number, rows, columns, assignments_json, created_at FROM exam_seatings WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) ORDER BY exam_date DESC, id DESC", (institute.id,))
    else:
        cur.execute("SELECT id, branch_id, exam_date, room_number, rows, columns, assignments_json, created_at FROM exam_seatings WHERE branch_id = %s ORDER BY exam_date DESC, id DESC", (branch_id,))
    rows = cur.fetchall()
    conn.close()
    return [{**dict(r), "assignments": json.loads(r["assignments_json"])} for r in rows]


@app.post("/api/seating/generate")
def generate_seating(req: SeatingGenerateRequest, institute: CurrentInstitute = Depends(require_write_access)):
    try:
        return _generate_seating_impl(req, institute)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Seating generation failed: {e}")


def _generate_seating_impl(req: "SeatingGenerateRequest", institute: "CurrentInstitute"):
    check_module_access(institute, SEATING_MODULE)
    verify_branch_ownership(req.branch_id, institute.id)
    if req.rows < 1 or req.columns < 1:
        raise HTTPException(status_code=400, detail="Rows and columns must both be at least 1.")
    room_number = req.room_number.strip()
    if not room_number:
        raise HTTPException(status_code=400, detail="Room number is required.")

    conn = get_conn()

    # Any registered classroom in this institute may host an exam. Classroom
    # department/branch ownership is intentionally not a seating restriction.
    room_cur = conn.cursor()
    room_cur.execute(
        """SELECT c.room_no, c.capacity
           FROM classrooms c
           JOIN branches b ON b.id = c.branch_id
           WHERE b.tenant_id = %s AND c.room_no = %s
           LIMIT 1""",
        (institute.id, room_number),
    )
    room = room_cur.fetchone()
    if not room:
        conn.close()
        raise HTTPException(status_code=400, detail="Selected exam room is not registered for this institute.")

    requested_capacity = req.rows * req.columns
    room_capacity = int(room[1] or 0)
    if room_capacity <= 0:
        conn.close()
        raise HTTPException(status_code=400, detail="Selected room has no valid seating capacity.")
    if requested_capacity > room_capacity:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Grid capacity ({requested_capacity}) exceeds room capacity ({room_capacity}).")

    # Re-generating one room replaces only that room's previous allocation.
    cursor = conn.cursor()
    cursor.execute(
        "SELECT assignments_json FROM exam_seatings WHERE branch_id = %s AND exam_date = %s AND room_number = %s",
        (req.branch_id, req.exam_date, room_number),
    )
    old_room = cursor.fetchone()
    old_student_ids = set()
    if old_room:
        try:
            old_student_ids = {
                int(a["student_id"])
                for a in json.loads(old_room["assignments_json"] or "[]")
                if a.get("student_id") is not None
            }
        except (TypeError, ValueError, KeyError):
            pass
    cursor.execute(
        "DELETE FROM exam_seatings WHERE branch_id = %s AND exam_date = %s AND room_number = %s",
        (req.branch_id, req.exam_date, room_number),
    )

    # Fetch the selected branch's complete student pool, remove students already
    # consumed by other rooms for this exam, then randomize the remaining pool.
    cursor.execute(
        """SELECT id, name, COALESCE(batch, '') AS batch, COALESCE(roll_number, '') AS roll_number
           FROM students WHERE branch_id = %s""",
        (req.branch_id,),
    )
    student_rows = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "SELECT assignments_json FROM exam_seatings WHERE branch_id = %s AND exam_date = %s",
        (req.branch_id, req.exam_date),
    )
    assigned_elsewhere = set()
    for row in cursor.fetchall():
        try:
            assigned_elsewhere.update(
                int(a["student_id"])
                for a in json.loads(row["assignments_json"] or "[]")
                if a.get("student_id") is not None
            )
        except (TypeError, ValueError, KeyError):
            continue
    assigned_elsewhere.difference_update(old_student_ids)

    remaining_students = [
        student for student in student_rows
        if int(student["id"]) not in assigned_elsewhere
    ]
    random.shuffle(remaining_students)
    if len(remaining_students) < requested_capacity:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail=f"Only {len(remaining_students)} unassigned students remain for this exam; {requested_capacity} seats were requested.",
        )
    assignments = _build_seating_layout(remaining_students, req.rows, req.columns)

    cursor.execute(
        """INSERT INTO exam_seatings (branch_id, exam_date, room_number, rows, columns, assignments_json, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (req.branch_id, req.exam_date, room_number, req.rows, req.columns,
         json.dumps(assignments), datetime.utcnow().isoformat()),
    )
    layout_id = cursor.fetchone()[0]
    conn.commit(); conn.close()
    audit_write(institute, req.branch_id, "GENERATE_SEATING", None, {"id": layout_id, "exam_date": req.exam_date, "room_number": room_number, "rows": req.rows, "columns": req.columns, "assignments": assignments})
    return {"status": "success", "id": layout_id, "assignments": assignments}


@app.delete("/api/seating/{layout_id}")
def delete_seating_layout(layout_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, SEATING_MODULE)
    conn = get_conn(); cursor = conn.cursor()
    cursor.execute(
        """SELECT exam_seatings.* FROM exam_seatings JOIN branches ON branches.id = exam_seatings.branch_id
           WHERE exam_seatings.id = %s AND branches.tenant_id = %s""",
        (layout_id, institute.id),
    )
    before = cursor.fetchone()
    if not before:
        conn.close(); raise HTTPException(status_code=404, detail="Seating layout not found")
    cursor.execute("DELETE FROM exam_seatings WHERE id = %s", (layout_id,))
    conn.commit(); conn.close()
    audit_write(institute, before["branch_id"], "DELETE_SEATING", dict(before), None)
    return {"status": "deleted"}




class FeeMarkPaidRequest(BaseModel):
    utr_reference: str


@app.post("/api/fees/{fee_id}/mark-paid")
def mark_fee_paid(fee_id: int, req: FeeMarkPaidRequest, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "fees")
    utr = req.utr_reference.strip()
    if not utr:
        raise HTTPException(status_code=400, detail="UTR / Reference No. is required.")
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM fees WHERE id = %s AND branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)", (fee_id, institute.id))
    before = cur.fetchone()
    if not before:
        conn.close(); raise HTTPException(status_code=404, detail="Fee record not found")
    cur.execute("UPDATE fees SET status='Paid', utr_reference=%s, paid_at=NOW(), paid_by=%s WHERE id=%s", (utr, institute.user_id, fee_id))
    cur.execute("SELECT * FROM fees WHERE id = %s", (fee_id,)); after=cur.fetchone()
    conn.commit(); conn.close()
    audit_write(institute, before["branch_id"], "FEE_MARK_PAID", dict(before), dict(after))
    return {"status":"paid","fee":dict(after)}

# ---------------------------------------------------------------------------
# Branch analytics
# ---------------------------------------------------------------------------

@app.get("/api/analytics/{branch_id}")
def get_analytics(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    """Return analytics without allowing one malformed/legacy record to take
    down the entire dashboard. Every query remains server-side and tenant-scoped."""
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cur = conn.cursor()
    scope = "branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "branch_id = %s"
    scope_param = institute.id if branch_id == 0 else branch_id

    def one(sql, params, default=0):
        try:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row[0] if row else default
        except Exception as exc:
            conn.rollback()
            print(f"[analytics] query failed: {exc}")
            return default

    def all_rows(sql, params, default=None):
        try:
            cur.execute(sql, params)
            return cur.fetchall()
        except Exception as exc:
            conn.rollback()
            print(f"[analytics] query failed: {exc}")
            return [] if default is None else default

    students_total = one(f"SELECT COUNT(*) FROM students WHERE {scope}", (scope_param,))
    teachers_total = one(f"SELECT COUNT(*) FROM teachers WHERE {scope}", (scope_param,))
    classrooms_total = one(f"SELECT COUNT(*) FROM classrooms WHERE {scope}", (scope_param,))
    seating_plans = one(f"SELECT COUNT(*) FROM exam_seatings WHERE {scope}", (scope_param,))
    try:
        cur.execute(f"SELECT COALESCE(SUM(amount_inr),0), COUNT(*) FROM fees WHERE {scope} AND LOWER(COALESCE(status,'')) = 'paid'", (scope_param,))
        paid_amount, paid_count = cur.fetchone() or (0, 0)
    except Exception as exc:
        conn.rollback(); print(f"[analytics] fees paid query failed: {exc}"); paid_amount, paid_count = 0, 0
    try:
        cur.execute(f"SELECT COALESCE(SUM(amount_inr),0), COUNT(*) FROM fees WHERE {scope} AND LOWER(COALESCE(status,'')) != 'paid'", (scope_param,))
        pending_amount, pending_count = cur.fetchone() or (0, 0)
    except Exception as exc:
        conn.rollback(); print(f"[analytics] fees pending query failed: {exc}"); pending_amount, pending_count = 0, 0

    now_ist = datetime.now(timezone.utc) + IST_OFFSET
    today = now_ist.date()
    week_start = today - timedelta(days=6)
    att_counts = {}
    rows = all_rows(f"SELECT status, COUNT(*) FROM attendance WHERE {scope} AND date >= %s AND date <= %s GROUP BY status", (scope_param, week_start.isoformat(), today.isoformat()))
    for r in rows:
        att_counts[str(r[0])] = int(r[1])
    marked = sum(att_counts.values())
    present = att_counts.get('Present', 0)
    absent = att_counts.get('Absent', 0)

    trend = []
    for i in range(7):
        d = week_start + timedelta(days=i)
        rows = all_rows(f"SELECT COUNT(*) FILTER (WHERE status='Present'), COUNT(*) FROM attendance WHERE {scope} AND date = %s", (scope_param, d.isoformat()))
        p, total = (rows[0] if rows else (0, 0))
        trend.append({"label": d.strftime('%a'), "pct": round(100 * p / total) if total else 0, "present": int(p or 0), "marked": int(total or 0)})

    by_batch = []
    rows = all_rows(f"""SELECT COALESCE(s.batch,'Unassigned') AS batch,
                              COUNT(*) FILTER (WHERE a.status='Present') AS present,
                              COUNT(*) AS total
                       FROM attendance a
                       LEFT JOIN students s ON s.branch_id=a.branch_id AND s.name=a.student_name
                       WHERE a.{ 'branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)' if branch_id == 0 else 'branch_id = %s'}
                         AND a.date >= %s
                       GROUP BY COALESCE(s.batch,'Unassigned') ORDER BY batch""", (scope_param, week_start.isoformat()))
    for b, pv, tv in rows:
        by_batch.append({"batch": b, "present": int(pv or 0), "total": int(tv or 0), "pct": round(100 * pv / tv) if tv else 0})

    by_day = [{"day": r[0], "count": int(r[1])} for r in all_rows(f"SELECT day, COUNT(*) FROM timetables_slots WHERE {scope} GROUP BY day ORDER BY MIN(id)", (scope_param,))]
    scheduled = int(one(f"SELECT COUNT(*) FROM timetables_slots WHERE {scope}", (scope_param,)))
    logged = int(one(f"SELECT COUNT(*) FROM syllabus WHERE {scope} AND lecture_date >= %s", (scope_param, week_start.isoformat())))

    # Payment date is intentionally derived from paid_at first, then a strictly
    # validated ISO due_date fallback. No arbitrary text is cast to a date.
    revenue_rows = all_rows(f"""
        SELECT COALESCE(TO_CHAR(paid_at, 'YYYY-MM-DD'),
                        CASE WHEN due_date ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' THEN due_date END) AS day,
               COALESCE(SUM(amount_inr),0)
        FROM fees
        WHERE {scope} AND LOWER(COALESCE(status,''))='paid'
        GROUP BY 1
        HAVING COALESCE(TO_CHAR(paid_at, 'YYYY-MM-DD'),
                        CASE WHEN due_date ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' THEN due_date END) IS NOT NULL
        ORDER BY 1 DESC LIMIT 30""", (scope_param,))
    revenue = [{"date": r[0], "amount": float(r[1] or 0)} for r in revenue_rows]
    conn.close()
    return {
        "students_total": int(students_total or 0),
        "teachers_total": int(teachers_total or 0),
        "classrooms_total": int(classrooms_total or 0),
        "seating_plans": int(seating_plans or 0),
        "attendance": {"present": present, "absent": absent, "marked": marked, "pct": round(100 * present / marked) if marked else 0, "trend": trend, "by_batch": by_batch},
        "fees": {"paid_amount": float(paid_amount or 0), "paid_count": int(paid_count or 0), "pending_amount": float(pending_amount or 0), "pending_count": int(pending_count or 0), "revenue": revenue},
        "lectures": {"scheduled_this_week": scheduled, "logged_last_7_days": logged, "by_day": by_day},
    }


# ---------------------------------------------------------------------------
# Dashboard analytics
# ---------------------------------------------------------------------------

IST_OFFSET = timedelta(hours=5, minutes=30)


def _parse_time_range(time_slot: str):
    """Best-effort parse of a free-text '09:00 AM - 10:00 AM' timing string
    into two time objects. Returns (None, None) if it doesn't match - a
    malformed timing just never counts as 'ongoing', it doesn't crash."""
    import re
    m = re.match(r"\s*(\d{1,2}:\d{2}\s*[AaPp][Mm])\s*-\s*(\d{1,2}:\d{2}\s*[AaPp][Mm])\s*", time_slot or "")
    if not m:
        return None, None
    try:
        start = datetime.strptime(m.group(1).upper().replace(" ", ""), "%I:%M%p").time()
        end = datetime.strptime(m.group(2).upper().replace(" ", ""), "%I:%M%p").time()
        return start, end
    except ValueError:
        return None, None


def _time_ranges_overlap(a: str, b: str) -> bool:
    a0, a1 = _parse_time_range(a); b0, b1 = _parse_time_range(b)
    if not all((a0, a1, b0, b1)): return a.strip() == b.strip()
    return a0 < b1 and b0 < a1


@app.get("/api/dashboard/{branch_id}")
def get_dashboard(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    verify_branch_read_access(branch_id, institute.id)
    conn = get_conn()
    cursor = conn.cursor()

    now_ist = datetime.utcnow() + IST_OFFSET
    today = now_ist.date()
    week_start = today - timedelta(days=6)  # last 7 days including today

    # --- Attendance this week, per batch ---
    attendance_week = []
    if institute.is_owner or "attendance" in institute.allowed_modules:
        cursor.execute("SELECT id, name, batch FROM students WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s)" if branch_id == 0 else "SELECT id, name, batch FROM students WHERE branch_id = %s", (institute.id if branch_id == 0 else branch_id,))
        student_batch = {row["name"]: (row["batch"] or "Unassigned") for row in cursor.fetchall()}
        cursor.execute(
            "SELECT student_name, status FROM attendance WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND date >= %s AND date <= %s" if branch_id == 0 else "SELECT student_name, status FROM attendance WHERE branch_id = %s AND date >= %s AND date <= %s",
            (institute.id if branch_id == 0 else branch_id, week_start.isoformat(), today.isoformat()),
        )
        per_batch = {}
        for row in cursor.fetchall():
            batch = student_batch.get(row["student_name"], "Unassigned")
            b = per_batch.setdefault(batch, {"present": 0, "total": 0})
            b["total"] += 1
            if row["status"] == "Present":
                b["present"] += 1
        for batch, stats in sorted(per_batch.items()):
            pct = round(100 * stats["present"] / stats["total"]) if stats["total"] else 0
            attendance_week.append({"batch": batch, "present": stats["present"], "total": stats["total"], "pct": pct})

    # --- Fees pending ---
    fees_pending_total, fees_pending_count = 0, 0
    if institute.is_owner or "fees" in institute.allowed_modules:
        cursor.execute(
            "SELECT COUNT(*), COALESCE(SUM(amount_inr), 0) FROM fees WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND LOWER(COALESCE(status, '')) != 'paid'" if branch_id == 0 else "SELECT COUNT(*), COALESCE(SUM(amount_inr), 0) FROM fees WHERE branch_id = %s AND LOWER(COALESCE(status, '')) != 'paid'",
            (institute.id if branch_id == 0 else branch_id,),
        )
        fees_pending_count, fees_pending_total = cursor.fetchone()

    # --- Lectures ongoing right now, per batch ---
    ongoing_lectures = []
    if institute.is_owner or "timetables" in institute.allowed_modules:
        today_name = now_ist.strftime("%A")
        now_time = now_ist.time()
        cursor.execute(
            "SELECT batch_name, day, time_slot, subject, teacher, room FROM timetables_slots WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) AND day = %s" if branch_id == 0 else "SELECT batch_name, day, time_slot, subject, teacher, room FROM timetables_slots WHERE branch_id = %s AND day = %s",
            (institute.id if branch_id == 0 else branch_id, today_name),
        )
        for row in cursor.fetchall():
            start, end = _parse_time_range(row["time_slot"])
            if start and end and start <= now_time <= end:
                ongoing_lectures.append({
                    "batch_name": row["batch_name"], "time_slot": row["time_slot"],
                    "subject": row["subject"], "teacher": row["teacher"], "room": row["room"],
                })

    conn.close()
    return {
        "attendance_week": attendance_week,
        "fees_pending_total": fees_pending_total,
        "fees_pending_count": fees_pending_count,
        "ongoing_lectures": ongoing_lectures,
        "as_of": now_ist.isoformat(),
    }


# ---------------------------------------------------------------------------
# Parallax — AI assistant over the institute's own data
# ---------------------------------------------------------------------------

PARALLAX_TABLES = {
    "students": "SELECT name, email, batch, status, roll_number, parent_contact FROM students",
    "teachers": "SELECT name, subject, department, contact_number FROM teachers",
    "classrooms": "SELECT room_no, capacity, building FROM classrooms",
    "syllabus": "SELECT subject, semester, units, topic, teacher_name, num_lectures, lecture_date FROM syllabus",
    "attendance": "SELECT student_name, date, status FROM attendance",
    "timetables_slots": "SELECT batch_name, day, time_slot, lecture_number, subject, teacher, room FROM timetables_slots",
    "invigilation": "SELECT teacher_name, exam_date, room FROM invigilation",
    "fees": "SELECT student_name, amount_inr, status, due_date FROM fees",
    "exam_seatings": "SELECT exam_date, room_number, rows, columns FROM exam_seatings",
}
PARALLAX_MAX_ROWS_PER_TABLE = 400


class AssistantQuery(BaseModel):
    question: str


def _parallax_gather_context(branch_id: int, institute: "CurrentInstitute") -> str:
    """Pulls a compact, branch-scoped snapshot of every module's data so
    Parallax can answer questions in any phrasing without needing the user
    to name a module or table."""
    conn = get_conn()
    cursor = conn.cursor()
    scope_hq = branch_id == 0
    blocks = []
    for table, base_sql in PARALLAX_TABLES.items():
        module_name = "timetables" if table in ("timetables_slots",) else ("seating" if table == "exam_seatings" else table)
        if not institute.is_owner and module_name not in institute.allowed_modules:
            continue
        if scope_hq:
            sql = f"{base_sql} WHERE branch_id IN (SELECT id FROM branches WHERE tenant_id = %s) LIMIT {PARALLAX_MAX_ROWS_PER_TABLE}"
            params = (institute.id,)
        else:
            sql = f"{base_sql} WHERE branch_id = %s LIMIT {PARALLAX_MAX_ROWS_PER_TABLE}"
            params = (branch_id,)
        try:
            cursor.execute(sql, params)
            rows = [dict(r) for r in cursor.fetchall()]
        except Exception:
            conn.rollback()
            rows = []
        if rows:
            blocks.append(f"### {table} ({len(rows)} rows)\n{json.dumps(rows, default=str)}")
    conn.close()
    return "\n\n".join(blocks) if blocks else "(no data recorded yet for this branch)"


def _parallax_call_gemini(context: str, question: str) -> str:
    if not GEMINI_API_KEY:
        raise HTTPException(status_code=503, detail="Parallax is not configured: GEMINI_API_KEY is missing on the server.")
    import urllib.request
    import urllib.error

    prompt = (
        "You are Parallax, an in-app data assistant for a school/institute management system. "
        "Answer the user's question using ONLY the data given below. The question may be phrased "
        "as a command, a fragment, casual text, or any other format — always answer it as a question "
        "about the data. If the data doesn't contain the answer, say so plainly instead of guessing. "
        "Be concise and factual; use short lists or numbers where that's clearer than prose.\n\n"
        f"=== INSTITUTE DATA ===\n{context}\n\n=== QUESTION ===\n{question}"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Parallax upstream error: {e.read().decode('utf-8', 'ignore')[:300]}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Parallax request failed: {e}")
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError):
        return "Parallax couldn't produce an answer for that just now — try rephrasing."


@app.post("/api/assistant/{branch_id}")
def parallax_ask(branch_id: int, body: AssistantQuery, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute, "assistant")
    verify_branch_read_access(branch_id, institute.id)
    question = (body.question or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="Ask Parallax something first.")
    context = _parallax_gather_context(branch_id, institute)
    answer = _parallax_call_gemini(context, question)
    audit_write(institute, branch_id if branch_id else None, "PARALLAX_QUERY", None, {"question": question})
    return {"answer": answer}


@app.delete("/api/assistant/history/{branch_id}")
def clear_parallax_history(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    check_module_access(institute,"assistant")
    verify_branch_read_access(branch_id,institute.id)
    return {"status":"cleared","persistent_history":False}

# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def read_root():
    return HTMLResponse(content=HTML_CONTENT, status_code=200)


HTML_CONTENT = Path(__file__).with_name("index.html").read_text(encoding="utf-8")

# === EXAM RESULTS / HISTORY UPGRADE ===
# Persistent exam result and exam-history records. This block is intentionally
# additive so existing application code/data remains untouched.

EXAM_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS exam_results (
    id SERIAL PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    batch_name TEXT NOT NULL,
    subjects TEXT NOT NULL,
    topics TEXT NOT NULL,
    exam_date TEXT NOT NULL,
    overall_marks NUMERIC(12,2) NOT NULL,
    student_id INTEGER REFERENCES students(id) ON DELETE SET NULL,
    student_name TEXT NOT NULL,
    roll_number TEXT,
    marks NUMERIC(12,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""
EXAM_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS exam_history (
    id SERIAL PRIMARY KEY,
    branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    topic TEXT NOT NULL,
    batch_name TEXT NOT NULL,
    exam_date TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

def _init_exam_upgrade_db():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(EXAM_RESULTS_TABLE)
        cur.execute(EXAM_HISTORY_TABLE)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_exam_results_branch_batch ON exam_results(branch_id, batch_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_exam_history_branch_date ON exam_history(branch_id, exam_date)")
        conn.commit()
    finally:
        conn.close()

_init_exam_upgrade_db()

class ExamResultPayload(BaseModel):
    branch_id: int
    batch_name: str
    subjects: str
    topics: str
    exam_date: str
    overall_marks: float
    student_id: int | None = None
    student_name: str
    roll_number: str | None = None
    marks: float | None = None

class ExamHistoryPayload(BaseModel):
    branch_id: int
    subject: str
    topic: str
    batch_name: str
    exam_date: str

def _exam_branch_check(institute, branch_id: int):
    check_module_access(institute, "examination")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM branches WHERE id=%s AND institute_id=%s", (branch_id, institute.id))
        if not cur.fetchone():
            raise HTTPException(status_code=403, detail="Branch access denied")
    finally:
        conn.close()

def _valid_marks(marks, overall):
    if marks is None:
        return None
    if marks < 0 or marks > overall:
        raise HTTPException(status_code=400, detail="Student marks must be between 0 and the overall marks.")
    return marks

@app.get("/api/exam/results/students/{branch_id}")
def exam_result_students(branch_id: int, batch: str, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id)
    if not batch.strip():
        raise HTTPException(status_code=400, detail="Batch is required")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, COALESCE(roll_number, '') AS roll_number
            FROM students
            WHERE branch_id=%s AND LOWER(TRIM(COALESCE(batch,'')))=LOWER(TRIM(%s))
            ORDER BY LOWER(COALESCE(name,'')), LOWER(COALESCE(roll_number,''))
        """, (branch_id, batch))
        return {"students": [dict(r) for r in cur.fetchall()]}
    finally:
        conn.close()

@app.get("/api/exam/results/{branch_id}")
def list_exam_results(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, branch_id, batch_name, subjects, topics, exam_date,
                   overall_marks, student_id, student_name, roll_number, marks,
                   created_at, updated_at
            FROM exam_results WHERE branch_id=%s
            ORDER BY exam_date DESC, batch_name, student_name, id
        """, (branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

@app.post("/api/exam/results")
def create_exam_result(payload: ExamResultPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id)
    overall = float(payload.overall_marks)
    if overall <= 0:
        raise HTTPException(status_code=400, detail="Overall marks must be greater than zero.")
    marks = _valid_marks(payload.marks, overall)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO exam_results
            (branch_id,batch_name,subjects,topics,exam_date,overall_marks,student_id,student_name,roll_number,marks)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
        """, (payload.branch_id,payload.batch_name.strip(),payload.subjects.strip(),payload.topics.strip(),payload.exam_date,
              overall,payload.student_id,payload.student_name.strip(),payload.roll_number,marks))
        row = dict(cur.fetchone()); conn.commit(); return row
    finally:
        conn.close()

@app.patch("/api/exam/results/{result_id}")
def update_exam_result(result_id: int, payload: ExamResultPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id)
    marks = _valid_marks(payload.marks, float(payload.overall_marks))
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE exam_results SET batch_name=%s, subjects=%s, topics=%s, exam_date=%s,
              overall_marks=%s, student_id=%s, student_name=%s, roll_number=%s, marks=%s, updated_at=NOW()
            WHERE id=%s AND branch_id=%s RETURNING *
        """, (payload.batch_name.strip(),payload.subjects.strip(),payload.topics.strip(),payload.exam_date,
              payload.overall_marks,payload.student_id,payload.student_name.strip(),payload.roll_number,marks,result_id,payload.branch_id))
        row = cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="Result record not found")
        result = dict(row); conn.commit(); return result
    finally:
        conn.close()

@app.delete("/api/exam/results/{result_id}")
def delete_exam_result(result_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "examination")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM exam_results WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE institute_id=%s) RETURNING id", (result_id,institute.id))
        if not cur.fetchone(): raise HTTPException(status_code=404, detail="Result record not found")
        conn.commit(); return {"status":"success"}
    finally:
        conn.close()

@app.get("/api/exam/history/{branch_id}")
def list_exam_history(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    _exam_branch_check(institute, branch_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, branch_id, subject, topic, batch_name, exam_date, created_at, updated_at FROM exam_history WHERE branch_id=%s ORDER BY exam_date DESC, id DESC", (branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

@app.post("/api/exam/history")
def create_exam_history(payload: ExamHistoryPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO exam_history (branch_id,subject,topic,batch_name,exam_date) VALUES (%s,%s,%s,%s,%s) RETURNING *", (payload.branch_id,payload.subject.strip(),payload.topic.strip(),payload.batch_name.strip(),payload.exam_date))
        row=dict(cur.fetchone()); conn.commit(); return row
    finally:
        conn.close()

@app.patch("/api/exam/history/{history_id}")
def update_exam_history(history_id: int, payload: ExamHistoryPayload, institute: CurrentInstitute = Depends(require_write_access)):
    _exam_branch_check(institute, payload.branch_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE exam_history SET subject=%s, topic=%s, batch_name=%s, exam_date=%s, updated_at=NOW() WHERE id=%s AND branch_id=%s RETURNING *", (payload.subject.strip(),payload.topic.strip(),payload.batch_name.strip(),payload.exam_date,history_id,payload.branch_id))
        row=cur.fetchone()
        if not row: raise HTTPException(status_code=404, detail="History record not found")
        result=dict(row); conn.commit(); return result
    finally:
        conn.close()

@app.delete("/api/exam/history/{history_id}")
def delete_exam_history(history_id: int, institute: CurrentInstitute = Depends(require_write_access)):
    check_module_access(institute, "examination")
    conn = get_conn()
    try:
        cur=conn.cursor()
        cur.execute("DELETE FROM exam_history WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE institute_id=%s) RETURNING id", (history_id,institute.id))
        if not cur.fetchone(): raise HTTPException(status_code=404, detail="History record not found")
        conn.commit(); return {"status":"success"}
    finally:
        conn.close()



# === FINAL EXAM MODULES V2 ===
# Stable, isolated API for the Results and History screens.  These endpoints
# intentionally use separate table names so they cannot conflict with older
# experimental exam-module migrations.

def _init_final_exam_tables():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS exam_results_v2 (
        id SERIAL PRIMARY KEY,
        branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
        batch_name TEXT NOT NULL,
        subjects TEXT NOT NULL,
        topics TEXT NOT NULL,
        exam_date TEXT NOT NULL,
        overall_marks NUMERIC(12,2) NOT NULL,
        student_id INTEGER REFERENCES students(id) ON DELETE SET NULL,
        student_name TEXT NOT NULL,
        roll_number TEXT,
        marks NUMERIC(12,2),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS exam_history_v2 (
        id SERIAL PRIMARY KEY,
        branch_id INTEGER NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        topic TEXT NOT NULL,
        batch_name TEXT NOT NULL,
        exam_date TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exam_results_v2_branch_batch ON exam_results_v2(branch_id,batch_name)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exam_history_v2_branch_date ON exam_history_v2(branch_id,exam_date)")
    conn.commit()
    conn.close()

_init_final_exam_tables()

class FinalExamResultStudent(BaseModel):
    student_id: int | None = None
    student_name: str
    roll_number: str | None = None
    marks: float | None = None

class FinalExamResultsCreate(BaseModel):
    branch_id: int
    batch_name: str
    subjects: str
    topics: str
    exam_date: str
    overall_marks: float
    students: list[FinalExamResultStudent]

class FinalExamResultUpdate(BaseModel):
    marks: float | None = None
    student_name: str | None = None
    roll_number: str | None = None

class FinalExamHistoryCreate(BaseModel):
    branch_id: int
    subject: str
    topic: str
    batch_name: str
    exam_date: str

class FinalExamHistoryUpdate(BaseModel):
    subject: str
    topic: str
    batch_name: str
    exam_date: str

def _final_exam_access(institute, branch_id, write=False):
    check_module_access(institute, 'examination')
    if write:
        if not institute.is_owner and institute.permission != 'edit':
            raise HTTPException(status_code=403, detail='Edit access is required')
        verify_branch_ownership(branch_id, institute.id)
    else:
        verify_branch_read_access(branch_id, institute.id)

def _final_mark(value, overall):
    if value is None:
        return None
    value = float(value)
    if value < 0 or value > overall:
        raise HTTPException(status_code=400, detail=f'Marks must be between 0 and {overall:g}')
    return value

@app.get('/api/examination/results/students/{branch_id}')
def final_exam_students(branch_id: int, batch: str, institute: CurrentInstitute = Depends(get_current_institute)):
    _final_exam_access(institute, branch_id)
    if not batch.strip():
        raise HTTPException(status_code=400, detail='Batch name is required')
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id,name,COALESCE(roll_number,'') AS roll_number
                       FROM students
                       WHERE branch_id=%s AND LOWER(TRIM(COALESCE(batch,'')))=LOWER(TRIM(%s))
                       ORDER BY LOWER(COALESCE(name,'')),LOWER(COALESCE(roll_number,''))""", (branch_id,batch))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

@app.get('/api/examination/results/{branch_id}')
def final_exam_results(branch_id: int, institute: CurrentInstitute = Depends(get_current_institute)):
    _final_exam_access(institute, branch_id)
    conn=get_conn()
    try:
        cur=conn.cursor()
        cur.execute("""SELECT id,batch_name,subjects,topics,exam_date,overall_marks,
                              student_id,student_name,roll_number,marks,created_at,updated_at
                       FROM exam_results_v2 WHERE branch_id=%s
                       ORDER BY exam_date DESC,batch_name,student_name,id""",(branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

@app.post('/api/examination/results')
def final_create_exam_results(payload: FinalExamResultsCreate, institute: CurrentInstitute = Depends(require_write_access)):
    _final_exam_access(institute,payload.branch_id,write=True)
    if not payload.batch_name.strip() or not payload.subjects.strip() or not payload.topics.strip() or not payload.exam_date.strip():
        raise HTTPException(status_code=400,detail='Batch, subject(s), topic(s), and exam date are required')
    overall=float(payload.overall_marks)
    if overall<=0: raise HTTPException(status_code=400,detail='Overall marks must be greater than zero')
    if not payload.students: raise HTTPException(status_code=400,detail='No students were supplied')
    conn=get_conn(); ids=[]
    try:
        cur=conn.cursor()
        for s in payload.students:
            cur.execute("""INSERT INTO exam_results_v2
                (branch_id,batch_name,subjects,topics,exam_date,overall_marks,student_id,student_name,roll_number,marks)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (payload.branch_id,payload.batch_name.strip(),payload.subjects.strip(),payload.topics.strip(),payload.exam_date,
                 overall,s.student_id,s.student_name.strip(),s.roll_number or '',_final_mark(s.marks,overall)))
            ids.append(cur.fetchone()[0])
        conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()
    return {'status':'success','ids':ids}

@app.patch('/api/examination/results/{result_id}')
def final_update_exam_result(result_id:int,payload:FinalExamResultUpdate,institute:CurrentInstitute=Depends(require_write_access)):
    check_module_access(institute,'examination')
    conn=get_conn()
    try:
        cur=conn.cursor()
        cur.execute("""SELECT r.* FROM exam_results_v2 r JOIN branches b ON b.id=r.branch_id
                       WHERE r.id=%s AND b.tenant_id=%s""",(result_id,institute.id))
        row=cur.fetchone()
        if not row: raise HTTPException(status_code=404,detail='Result record not found')
        if payload.marks is not None: _final_mark(payload.marks,float(row['overall_marks']))
        sets=[]; vals=[]
        if payload.marks is not None: sets.append('marks=%s'); vals.append(payload.marks)
        if payload.student_name is not None: sets.append('student_name=%s'); vals.append(payload.student_name.strip())
        if payload.roll_number is not None: sets.append('roll_number=%s'); vals.append(payload.roll_number.strip())
        if not sets: raise HTTPException(status_code=400,detail='Nothing to update')
        sets.append('updated_at=NOW()')
        cur.execute(f"UPDATE exam_results_v2 SET {','.join(sets)} WHERE id=%s",(*vals,result_id))
        conn.commit(); return {'status':'updated','id':result_id}
    finally:
        conn.close()

@app.delete('/api/examination/results/{result_id}')
def final_delete_exam_result(result_id:int,institute:CurrentInstitute=Depends(require_write_access)):
    check_module_access(institute,'examination')
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("DELETE FROM exam_results_v2 WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s) RETURNING id",(result_id,institute.id))
        if not cur.fetchone(): raise HTTPException(status_code=404,detail='Result record not found')
        conn.commit(); return {'status':'deleted'}
    finally: conn.close()

@app.get('/api/examination/history/{branch_id}')
def final_exam_history(branch_id:int,institute:CurrentInstitute=Depends(get_current_institute)):
    _final_exam_access(institute,branch_id)
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("SELECT id,subject,topic,batch_name,exam_date,created_at,updated_at FROM exam_history_v2 WHERE branch_id=%s ORDER BY exam_date DESC,id DESC",(branch_id,))
        return [dict(r) for r in cur.fetchall()]
    finally: conn.close()

@app.post('/api/examination/history')
def final_create_exam_history(payload:FinalExamHistoryCreate,institute:CurrentInstitute=Depends(require_write_access)):
    _final_exam_access(institute,payload.branch_id,write=True)
    if not all(v.strip() for v in (payload.subject,payload.topic,payload.batch_name,payload.exam_date)):
        raise HTTPException(status_code=400,detail='All history fields are required')
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("INSERT INTO exam_history_v2(branch_id,subject,topic,batch_name,exam_date) VALUES(%s,%s,%s,%s,%s) RETURNING id",(payload.branch_id,payload.subject.strip(),payload.topic.strip(),payload.batch_name.strip(),payload.exam_date)); rid=cur.fetchone()[0]; conn.commit(); return {'status':'success','id':rid}
    finally: conn.close()

@app.patch('/api/examination/history/{history_id}')
def final_update_exam_history(history_id:int,payload:FinalExamHistoryUpdate,institute:CurrentInstitute=Depends(require_write_access)):
    check_module_access(institute,'examination')
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("UPDATE exam_history_v2 SET subject=%s,topic=%s,batch_name=%s,exam_date=%s,updated_at=NOW() WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s) RETURNING id",(payload.subject.strip(),payload.topic.strip(),payload.batch_name.strip(),payload.exam_date,history_id,institute.id));
        if not cur.fetchone(): raise HTTPException(status_code=404,detail='History record not found')
        conn.commit(); return {'status':'updated','id':history_id}
    finally: conn.close()

@app.delete('/api/examination/history/{history_id}')
def final_delete_exam_history(history_id:int,institute:CurrentInstitute=Depends(require_write_access)):
    check_module_access(institute,'examination')
    conn=get_conn()
    try:
        cur=conn.cursor(); cur.execute("DELETE FROM exam_history_v2 WHERE id=%s AND branch_id IN (SELECT id FROM branches WHERE tenant_id=%s) RETURNING id",(history_id,institute.id))
        if not cur.fetchone(): raise HTTPException(status_code=404,detail='History record not found')
        conn.commit(); return {'status':'deleted'}
    finally: conn.close()


