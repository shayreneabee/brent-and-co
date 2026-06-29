import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
import base64
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from flask import Flask, flash, redirect, request, send_from_directory, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.getenv("INSTANCE_DIR", BASE_DIR / "instance"))
DB_PATH = Path(os.getenv("DATABASE_PATH", INSTANCE_DIR / "brent_identity.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET") or os.getenv("SECRET_KEY") or "dev-session-change-me"
SSO_SHARED_SECRET = os.getenv("SSO_SHARED_SECRET", "dev-sso-change-me").strip()
SSO_TOKEN_SECONDS = int(os.getenv("SSO_TOKEN_SECONDS", "300"))
DEBUG_SSO = os.getenv("DEBUG_SSO", "").strip().lower() in {"1", "true", "yes", "on"}
BRENT_PUBLIC_URL = os.getenv("BRENT_PUBLIC_URL", "https://www.brentandco.org").rstrip("/")
BRENT_PUBLIC_PARTS = urlsplit(BRENT_PUBLIC_URL)
BRENT_PUBLIC_HOST = BRENT_PUBLIC_PARTS.netloc.lower()

APP_SSO_TARGETS = {
    "find-the-beat": {
        "callback": os.getenv("FIND_THE_BEAT_SSO_CONSUME_URL", "https://www.findthebeatmusic.com/sso/consume").strip(),
        "default_next": "/profile",
    },
    "lets-cook": {
        "callback": os.getenv("LETS_COOK_SSO_CONSUME_URL", "https://letscookyall.com/sso/consume").strip(),
        "default_next": "/#account",
    },
    "second-chance": {
        "callback": os.getenv("SECOND_CHANCE_SSO_CONSUME_URL", "https://secondchancecareers.org/sso/consume").strip(),
        "default_next": "/second-chance/profile",
    },
    "beu": {
        "callback": os.getenv("BEU_SSO_CONSUME_URL", "https://beutravel.org/sso/consume").strip(),
        "default_next": "/#profile",
    },
}

FOUNDER_EMAIL = os.getenv("BRENT_OWNER_EMAIL", "shalanda.brent@gmail.com").strip().lower()

app = Flask(__name__, static_folder=None)
app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE",
        "1" if BRENT_PUBLIC_URL.startswith("https://") else "0",
    ).strip().lower() in {"1", "true", "yes", "on"},
    SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
)
session_cookie_domain = os.getenv("SESSION_COOKIE_DOMAIN", "").strip()
if session_cookie_domain:
    app.config["SESSION_COOKIE_DOMAIN"] = session_cookie_domain
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def log_sso_debug(event, app_name="", callback_url=""):
    if not DEBUG_SSO:
        return
    app.logger.info(
        "SSO %s app=%s BRENT_PUBLIC_URL=%s SSO_SHARED_SECRET_PRESENT=%s callback=%s",
        event,
        app_name,
        BRENT_PUBLIC_URL,
        bool(SSO_SHARED_SECRET),
        callback_url,
    )


def log_oauth_debug(event, **details):
    if not DEBUG_SSO:
        return
    safe_details = " ".join(f"{key}={value}" for key, value in details.items())
    app.logger.info("OAuth %s %s", event, safe_details)


def canonical_url_for_current_request():
    if not BRENT_PUBLIC_HOST:
        return ""
    current_host = request.host.lower()
    if current_host == BRENT_PUBLIC_HOST or current_host.startswith("localhost") or current_host.startswith("127.0.0.1"):
        return ""
    parts = urlsplit(request.url)
    return urlunsplit((BRENT_PUBLIC_PARTS.scheme or "https", BRENT_PUBLIC_HOST, parts.path, parts.query, parts.fragment))


class Database:
    def __init__(self):
        self.conn = None

    def __enter__(self):
        if USE_POSTGRES:
            import psycopg2
            from psycopg2.extras import RealDictCursor

            self.conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        else:
            INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

    def execute(self, sql, params=()):
        cursor = self.conn.cursor()
        if USE_POSTGRES:
            sql = sql.replace("?", "%s")
        cursor.execute(sql, params)
        return cursor


def get_db():
    return Database()


def init_db():
    with get_db() as conn:
        if USE_POSTGRES:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT DEFAULT '',
                    display_name TEXT DEFAULT '',
                    profile_photo TEXT DEFAULT '',
                    auth_provider TEXT DEFAULT 'google',
                    provider_user_id TEXT DEFAULT '',
                    is_admin INTEGER DEFAULT 0,
                    is_founder INTEGER DEFAULT 0,
                    created_at BIGINT DEFAULT 0,
                    last_login_at BIGINT DEFAULT 0,
                    updated_at BIGINT DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_memberships (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    app_name TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    joined_at BIGINT DEFAULT 0,
                    last_seen_at BIGINT DEFAULT 0,
                    UNIQUE(user_id, app_name)
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT DEFAULT '',
                    display_name TEXT DEFAULT '',
                    profile_photo TEXT DEFAULT '',
                    auth_provider TEXT DEFAULT 'google',
                    provider_user_id TEXT DEFAULT '',
                    is_admin INTEGER DEFAULT 0,
                    is_founder INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT 0,
                    last_login_at INTEGER DEFAULT 0,
                    updated_at INTEGER DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_memberships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    app_name TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    joined_at INTEGER DEFAULT 0,
                    last_seen_at INTEGER DEFAULT 0,
                    UNIQUE(user_id, app_name)
                )
                """
            )
        try:
            if USE_POSTGRES:
                existing_columns = {
                    row["column_name"]
                    for row in conn.execute(
                        "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
                    ).fetchall()
                }
            else:
                existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "password_hash" not in existing_columns:
                conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''")
        except Exception:
            app.logger.exception("Could not verify Brent users password_hash column")


@app.before_request
def ensure_db():
    canonical_url = canonical_url_for_current_request()
    if canonical_url and request.path.startswith(("/login", "/signup", "/auth/", "/sso/start")):
        log_oauth_debug("canonical_redirect", host=request.host, target=canonical_url)
        return redirect(canonical_url, code=302)
    init_db()


def b64encode(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def brent_account_id(email):
    return "brent-google-" + hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def safe_relative_next(value, default="/"):
    value = (value or "").strip()
    if value.startswith("/") and not value.startswith("//"):
        return value
    if value.startswith("#"):
        return f"/{value}"
    return default


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_local_user(email, password, display_name):
    email = (email or "").strip().lower()
    display_name = (display_name or "").strip() or email.split("@")[0]
    if not email or len(password or "") < 8:
        raise ValueError("Email and an 8-character password are required.")
    now = int(time.time())
    is_founder = int(email == FOUNDER_EMAIL)
    with get_db() as conn:
        insert_sql = """
            INSERT INTO users (
                email, password_hash, display_name, profile_photo, auth_provider,
                provider_user_id, is_admin, is_founder, created_at, last_login_at, updated_at
            )
            VALUES (?, ?, ?, '', 'local', '', ?, ?, ?, ?, ?)
        """
        params = (
            email,
            generate_password_hash(password),
            display_name,
            is_founder,
            is_founder,
            now,
            now,
            now,
        )
        if USE_POSTGRES:
            inserted = conn.execute(f"{insert_sql} RETURNING id", params).fetchone()
            user_id = inserted["id"]
        else:
            cursor = conn.execute(insert_sql, params)
            user_id = cursor.lastrowid
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def authenticate_local_user(email, password):
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE lower(email) = lower(?)",
            ((email or "").strip().lower(),),
        ).fetchone()
        if not user or not user["password_hash"] or not check_password_hash(user["password_hash"], password or ""):
            return None
        now = int(time.time())
        conn.execute(
            """
            UPDATE users
            SET auth_provider = COALESCE(NULLIF(auth_provider, ''), 'local'),
                last_login_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (now, now, user["id"]),
        )
        return conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()


def upsert_google_user(profile):
    email = (profile.get("email") or "").strip().lower()
    if not email:
        raise ValueError("Google did not return an email address.")
    now = int(time.time())
    display_name = profile.get("name") or email.split("@")[0]
    photo = profile.get("picture") or ""
    provider_user_id = profile.get("sub") or ""
    is_founder = int(email == FOUNDER_EMAIL)
    with get_db() as conn:
        existing = conn.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (email,)).fetchone()
        if existing:
            if USE_POSTGRES:
                conn.execute(
                    """
                    UPDATE users
                    SET display_name = ?, profile_photo = ?, auth_provider = 'google',
                        provider_user_id = ?, is_admin = GREATEST(is_admin, ?),
                        is_founder = GREATEST(is_founder, ?),
                        last_login_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (display_name, photo, provider_user_id, is_founder, is_founder, now, now, existing["id"]),
                )
            else:
                conn.execute(
                    """
                    UPDATE users
                    SET display_name = ?, profile_photo = ?, auth_provider = 'google',
                        provider_user_id = ?, is_admin = MAX(is_admin, ?),
                        is_founder = MAX(is_founder, ?),
                        last_login_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (display_name, photo, provider_user_id, is_founder, is_founder, now, now, existing["id"]),
                )
            return conn.execute("SELECT * FROM users WHERE id = ?", (existing["id"],)).fetchone()
        insert_sql = """
            INSERT INTO users (
                email, display_name, profile_photo, auth_provider, provider_user_id,
                is_admin, is_founder, created_at, last_login_at, updated_at
            )
            VALUES (?, ?, ?, 'google', ?, ?, ?, ?, ?, ?)
        """
        if USE_POSTGRES:
            inserted = conn.execute(
                f"{insert_sql} RETURNING id",
                (email, display_name, photo, provider_user_id, is_founder, is_founder, now, now, now),
            ).fetchone()
            user_id = inserted["id"]
        else:
            cursor = conn.execute(
                insert_sql,
                (email, display_name, photo, provider_user_id, is_founder, is_founder, now, now, now),
            )
            user_id = cursor.lastrowid
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def make_sso_token(user, audience):
    now = int(time.time())
    payload = {
        "iss": "brent-co-identity",
        "aud": audience,
        "sub": brent_account_id(user["email"]),
        "email": user["email"],
        "display_name": user["display_name"] or user["email"].split("@")[0],
        "profile_photo": user["profile_photo"] or "",
        "authentication_provider": user["auth_provider"] or "google",
        "is_admin": bool(user["is_admin"]),
        "is_founder": bool(user["is_founder"]),
        "iat": now,
        "exp": now + SSO_TOKEN_SECONDS,
    }
    body = b64encode(json.dumps(payload, separators=(",", ":")))
    signature = hmac.new(
        SSO_SHARED_SECRET.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"{body}.{b64encode(signature)}"


def profile_completion(user):
    checks = [
        bool(user["display_name"]),
        bool(user["email"]),
        bool(user["profile_photo"]),
        bool(user["auth_provider"]),
    ]
    return round((sum(checks) / len(checks)) * 100)


def format_timestamp(value):
    try:
        stamp = int(value or 0)
    except (TypeError, ValueError):
        stamp = 0
    if not stamp:
        return "Not recorded yet"
    return time.strftime("%b %d, %Y %I:%M %p", time.localtime(stamp))


def require_admin():
    user = current_user()
    if not user or not user["is_admin"]:
        return None
    return user


def google_redirect_uri():
    configured = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    if configured:
        return configured
    if BRENT_PUBLIC_URL and not request.host.startswith(("localhost", "127.0.0.1")):
        return f"{BRENT_PUBLIC_URL}/auth/google/callback"
    scheme = "http" if request.host.startswith(("localhost", "127.0.0.1")) else "https"
    return url_for("google_callback", _external=True, _scheme=scheme)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or "/account"
    app_name = request.args.get("app", "")
    if request.method == "POST":
        user = authenticate_local_user(
            request.form.get("email", ""),
            request.form.get("password", ""),
        )
        if not user:
            return redirect(url_for("login", next=next_url, app=app_name, error="invalid"))
        session.clear()
        session["user_id"] = user["id"]
        if app_name:
            return redirect(url_for("sso_start", app=app_name, next=next_url))
        return redirect(safe_relative_next(next_url, "/account"))
    error_html = "<p class='auth-error'>Email or password did not match.</p>" if request.args.get("error") == "invalid" else ""
    body = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Sign in | Brent & Co</title>
      <link rel="stylesheet" href="/styles.css">
      <style>
        body {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
        .auth-card {{ width: min(520px, 100%); border-radius: 32px; padding: clamp(28px, 5vw, 48px); background: rgba(255,255,255,.88); box-shadow: 0 24px 60px rgba(8,18,35,.18); }}
        .auth-card img {{ width: 88px; border-radius: 24px; }}
        .auth-card h1 {{ margin: 18px 0 8px; }}
        .auth-card p {{ color: #5c6472; line-height: 1.6; }}
        .auth-actions {{ display: grid; gap: 12px; margin-top: 24px; }}
        .auth-actions a {{ text-align: center; }}
        .auth-form {{ display: grid; gap: 12px; margin-top: 24px; }}
        .auth-form input {{ width: 100%; border: 1px solid rgba(17,24,39,.14); border-radius: 16px; padding: 14px 16px; font: inherit; }}
        .auth-form button {{ border: 0; cursor: pointer; }}
        .auth-error {{ color: #9f1239; font-weight: 800; }}
      </style>
    </head>
    <body>
      <main class="auth-card">
        <img src="/assets/brent-co-profile.png" alt="Brent & Co">
        <p class="eyebrow">Brent & Co account</p>
        <h1>Sign in once. Use every app.</h1>
        <p>Use your Brent & Co account to access Brent & Co, Find The Beat, Let's Cook Y'all, and Second Chance Careers.</p>
        {error_html}
        <div class="auth-actions">
          <a class="button" href="{url_for('google_start')}?{urlencode({'next': next_url, 'app': app_name})}">Continue with Google</a>
        </div>
        <form class="auth-form" method="post" action="{url_for('login')}?{urlencode({'next': next_url, 'app': app_name})}">
          <input type="email" name="email" autocomplete="email" placeholder="Email address" required>
          <input type="password" name="password" autocomplete="current-password" placeholder="Password" required>
          <button class="button secondary" type="submit">Sign in with Email</button>
        </form>
        <div class="auth-actions">
          <a class="button secondary" href="{url_for('signup')}?{urlencode({'next': next_url, 'app': app_name})}">Create Brent & Co Account</a>
          <a class="button secondary" href="/">Back to Brent & Co</a>
        </div>
      </main>
    </body>
    </html>
    """
    return body


@app.route("/signup", methods=["GET", "POST"])
def signup():
    next_url = request.args.get("next") or "/account"
    app_name = request.args.get("app", "")
    error = ""
    if request.method == "POST":
        if request.form.get("password", "") != request.form.get("confirm_password", ""):
            error = "Passwords do not match."
        else:
            try:
                user = create_local_user(
                    request.form.get("email", ""),
                    request.form.get("password", ""),
                    request.form.get("display_name", ""),
                )
                session.clear()
                session["user_id"] = user["id"]
                if app_name:
                    return redirect(url_for("sso_start", app=app_name, next=next_url))
                return redirect(safe_relative_next(next_url, "/account"))
            except Exception as exc:
                app.logger.info("Local Brent signup failed: %s", exc)
                error = "That account could not be created. The email may already be registered."
    error_html = f"<p class='auth-error'>{error}</p>" if error else ""
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Create account | Brent & Co</title>
      <link rel="stylesheet" href="/styles.css">
      <style>
        body {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
        .auth-card {{ width: min(520px, 100%); border-radius: 32px; padding: clamp(28px, 5vw, 48px); background: rgba(255,255,255,.88); box-shadow: 0 24px 60px rgba(8,18,35,.18); }}
        .auth-card img {{ width: 88px; border-radius: 24px; }}
        .auth-form {{ display: grid; gap: 12px; margin-top: 24px; }}
        .auth-form input {{ width: 100%; border: 1px solid rgba(17,24,39,.14); border-radius: 16px; padding: 14px 16px; font: inherit; }}
        .auth-form button {{ border: 0; cursor: pointer; }}
        .auth-actions {{ display: grid; gap: 12px; margin-top: 16px; }}
        .auth-error {{ color: #9f1239; font-weight: 800; }}
      </style>
    </head>
    <body>
      <main class="auth-card">
        <img src="/assets/brent-co-profile.png" alt="Brent & Co">
        <p class="eyebrow">Brent & Co account</p>
        <h1>Create your account.</h1>
        <p>Keep it quick: email, password, and the name you want shown across Brent & Co apps.</p>
        {error_html}
        <form class="auth-form" method="post" action="{url_for('signup')}?{urlencode({'next': next_url, 'app': app_name})}">
          <input type="text" name="display_name" autocomplete="name" placeholder="Display name">
          <input type="email" name="email" autocomplete="email" placeholder="Email address" required>
          <input type="password" name="password" autocomplete="new-password" placeholder="Password" minlength="8" required>
          <input type="password" name="confirm_password" autocomplete="new-password" placeholder="Confirm password" minlength="8" required>
          <button class="button" type="submit">Create Account</button>
        </form>
        <div class="auth-actions">
          <a class="button secondary" href="{url_for('login')}?{urlencode({'next': next_url, 'app': app_name})}">I already have an account</a>
        </div>
      </main>
    </body>
    </html>
    """


@app.get("/auth/google")
def google_start():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        return "Google OAuth is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.", 503
    state = secrets.token_urlsafe(24)
    session["oauth_state"] = state
    session["post_auth_next"] = request.args.get("next") or "/account"
    session["post_auth_app"] = request.args.get("app") or ""
    log_oauth_debug(
        "start",
        host=request.host,
        redirect_uri=google_redirect_uri(),
        has_session_state=bool(session.get("oauth_state")),
        app=session.get("post_auth_app") or "",
    )
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}")


@app.get("/auth/google/callback")
def google_callback():
    incoming_state = request.args.get("state")
    expected_state = session.get("oauth_state")
    if incoming_state != expected_state:
        next_path = session.get("post_auth_next") or "/account"
        app_name = session.get("post_auth_app") or ""
        log_oauth_debug(
            "state_mismatch",
            host=request.host,
            session_state_present=bool(expected_state),
            incoming_state_present=bool(incoming_state),
            secure_cookie=app.config.get("SESSION_COOKIE_SECURE"),
            samesite=app.config.get("SESSION_COOKIE_SAMESITE"),
        )
        session.clear()
        return redirect(url_for("login", next=next_path, app=app_name))
    code = request.args.get("code")
    if not code:
        return "Google did not return an authorization code.", 400
    token_payload = urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": google_redirect_uri(),
        "grant_type": "authorization_code",
    }).encode("utf-8")
    token_request = Request(
        "https://oauth2.googleapis.com/token",
        data=token_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(token_request, timeout=15) as response:
            token_data = json.loads(response.read().decode("utf-8"))
        profile_request = Request(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        with urlopen(profile_request, timeout=15) as response:
            profile = json.loads(response.read().decode("utf-8"))
    except Exception:
        return "Google sign-in failed. Please check the OAuth credentials and redirect URI.", 502

    user = upsert_google_user(profile)
    app_name = session.get("post_auth_app") or request.args.get("app") or ""
    next_path = session.get("post_auth_next") or "/account"
    session.clear()
    session["user_id"] = user["id"]
    log_oauth_debug("success", host=request.host, app=app_name, user_email=user["email"])
    if app_name:
        return redirect(url_for("sso_start", app=app_name, next=next_path))
    return redirect(safe_relative_next(next_path, "/account"))


@app.get("/sso/start")
def sso_start():
    app_name = request.args.get("app", "").strip().lower()
    target = APP_SSO_TARGETS.get(app_name)
    if not target:
        return redirect(url_for("login", next=request.args.get("next") or "/", app=app_name))
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.url, app=app_name))
    now = int(time.time())
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO app_memberships (user_id, app_name, role, joined_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, app_name) DO UPDATE SET last_seen_at = excluded.last_seen_at
            """,
            (user["id"], app_name, "admin" if user["is_admin"] else "user", now, now),
        )
    next_path = safe_relative_next(request.args.get("next"), target["default_next"])
    token = make_sso_token(user, app_name)
    separator = "&" if "?" in target["callback"] else "?"
    log_sso_debug("handoff", app_name=app_name, callback_url=target["callback"])
    return redirect(f"{target['callback']}{separator}{urlencode({'token': token, 'next': next_path})}")


@app.get("/logout")
def logout():
    session.clear()
    flash("Signed out.")
    return redirect("/")


@app.get("/account")
def account_dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login", next="/account"))
    with get_db() as conn:
        memberships = conn.execute(
            """
            SELECT app_name, role, joined_at, last_seen_at
            FROM app_memberships
            WHERE user_id = ?
            ORDER BY last_seen_at DESC, joined_at DESC
            """,
            (user["id"],),
        ).fetchall()
    membership_names = {row["app_name"] for row in memberships}
    app_cards = []
    app_labels = {
        "find-the-beat": "Find The Beat",
        "lets-cook": "Let's Cook Y'all",
        "second-chance": "Second Chance Careers",
        "beu": "BEU",
    }
    for app_name, label in app_labels.items():
        joined = app_name in membership_names
        href = url_for("sso_start", app=app_name, next=APP_SSO_TARGETS[app_name]["default_next"])
        status = "Connected" if joined else "Open app"
        app_cards.append(
            f"""
            <a class="app-card" href="{href}">
              <span>{html.escape(status)}</span>
              <strong>{html.escape(label)}</strong>
              <small>Use your Brent & Co account here.</small>
            </a>
            """
        )
    app_cards_html = "".join(app_cards)
    rows = "".join(
        f"""
        <tr>
          <td>{html.escape(row['app_name'])}</td>
          <td>{html.escape(row['role'] or 'user')}</td>
          <td>{format_timestamp(row['last_seen_at'])}</td>
        </tr>
        """
        for row in memberships
    ) or "<tr><td colspan='3'>No app handoffs yet. Choose an app below to connect it.</td></tr>"
    avatar = user["profile_photo"] or "/assets/brent-co-profile.png"
    display_name = html.escape(user["display_name"] or user["email"].split("@")[0])
    email = html.escape(user["email"])
    provider = html.escape(user["auth_provider"] or "local")
    role = "Founder" if user["is_founder"] else ("Admin" if user["is_admin"] else "Member")
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>My Brent & Co Account</title>
      <link rel="stylesheet" href="/styles.css">
      <style>
        body {{ min-height: 100vh; background: #f7f2e9; color: #101827; padding: 24px; }}
        .account-shell {{ width: min(1120px, 100%); margin: 0 auto; display: grid; gap: 22px; }}
        .account-hero, .account-panel {{ background: rgba(255,255,255,.92); border: 1px solid rgba(17,24,39,.1); border-radius: 28px; padding: clamp(22px, 4vw, 42px); box-shadow: 0 20px 50px rgba(8,18,35,.12); }}
        .account-hero {{ display: grid; grid-template-columns: auto 1fr; gap: 20px; align-items: center; }}
        .account-avatar {{ width: 96px; height: 96px; border-radius: 28px; object-fit: cover; border: 3px solid #d9a441; background: #fff; }}
        .account-hero h1 {{ margin: 4px 0 8px; font-size: clamp(2rem, 5vw, 4.6rem); line-height: .94; }}
        .account-meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
        .pill {{ border-radius: 999px; background: #f7f2e9; border: 1px solid #e6d6b8; padding: 8px 12px; font-weight: 800; }}
        .app-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; }}
        .app-card {{ display: grid; gap: 8px; padding: 18px; border-radius: 20px; background: linear-gradient(135deg, #0f172a, #1f3b49); color: #fff; text-decoration: none; box-shadow: 0 16px 30px rgba(15,23,42,.18); transition: transform .18s ease, box-shadow .18s ease; }}
        .app-card:hover {{ transform: translateY(-3px); box-shadow: 0 20px 38px rgba(15,23,42,.24); }}
        .app-card span {{ color: #f5c76b; font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 900; }}
        .app-card strong {{ font-size: 1.25rem; }}
        .app-card small {{ color: rgba(255,255,255,.78); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 14px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid rgba(17,24,39,.1); }}
        .account-actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 20px; }}
        @media (max-width: 640px) {{
          .account-hero {{ grid-template-columns: 1fr; }}
          .account-avatar {{ width: 82px; height: 82px; }}
        }}
      </style>
    </head>
    <body>
      <main class="account-shell">
        <section class="account-hero">
          <img class="account-avatar" src="{html.escape(avatar)}" alt="">
          <div>
            <p class="eyebrow">Brent & Co account</p>
            <h1>Welcome, {display_name}.</h1>
            <p>This is your shared Brent & Co identity. One account, multiple apps, app-specific profiles.</p>
            <div class="account-meta">
              <span class="pill">{email}</span>
              <span class="pill">{html.escape(role)}</span>
              <span class="pill">{provider}</span>
              <span class="pill">Profile {profile_completion(user)}% complete</span>
            </div>
            <div class="account-actions">
              <a class="button" href="/">Brent & Co Home</a>
              <a class="button secondary" href="/logout">Sign out</a>
              <a class="button secondary" href="/admin">Founder Control Center</a>
            </div>
          </div>
        </section>
        <section class="account-panel">
          <p class="eyebrow">App switcher</p>
          <h2>Open your Brent & Co apps</h2>
          <div class="app-grid">{app_cards_html}</div>
        </section>
        <section class="account-panel">
          <h2>Connected app activity</h2>
          <table>
            <thead><tr><th>App</th><th>Role</th><th>Last seen</th></tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </section>
      </main>
    </body>
    </html>
    """


@app.get("/sso/debug")
def sso_debug():
    user = current_user()
    if not user or not user["is_admin"]:
        return "Admin access required.", 403
    return {
        "app": "Brent & Co",
        "brent_public_url": BRENT_PUBLIC_URL,
        "google_redirect_uri": google_redirect_uri(),
        "sso_shared_secret_present": bool(SSO_SHARED_SECRET),
        "sso_shared_secret_fingerprint": hashlib.sha256(SSO_SHARED_SECRET.encode("utf-8")).hexdigest()[:12],
        "sso_token_seconds": SSO_TOKEN_SECONDS,
        "session_cookie_secure": app.config.get("SESSION_COOKIE_SECURE"),
        "session_cookie_samesite": app.config.get("SESSION_COOKIE_SAMESITE"),
        "targets": {
            name: {
                "callback": target["callback"],
                "default_next": target["default_next"],
            }
            for name, target in APP_SSO_TARGETS.items()
        },
    }


@app.get("/admin")
def admin_dashboard():
    admin = require_admin()
    if not admin:
        return "Admin access required. Sign in with the Brent & Co founder account.", 403
    with get_db() as conn:
        users = conn.execute(
            """
            SELECT id, email, display_name, profile_photo, auth_provider,
                   is_admin, is_founder, created_at, last_login_at
            FROM users
            ORDER BY last_login_at DESC, created_at DESC
            LIMIT 100
            """
        ).fetchall()
        memberships = conn.execute(
            """
            SELECT m.app_name, COUNT(*) AS count
            FROM app_memberships m
            GROUP BY m.app_name
            ORDER BY m.app_name
            """
        ).fetchall()
        recent_memberships = conn.execute(
            """
            SELECT m.app_name, m.role, m.joined_at, m.last_seen_at, u.email, u.display_name
            FROM app_memberships m
            JOIN users u ON u.id = m.user_id
            ORDER BY m.last_seen_at DESC
            LIMIT 50
            """
        ).fetchall()
    user_rows = "".join(
        f"""
        <tr>
          <td>{user['display_name'] or user['email'].split('@')[0]}</td>
          <td>{user['email']}</td>
          <td>{user['auth_provider']}</td>
          <td>{'Founder' if user['is_founder'] else 'Admin' if user['is_admin'] else 'User'}</td>
          <td>{profile_completion(user)}%</td>
          <td>{user['last_login_at'] or ''}</td>
        </tr>
        """
        for user in users
    )
    app_rows = "".join(
        f"<li><strong>{row['app_name']}</strong><span>{row['count']} users</span></li>"
        for row in memberships
    ) or "<li><strong>No memberships yet</strong><span>Apps populate after first SSO handoff.</span></li>"
    membership_rows = "".join(
        f"""
        <tr>
          <td>{row['app_name']}</td>
          <td>{row['display_name'] or row['email']}</td>
          <td>{row['role']}</td>
          <td>{row['last_seen_at'] or row['joined_at']}</td>
        </tr>
        """
        for row in recent_memberships
    )
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Brent & Co Admin</title>
      <link rel="stylesheet" href="/styles.css">
      <style>
        body {{ padding: 24px; background: #f6f0e7; }}
        main {{ max-width: 1180px; margin: 0 auto; display: grid; gap: 24px; }}
        .admin-card {{ background: #fff; border-radius: 24px; padding: 24px; box-shadow: 0 18px 48px rgba(17, 24, 39, .12); overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; min-width: 720px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid rgba(17, 24, 39, .1); }}
        .app-list {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; padding: 0; list-style: none; }}
        .app-list li {{ display: grid; gap: 4px; padding: 16px; border-radius: 18px; background: #f7f2e9; }}
      </style>
    </head>
    <body>
      <main>
        <section class="admin-card">
          <p class="eyebrow">Founder control center</p>
          <h1>Brent & Co Identity</h1>
          <p>Signed in as {admin['email']}.</p>
          <a class="button secondary" href="/">Back to Brent & Co</a>
        </section>
        <section class="admin-card">
          <h2>Users by App</h2>
          <ul class="app-list">{app_rows}</ul>
        </section>
        <section class="admin-card">
          <h2>Users</h2>
          <table><thead><tr><th>Name</th><th>Email</th><th>Provider</th><th>Role</th><th>Profile</th><th>Last login</th></tr></thead><tbody>{user_rows}</tbody></table>
        </section>
        <section class="admin-card">
          <h2>Recent App Memberships</h2>
          <table><thead><tr><th>App</th><th>User</th><th>Role</th><th>Last seen</th></tr></thead><tbody>{membership_rows}</tbody></table>
        </section>
      </main>
    </body>
    </html>
    """


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/about.html")
@app.get("/about")
def about():
    return send_from_directory(BASE_DIR, "about.html")


@app.get("/founder.html")
@app.get("/founder")
def founder():
    return send_from_directory(BASE_DIR, "founder.html")


@app.get("/<path:path>")
def static_files(path):
    target = BASE_DIR / path
    if target.is_file():
        return send_from_directory(BASE_DIR, path)
    return send_from_directory(BASE_DIR, "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5001")), debug=True)
