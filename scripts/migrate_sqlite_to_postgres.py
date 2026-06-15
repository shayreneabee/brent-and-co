import os
import sqlite3
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor


BASE_DIR = Path(__file__).resolve().parents[1]
SQLITE_PATH = Path(os.getenv("SQLITE_IDENTITY_DB", BASE_DIR / "instance" / "brent_identity.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "")


def ensure_postgres_schema(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
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
        cur.execute(
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


def main():
    if not DATABASE_URL:
        raise SystemExit("Set DATABASE_URL to the Render PostgreSQL external connection string.")
    if not SQLITE_PATH.exists():
        raise SystemExit(f"SQLite database not found: {SQLITE_PATH}")

    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row
    pg_conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

    with pg_conn:
        ensure_postgres_schema(pg_conn)
        with pg_conn.cursor() as cur:
            for row in sqlite_conn.execute("SELECT * FROM users").fetchall():
                cur.execute(
                    """
                    INSERT INTO users (
                        email, display_name, profile_photo, auth_provider, provider_user_id,
                        is_admin, is_founder, created_at, last_login_at, updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        profile_photo = EXCLUDED.profile_photo,
                        auth_provider = EXCLUDED.auth_provider,
                        provider_user_id = EXCLUDED.provider_user_id,
                        is_admin = GREATEST(users.is_admin, EXCLUDED.is_admin),
                        is_founder = GREATEST(users.is_founder, EXCLUDED.is_founder),
                        last_login_at = GREATEST(users.last_login_at, EXCLUDED.last_login_at),
                        updated_at = EXCLUDED.updated_at
                    RETURNING id
                    """,
                    (
                        row["email"],
                        row["display_name"],
                        row["profile_photo"],
                        row["auth_provider"],
                        row["provider_user_id"],
                        row["is_admin"],
                        row["is_founder"],
                        row["created_at"],
                        row["last_login_at"],
                        row["updated_at"],
                    ),
                )
                pg_user_id = cur.fetchone()["id"]
                for membership in sqlite_conn.execute(
                    "SELECT * FROM app_memberships WHERE user_id = ?",
                    (row["id"],),
                ).fetchall():
                    cur.execute(
                        """
                        INSERT INTO app_memberships (user_id, app_name, role, joined_at, last_seen_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (user_id, app_name) DO UPDATE SET
                            role = EXCLUDED.role,
                            last_seen_at = GREATEST(app_memberships.last_seen_at, EXCLUDED.last_seen_at)
                        """,
                        (
                            pg_user_id,
                            membership["app_name"],
                            membership["role"],
                            membership["joined_at"],
                            membership["last_seen_at"],
                        ),
                    )

    sqlite_conn.close()
    pg_conn.close()
    print("Brent identity SQLite data migrated to PostgreSQL.")


if __name__ == "__main__":
    main()
