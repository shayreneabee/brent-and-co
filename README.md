# Brent & Co.

The dedicated umbrella homepage for the Brent & Co. ecosystem.

## Public Platform Links

- Brent & Co.: https://brentandco.org/
- Let's Cook Ya'll: https://letscookyall.com/
- Find the Beat: https://findthebeatmusic.com/
- Second Chance Careers: https://secondchancecareers.org/

Do not use the old Netlify Brent & Co. page or the old `lets-cook.onrender.com` app as final launch destinations. Source code links are intentionally kept off the public homepage. Brent & Co. should act as the launch umbrella for the live platforms.

## Google OAuth / Brent SSO

Brent & Co is the central identity service. Google OAuth should be configured only on Brent & Co, then app access is handed off with short-lived signed SSO tokens.

Google OAuth redirect URIs:

- `http://localhost:5001/auth/google/callback`
- `https://brentandco.org/auth/google/callback`
- `https://www.brentandco.org/auth/google/callback`

Required Render environment variables for Brent & Co:

- `DATABASE_URL`: Render PostgreSQL internal connection string
- `GOOGLE_CLIENT_ID`: Google OAuth web client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth web client secret
- `SESSION_SECRET`: long random Flask session secret
- `SSO_SHARED_SECRET`: long random shared token-signing secret; must match every connected app
- `SSO_TOKEN_SECONDS`: optional, defaults to `300`
- `BRENT_PUBLIC_URL`: `https://brentandco.org`
- `FIND_THE_BEAT_SSO_CONSUME_URL`: `https://findthebeatmusic.com/sso/consume`
- `LETS_COOK_SSO_CONSUME_URL`: `https://letscookyall.com/sso/consume`
- `SECOND_CHANCE_SSO_CONSUME_URL`: `https://secondchancecareers.org/sso/consume`

If `DATABASE_URL` is present, Brent & Co uses PostgreSQL. If it is missing, local development falls back to SQLite at `instance/brent_identity.db`.

Required Render environment variables for Find The Beat, Let's Cook Ya'll, and Second Chance Careers:

- `BRENT_SSO_URL`: `https://brentandco.org/sso/start`
- `SSO_SHARED_SECRET`: same exact value used on Brent & Co
- `SESSION_SECRET` or `SECRET_KEY`: long random app session secret

Do not put Google OAuth redirect URIs on the child apps unless they later get their own independent OAuth clients.

## Identity Database

Production should use Render PostgreSQL, not SQLite. SQLite is only for local development.

Automatic table creation:

- `users`
- `app_memberships`

The tables are created automatically on the first request if they do not already exist.

To migrate an existing local SQLite identity DB into PostgreSQL:

```bash
set DATABASE_URL=postgresql://...
set SQLITE_IDENTITY_DB=C:\path\to\brent_identity.db
python scripts\migrate_sqlite_to_postgres.py
```

On macOS/Linux:

```bash
export DATABASE_URL='postgresql://...'
export SQLITE_IDENTITY_DB='/path/to/brent_identity.db'
python scripts/migrate_sqlite_to_postgres.py
```

Render deployment order:

1. Create Render PostgreSQL.
2. Create Brent & Co Web Service.
3. Add `DATABASE_URL`, Google OAuth variables, `SESSION_SECRET`, and `SSO_SHARED_SECRET` to Brent & Co.
4. Deploy Brent & Co and confirm `/login`, `/auth/google`, `/auth/google/callback`, `/sso/start`, and `/admin` exist.
5. Add the same `SSO_SHARED_SECRET` and `BRENT_SSO_URL=https://brentandco.org/sso/start` to Find The Beat, Let's Cook Ya'll, and Second Chance Careers.
6. Deploy child apps.
7. Test Google login into each app through Brent SSO.

## Deploy on Render

Create a Web Service from this repository:

- Repository: `shayreneabee/brent-and-co`
- Branch: `main`
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 2 --threads 4 --timeout 120`

Brent & Co. is served at `brentandco.org`.
