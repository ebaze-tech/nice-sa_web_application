# NICESA backend

This directory contains the Django/DRF backend. The current scope is authentication and authorization only.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and set a local `DATABASE_URL` and `DJANGO_SECRET_KEY`.
4. Run `python manage.py migrate` against your local database.
5. Create the first administrator with `python manage.py createsuperuser`.
6. Run `python manage.py runserver`.

The auth dependencies are:

- `djangorestframework-simplejwt` for signed access/refresh JWTs, refresh rotation, and blacklisting.
- `drf-spectacular` for OpenAPI generation and Swagger UI.
- `django-cors-headers` for the separately hosted SPA.
- `gunicorn` as the production WSGI server behind nginx.
- `dj-database-url` and `psycopg` for `DATABASE_URL`-configured PostgreSQL.

## Token and CSRF design

The API returns a five-minute access token in the JSON response. The SPA should keep it in memory and send it as `Authorization: Bearer <access>`; it should not put tokens in local storage.

The seven-day refresh token is held in an `HttpOnly` cookie, marked `Secure` outside development, and is never exposed in a response body. This reduces refresh-token theft through JavaScript/XSS. Cookie-authenticated login, refresh, and logout requests are CSRF-protected:

1. `GET /api/v1/auth/csrf/` with credentials included.
2. Take `csrf_token` from the JSON response (the browser also receives the matching CSRF cookie).
3. Send that value in `X-CSRFToken` for login, refresh, and logout, with credentials included.

`SameSite=Lax` is the safe default for localhost ports or same-site subdomains. If the SPA and API use different registrable domains, use `REFRESH_COOKIE_SAMESITE=None`, `REFRESH_COOKIE_SECURE=True`, HTTPS, exact CORS origins, and exact CSRF trusted origins. The tradeoff is that cookie storage requires CSRF controls and correct cross-origin configuration, but keeps the long-lived credential out of JavaScript.

Refresh tokens rotate on every use and the previous token is blacklisted. Reuse of an already-rotated, still-valid refresh token revokes the linked server-side session. Every access request also checks the session record in the database, so session revocation takes effect immediately rather than waiting for access-token expiry.

## API

All endpoints are under `/api/v1/auth/`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `csrf/` | Set/return a CSRF token for the SPA. |
| POST | `register/` | Register an inactive student account. |
| POST | `verify-email/` | Consume a single-use verification token. |
| POST | `resend-verification/` | Generically request another verification email. |
| POST | `login/` | Login with one email-or-matric `identifier` and password. |
| POST | `refresh/` | Rotate the refresh cookie and return a new access token. |
| POST | `logout/` | Revoke the current session and clear the refresh cookie. |
| POST | `logout-all/` | Revoke every session for the authenticated user. |
| POST | `password-reset/` | Generically request a reset link by email. |
| POST | `password-reset/confirm/` | Consume a token, set a password, and revoke all sessions. |
| GET | `me/` | Return the authenticated user and current database permissions. |
| GET | `sessions/` | List the user's active and revoked login sessions. |
| POST | `sessions/{uuid}/revoke/` | Revoke one of the user's sessions. |
| GET | `roles/permissions/` | Admin-only fixed officer permission catalogue. |
| POST | `roles/users/{id}/promote/` | Admin-only promotion with an exact permission list. |
| PUT | `roles/users/{id}/permissions/` | Admin-only replacement of an officer's permissions. |
| POST | `roles/users/{id}/demote/` | Admin-only demotion and permission removal. |

Swagger UI is at `/api/v1/docs/`; the raw OpenAPI schema is at `/api/v1/schema/`. Generate and validate a file with `python manage.py spectacular --file openapi.yaml --validate`.

Registration accepts `first_name`, `last_name`, `email`, `matric_number`, `level`, and `password`. Student email matching is case-insensitive and limited to `@stu.ui.edu.ng`. Levels are 100, 200, 300, 400, or 500. Registration always creates an inactive student; only email verification activates the account.

Matric numbers are trimmed, Unicode-normalized, uppercased, and have repeated internal whitespace collapsed. They may not contain `@` or control characters and are limited to 64 characters. No department-specific regex is enforced because the official matric format has not been confirmed.

## Roles and permissions

Roles are `student`, `officer`, and `admin`. Public registration can only create students. Administrators are superusers created with `createsuperuser`; an admin promotes an existing non-admin user to officer and supplies the complete permission list.

The fixed officer permissions are view/manage students, levies, payments, announcements, and events; view/export reports; and view audit log. Feature views should use `HasNicesaPermission` and set `required_permission`, for example `required_permission = "manage_events"`. Permissions and roles are loaded from the database on every authenticated request and are not trusted from JWT claims.

Permission failures consistently return:

```json
{
  "error": {
    "code": "permission_denied",
    "message": "You do not have permission to perform this action.",
    "fields": {}
  }
}
```

Validation failures use the same envelope with field-level entries in `error.fields`. Login and password-reset request responses are deliberately generic to avoid identifier enumeration.

## Email and expiry

Development uses Django's console email backend. Any other `DJANGO_ENV` uses SMTP from environment variables. Verification links expire after 24 hours; password-reset links expire after 60 minutes. Issuing a new link invalidates the previous unused link, and successful password reset invalidates all sessions.

## Reverse proxy

Django trusts `X-Forwarded-Proto: https`, uses `STATIC_ROOT=server/staticfiles`, and derives client IPs from `X-Forwarded-For` using `TRUSTED_PROXY_COUNT`. nginx must replace or safely append forwarding headers and the configured proxy count must match the trusted topology; never accept spoofable forwarding headers directly from the public internet.

Production example:

```sh
gunicorn config.wsgi:application --bind 127.0.0.1:8000
```

Enable HTTPS redirect and HSTS only after nginx HTTPS and forwarded-protocol handling are verified.

## Tests

Run:

```powershell
python manage.py test accounts audit
```

