# NICESA backend

This directory contains the Django/DRF backend. The current scope is authentication and authorization only.

## Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Create `.env` in this directory using the environment-variable table below.
4. Run `python manage.py migrate` against your local database.
5. Create the first administrator with `python manage.py createsuperuser`.
6. Run `python manage.py runserver`.

## Environment variables

`DJANGO_ENV=development` enables the documented local defaults. In every other environment, startup fails unless the five production-required values below are present.

| Variable | Default | Required in production |
| --- | --- | --- |
| `DJANGO_ENV` | `development` | No |
| `DJANGO_SECRET_KEY` | Unsafe development-only key | Yes; minimum 32 characters |
| `DJANGO_DEBUG` | `True` in development; `False` otherwise | No |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1,testserver` in development | Yes |
| `DATABASE_URL` | `sqlite:///server/db.sqlite3` in development | Yes |
| `DB_CONN_MAX_AGE` | `60` seconds | No |
| `DJANGO_TIME_ZONE` | `Africa/Lagos` | No |
| `USE_X_FORWARDED_HOST` | `True` | No |
| `TRUSTED_PROXY_COUNT` | `1` | No |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` in development; empty otherwise | No |
| `CSRF_TRUSTED_ORIGINS` | `http://localhost:3000` in development; empty otherwise | No |
| `CSRF_COOKIE_SECURE` | Opposite of `DEBUG` | No |
| `CSRF_COOKIE_SAMESITE` | `Lax` | No |
| `SESSION_COOKIE_SECURE` | Opposite of `DEBUG` | No |
| `REFRESH_COOKIE_NAME` | `nicesa_refresh` | No |
| `REFRESH_COOKIE_SECURE` | Opposite of `DEBUG` | No |
| `REFRESH_COOKIE_SAMESITE` | `Lax` | No |
| `REFRESH_COOKIE_DOMAIN` | Unset | No |
| `REFRESH_COOKIE_PATH` | `/api/v1/auth/` | No |
| `LOGIN_THROTTLE_RATE` | `10/minute` | No |
| `REGISTRATION_THROTTLE_RATE` | `5/hour` | No |
| `RESEND_VERIFICATION_THROTTLE_RATE` | `5/hour` | No |
| `PASSWORD_RESET_THROTTLE_RATE` | `5/hour` | No |
| `CHANGE_PASSWORD_THROTTLE_RATE` | `10/hour` | No |
| `JWT_ACCESS_MINUTES` | `5` | No |
| `JWT_REFRESH_DAYS` | `7` | No |
| `EMAIL_HOST` | Empty | No |
| `EMAIL_PORT` | `587` | No |
| `EMAIL_HOST_USER` | Empty | No |
| `EMAIL_HOST_PASSWORD` | Empty | No |
| `EMAIL_USE_TLS` | `True` | No |
| `EMAIL_USE_SSL` | `False` | No |
| `EMAIL_TIMEOUT` | `10` seconds | No |
| `DEFAULT_FROM_EMAIL` | `NICESA <no-reply@example.com>` | No |
| `FRONTEND_VERIFY_URL` | `http://localhost:3000/verify-email` in development | Yes |
| `FRONTEND_PASSWORD_RESET_URL` | `http://localhost:3000/reset-password` in development | Yes |
| `EMAIL_VERIFICATION_HOURS` | `24` | No |
| `PASSWORD_RESET_MINUTES` | `60` | No |
| `LOGIN_MAX_FAILURES` | `5` | No |
| `LOGIN_LOCKOUT_MINUTES` | `15` | No |
| `SECURE_SSL_REDIRECT` | `False` | No |
| `SECURE_HSTS_SECONDS` | `0` | No |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `False` | No |
| `SECURE_HSTS_PRELOAD` | `False` | No |

Development uses the console email backend. Other environments use SMTP and should configure the relevant `EMAIL_*` values for their provider.

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
| POST | `change-password/` | Change the authenticated user's password, retain the current session, and revoke all others. |
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


## Password policy

All passwords — registration, password-reset, and admin-created users — are validated against the following rules. Every violated rule is reported in the same response.

| Rule | Detail |
| --- | --- |
| Minimum length | 8 characters |
| Maximum length | 128 characters (prevents hashing-abuse DoS) |
| Uppercase letter | At least one A–Z |
| Lowercase letter | At least one a–z |
| Digit | At least one 0–9 |
| Special character | At least one non-alphanumeric printable character |
| Not similar to user attributes | Compared against email, first name, last name, and matric number |
| Not on common-password list | Django's built-in list of ~20 000 common passwords |
| Not entirely numeric | Must contain at least one non-digit character |

Validation errors are returned field-level under `error.fields.password` (registration) or `error.fields.new_password` (password reset and authenticated password change) in the standard error envelope.


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

## Email and expiry

Development uses Django's console email backend. Any other `DJANGO_ENV` uses SMTP from environment variables. Verification links expire after 24 hours; password-reset links expire after 60 minutes. Issuing a new link invalidates the previous unused link, and successful password reset invalidates all sessions. Verification, reset, and password-change emails are sent only after the surrounding database transaction commits.


## Tests

Run:

```powershell
python manage.py test accounts audit
```

