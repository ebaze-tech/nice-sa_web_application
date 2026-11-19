from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.state import token_backend

from .exceptions import LoginLocked, RevokedSession
from .models import AuthSession, LoginAttempt, OneTimeToken
from .utils import identifier_digest


def check_login_lock(identifier):
    digest = identifier_digest(identifier)
    now = timezone.now()
    attempt = LoginAttempt.objects.filter(identifier_hash=digest).first()
    if attempt and attempt.locked_until and attempt.locked_until > now:
        raise LoginLocked()
    if attempt and attempt.locked_until and attempt.locked_until <= now:
        LoginAttempt.objects.filter(pk=attempt.pk).update(failed_count=0, locked_until=None)


@transaction.atomic
def record_login_failure(identifier):
    digest = identifier_digest(identifier)
    attempt, _ = LoginAttempt.objects.select_for_update().get_or_create(identifier_hash=digest)
    attempt.failed_count += 1
    if attempt.failed_count >= settings.LOGIN_MAX_FAILURES:
        attempt.locked_until = timezone.now() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    attempt.save(update_fields=("failed_count", "locked_until", "updated_at"))


def clear_login_failures(identifier):
    LoginAttempt.objects.filter(identifier_hash=identifier_digest(identifier)).delete()


def issue_one_time_token(user, purpose, lifetime):
    return OneTimeToken.issue(user=user, purpose=purpose, expires_at=timezone.now() + lifetime)


def issue_session_tokens(user, *, ip_address=None, user_agent=""):
    refresh = RefreshToken.for_user(user)
    session = AuthSession.objects.create(
        user=user,
        refresh_jti=str(refresh["jti"]),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512],
    )
    refresh["session_id"] = str(session.id)
    return session, str(refresh.access_token), str(refresh)


@transaction.atomic
def rotate_session_refresh(raw_refresh):
    refresh = RefreshToken(raw_refresh)
    session_id = refresh.get("session_id")
    try:
        session = AuthSession.objects.select_for_update().select_related("user").get(
            id=session_id,
            refresh_jti=str(refresh["jti"]),
            revoked_at__isnull=True,
            user__is_active=True,
        )
    except (AuthSession.DoesNotExist, ValueError):
        raise RevokedSession("Session is no longer active.")
    refresh.blacklist()
    new_refresh = RefreshToken.for_user(session.user)
    new_refresh["session_id"] = str(session.id)
    session.refresh_jti = str(new_refresh["jti"])
    session.last_active_at = timezone.now()
    session.save(update_fields=("refresh_jti", "last_active_at"))
    return session, str(new_refresh.access_token), str(new_refresh)


def revoke_session_for_refresh_reuse(raw_refresh):
    """Revoke a token family when an already-rotated refresh token is replayed."""
    try:
        claims = token_backend.decode(raw_refresh, verify=True)
    except Exception:
        return
    if claims.get("token_type") != "refresh" or not claims.get("session_id"):
        return
    session = AuthSession.objects.filter(
        id=claims["session_id"],
        revoked_at__isnull=True,
    ).first()
    if session and session.refresh_jti != str(claims.get("jti", "")):
        revoke_session(session, "refresh_reuse")


def blacklist_session(session):
    outstanding = OutstandingToken.objects.filter(jti=session.refresh_jti).first()
    if outstanding:
        BlacklistedToken.objects.get_or_create(token=outstanding)


def revoke_session(session, reason):
    blacklist_session(session)
    session.revoke(reason)


def revoke_all_sessions(user, reason):
    sessions = list(user.auth_sessions.filter(revoked_at__isnull=True))
    for session in sessions:
        blacklist_session(session)
    now = timezone.now()
    user.auth_sessions.filter(revoked_at__isnull=True).update(revoked_at=now, revoke_reason=reason)
    return len(sessions)
