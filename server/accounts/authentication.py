from datetime import timedelta

from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from .models import AuthSession


class SessionBoundJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None
        user, token = result
        session_id = token.get("session_id")
        if not session_id:
            raise AuthenticationFailed("Token is not linked to an active session.", code="session_revoked")
        try:
            session = AuthSession.objects.get(id=session_id, user=user, revoked_at__isnull=True)
        except (AuthSession.DoesNotExist, ValueError):
            raise AuthenticationFailed("Session has been revoked.", code="session_revoked")
        now = timezone.now()
        if session.last_active_at < now - timedelta(minutes=1):
            AuthSession.objects.filter(pk=session.pk, revoked_at__isnull=True).update(last_active_at=now)
        request.auth_session = session
        return user, token
