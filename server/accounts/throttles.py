import hashlib

from django.conf import settings
from rest_framework.throttling import SimpleRateThrottle

from .utils import get_client_ip, normalize_identifier


def _digest(discriminator):
    return hashlib.sha256(f"{settings.SECRET_KEY}:{discriminator}".encode()).hexdigest()


class IdentifierThrottle(SimpleRateThrottle):
    field_name = "identifier"

    def get_cache_key(self, request, view):
        raw = request.data.get(self.field_name, "") if hasattr(request, "data") else ""
        normalized = normalize_identifier(str(raw))
        discriminator = normalized or get_client_ip(request) or "unknown"
        return self.cache_format % {"scope": self.scope, "ident": _digest(discriminator)}


class ClientIPThrottle(SimpleRateThrottle):
    def get_cache_key(self, request, view):
        discriminator = get_client_ip(request) or "unknown"
        return self.cache_format % {"scope": self.scope, "ident": _digest(discriminator)}


class LoginThrottle(IdentifierThrottle):
    scope = "login"


class RegistrationThrottle(ClientIPThrottle):
    scope = "registration"


class ResendVerificationThrottle(ClientIPThrottle):
    scope = "resend_verification"


class PasswordResetThrottle(ClientIPThrottle):
    scope = "password_reset"
