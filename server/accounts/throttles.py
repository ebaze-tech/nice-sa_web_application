import hashlib

from django.conf import settings
from rest_framework.throttling import SimpleRateThrottle, UserRateThrottle

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

    def allow_request(self, request, view):
        if self.rate is None:
            return True

        self.num_requests, self.duration = self.parse_rate(self.rate)
        self.now = self.timer()
        raw = request.data.get(self.field_name, "") if hasattr(request, "data") else ""
        normalized = normalize_identifier(str(raw)) or "unknown"
        client_ip = get_client_ip(request) or "unknown"
        keys = (
            self.cache_format % {
                "scope": self.scope,
                "ident": f"identifier:{_digest(normalized)}",
            },
            self.cache_format % {
                "scope": self.scope,
                "ident": f"ip:{_digest(client_ip)}",
            },
        )

        histories = {}
        blocked_history = None
        for key in keys:
            history = self.cache.get(key, [])
            while history and history[-1] <= self.now - self.duration:
                history.pop()
            histories[key] = history
            if len(history) >= self.num_requests:
                if blocked_history is None or history[-1] < blocked_history[-1]:
                    blocked_history = history

        if blocked_history is not None:
            self.history = blocked_history
            return self.throttle_failure()

        for key, history in histories.items():
            history.insert(0, self.now)
            self.cache.set(key, history, self.duration)
        self.history = next(iter(histories.values()))
        return True


class RegistrationThrottle(ClientIPThrottle):
    scope = "registration"


class ResendVerificationThrottle(ClientIPThrottle):
    scope = "resend_verification"


class PasswordResetThrottle(ClientIPThrottle):
    scope = "password_reset"


class ChangePasswordThrottle(UserRateThrottle):
    scope = "change_password"
