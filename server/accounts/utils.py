import hashlib
import hmac
import ipaddress
import unicodedata

from django.conf import settings


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def normalize_matric_number(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(unicodedata.normalize("NFKC", value).strip().upper().split())
    return normalized or None


def normalize_identifier(value: str) -> str:
    value = value or ""
    return normalize_email(value) if "@" in value else (normalize_matric_number(value) or "")


def identifier_digest(value: str) -> str:
    normalized = normalize_identifier(value)
    return hmac.new(
        settings.SECRET_KEY.encode(),
        normalized.encode(),
        hashlib.sha256,
    ).hexdigest()


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def verification_code_digest(user_id: int, code: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode(),
        f"email-verification:{user_id}:{code}".encode(),
        hashlib.sha256,
    ).hexdigest()


def get_client_ip(request) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    trusted_count = max(int(getattr(settings, "TRUSTED_PROXY_COUNT", 0)), 0)
    if forwarded_for and trusted_count:
        addresses = [part.strip() for part in forwarded_for.split(",") if part.strip()]
        if len(addresses) >= trusted_count:
            index = max(len(addresses) - trusted_count, 0)
            candidate = addresses[index]
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    candidate = request.META.get("REMOTE_ADDR") or None
    try:
        return str(ipaddress.ip_address(candidate)) if candidate else None
    except ValueError:
        return None


def get_user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:512]
