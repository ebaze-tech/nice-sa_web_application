from django.http import JsonResponse
from rest_framework import exceptions, status
from rest_framework.views import exception_handler


class Unauthorized(exceptions.APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Authentication failed."
    default_code = "authentication_failed"


class GenericLoginError(Unauthorized):
    default_detail = "Unable to sign in with the provided credentials."
    default_code = "invalid_credentials"


class InvalidRefreshSession(Unauthorized):
    default_detail = "Refresh session is invalid or expired."
    default_code = "refresh_invalid"


class MissingRefreshSession(Unauthorized):
    default_detail = "Refresh session is missing."
    default_code = "refresh_missing"


class RevokedSession(Unauthorized):
    default_detail = "Session has been revoked."
    default_code = "session_revoked"


class LoginLocked(exceptions.APIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = "Too many unsuccessful attempts. Please try again later."
    default_code = "login_locked"


def csrf_failure(request, reason=""):
    return JsonResponse(
        {
            "error": {
                "code": "csrf_failed",
                "message": "Security validation failed. Refresh the page and try again.",
                "fields": {},
            }
        },
        status=status.HTTP_403_FORBIDDEN,
    )


def _field_errors(detail):
    fields = {}
    for field, errors in detail.items():
        values = errors if isinstance(errors, (list, tuple)) else [errors]
        fields[field] = [
            {"message": str(item), "code": getattr(item, "code", "invalid")}
            for item in values
        ]
    return fields


def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return None

    if isinstance(exc, exceptions.ValidationError):
        detail = response.data
        if isinstance(detail, dict):
            fields = _field_errors(detail)
        else:
            fields = {"non_field_errors": _field_errors({"errors": detail})["errors"]}
        response.data = {
            "error": {
                "code": "validation_error",
                "message": "Please correct the highlighted fields.",
                "fields": fields,
            }
        }
        return response

    code = getattr(exc, "default_code", "error")
    if hasattr(exc, "get_codes"):
        codes = exc.get_codes()
        if isinstance(codes, str):
            code = codes
    if response.status_code == status.HTTP_403_FORBIDDEN:
        code = "permission_denied"
        message = "You do not have permission to perform this action."
    else:
        detail = response.data.get("detail", response.data) if isinstance(response.data, dict) else response.data
        message = str(detail)
    response.data = {"error": {"code": code, "message": message, "fields": {}}}
    return response
