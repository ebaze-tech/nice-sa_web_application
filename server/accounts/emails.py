from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import send_mail


def _url(base, raw_token):
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode({'token': raw_token})}"


def send_verification_email(user, raw_token):
    send_mail(
        "Verify your NICESA account",
        (
            f"Hello {user.first_name},\n\n"
            "Verify your NICESA account using this link:\n"
            f"{_url(settings.FRONTEND_VERIFY_URL, raw_token)}\n\n"
            f"This link expires in {settings.EMAIL_VERIFICATION_HOURS} hours and can be used once."
        ),
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


def send_password_reset_email(user, raw_token):
    send_mail(
        "Reset your NICESA password",
        (
            f"Hello {user.first_name or 'there'},\n\n"
            "Reset your password using this link:\n"
            f"{_url(settings.FRONTEND_PASSWORD_RESET_URL, raw_token)}\n\n"
            f"This link expires in {settings.PASSWORD_RESET_MINUTES} minutes and can be used once."
        ),
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


def send_password_changed_email(user):
    send_mail(
        "Your NICESA password was changed",
        (
            f"Hello {user.first_name or 'there'},\n\n"
            "Your NICESA account password was changed successfully.\n\n"
            "If you did not make this change, contact the department administrator immediately."
        ),
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
