from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    class Event(models.TextChoices):
        REGISTRATION = "registration", "Registration"
        EMAIL_VERIFIED = "email_verified", "Email verified"
        EMAIL_VERIFICATION_FAILED = "email_verification_failed", "Email verification failed"
        VERIFICATION_RESENT = "verification_resent", "Verification resent"
        LOGIN_SUCCEEDED = "login_succeeded", "Login succeeded"
        LOGIN_FAILED = "login_failed", "Login failed"
        LOGOUT = "logout", "Logout"
        LOGOUT_ALL = "logout_all", "Logout all"
        SESSION_REVOKED = "session_revoked", "Session revoked"
        PASSWORD_RESET_REQUESTED = "password_reset_requested", "Password reset requested"
        PASSWORD_RESET_COMPLETED = "password_reset_completed", "Password reset completed"
        PASSWORD_CHANGED = "password_changed", "Password changed"
        ROLE_CHANGED = "role_changed", "Role changed"
        PERMISSIONS_CHANGED = "permissions_changed", "Permissions changed"

    event = models.CharField(max_length=64, choices=Event.choices, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="audit_actions",
    )
    subject = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="audit_events",
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.event} at {self.created_at.isoformat()}"
