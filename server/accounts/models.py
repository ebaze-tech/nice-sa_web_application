import secrets
import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import Q
from django.db.models.functions import Lower, Upper
from django.utils import timezone

from .constants import OFFICER_PERMISSIONS
from .managers import UserManager
from .utils import normalize_email, normalize_matric_number, token_digest


def validate_matric_number(value):
    normalized = normalize_matric_number(value)
    if normalized and len(normalized) > 64:
        raise ValidationError("Matric number must be no longer than 64 characters after normalization.")
    if normalized and "@" in normalized:
        raise ValidationError("Matric number cannot contain '@'.")
    if normalized and any(not char.isprintable() for char in normalized):
        raise ValidationError("Matric number contains unsupported characters.")


class User(AbstractUser):
    class Role(models.TextChoices):
        STUDENT = "student", "Student"
        OFFICER = "officer", "Officer / staff"
        ADMIN = "admin", "Admin"

    class Level(models.IntegerChoices):
        LEVEL_100 = 100, "100"
        LEVEL_200 = 200, "200"
        LEVEL_300 = 300, "300"
        LEVEL_400 = 400, "400"
        LEVEL_500 = 500, "500"

    username = None
    email = models.EmailField(unique=True)
    matric_number = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        validators=[validate_matric_number],
    )
    level = models.PositiveSmallIntegerField(choices=Level.choices, null=True, blank=True)
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.STUDENT)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("email"), name="accounts_user_email_ci_unique"),
            models.UniqueConstraint(
                Upper("matric_number"),
                condition=Q(matric_number__isnull=False),
                name="accounts_user_matric_ci_unique",
            ),
            models.CheckConstraint(
                condition=~Q(role="admin") | Q(is_superuser=True),
                name="accounts_admin_role_requires_superuser",
            ),
        ]
        permissions = [(item.codename, item.name) for item in OFFICER_PERMISSIONS]

    def clean(self):
        super().clean()
        self.email = normalize_email(self.email)
        self.matric_number = normalize_matric_number(self.matric_number)
        validate_matric_number(self.matric_number)
        if self.role == self.Role.ADMIN and not self.is_superuser:
            raise ValidationError({"role": "The admin role requires superuser status."})

    def save(self, *args, **kwargs):
        self.email = normalize_email(self.email)
        self.matric_number = normalize_matric_number(self.matric_number)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email


class AuthSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="auth_sessions")
    refresh_jti = models.CharField(max_length=255, unique=True)
    user_agent = models.CharField(max_length=512, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("-last_active_at",)
        indexes = [models.Index(fields=("user", "revoked_at"))]

    @property
    def is_active(self):
        return self.revoked_at is None and self.user.is_active

    def revoke(self, reason="revoked"):
        if not self.revoked_at:
            self.revoked_at = timezone.now()
            self.revoke_reason = reason
            self.save(update_fields=("revoked_at", "revoke_reason"))


class OneTimeToken(models.Model):
    class Purpose(models.TextChoices):
        EMAIL_VERIFICATION = "email_verification", "Email verification"
        PASSWORD_RESET = "password_reset", "Password reset"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="one_time_tokens")
    purpose = models.CharField(max_length=32, choices=Purpose.choices)
    digest = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=("purpose", "digest"))]
        constraints = [
            models.UniqueConstraint(
                fields=("user", "purpose"),
                condition=Q(used_at__isnull=True),
                name="accounts_one_active_token_per_purpose",
            )
        ]

    @classmethod
    @transaction.atomic
    def issue(cls, *, user, purpose, expires_at):
        now = timezone.now()
        user.__class__.objects.select_for_update().get(pk=user.pk)
        cls.objects.filter(user=user, purpose=purpose, used_at__isnull=True).update(used_at=now)
        raw_token = secrets.token_urlsafe(32)
        instance = cls.objects.create(
            user=user,
            purpose=purpose,
            digest=token_digest(raw_token),
            expires_at=expires_at,
        )
        return instance, raw_token

    @property
    def is_usable(self):
        return self.used_at is None and self.expires_at > timezone.now()


class LoginAttempt(models.Model):
    identifier_hash = models.CharField(max_length=64, unique=True)
    failed_count = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
