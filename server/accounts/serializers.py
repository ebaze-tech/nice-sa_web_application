from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.models import Permission
from rest_framework import serializers

from .constants import OFFICER_PERMISSION_CODENAMES, OFFICER_PERMISSIONS
from .models import AuthSession, User, validate_matric_number
from .utils import normalize_email, normalize_matric_number


class RegistrationSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=150, allow_blank=False)
    last_name = serializers.CharField(max_length=150, allow_blank=False)
    matric_number = serializers.CharField(allow_blank=False)
    password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "matric_number", "level", "password")

    def validate_email(self, value):
        value = normalize_email(value)
        if not value.endswith("@stu.ui.edu.ng") or value == "@stu.ui.edu.ng":
            raise serializers.ValidationError("Use your University of Ibadan student email ending in @stu.ui.edu.ng.")
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value

    def validate_matric_number(self, value):
        value = normalize_matric_number(value)
        if not value:
            raise serializers.ValidationError("Matric number is required.")
        try:
            validate_matric_number(value)
        except Exception as exc:
            raise serializers.ValidationError(exc.messages if hasattr(exc, "messages") else str(exc))
        if User.objects.filter(matric_number__iexact=value).exists():
            raise serializers.ValidationError("An account with this matric number already exists.")
        return value

    def validate(self, attrs):
        candidate = User(
            first_name=attrs.get("first_name", ""),
            last_name=attrs.get("last_name", ""),
            email=attrs.get("email", ""),
            matric_number=attrs.get("matric_number"),
            level=attrs.get("level"),
            role=User.Role.STUDENT,
        )
        try:
            password_validation.validate_password(attrs.get("password"), user=candidate)
        except Exception as exc:
            raise serializers.ValidationError(
                {"password": getattr(exc, "messages", [str(exc)])}
            ) from exc
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password")
        return User.objects.create_user(
            password=password,
            role=User.Role.STUDENT,
            is_active=False,
            **validated_data,
        )


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return normalize_email(value)


class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(trim_whitespace=False)


class VerificationCodeField(serializers.RegexField):
    def __init__(self, **kwargs):
        kwargs.setdefault(
            "regex",
            rf"^[0-9]{{{settings.EMAIL_VERIFICATION_CODE_LENGTH}}}$",
        )
        kwargs.setdefault("min_length", settings.EMAIL_VERIFICATION_CODE_LENGTH)
        kwargs.setdefault("max_length", settings.EMAIL_VERIFICATION_CODE_LENGTH)
        kwargs.setdefault("trim_whitespace", False)
        kwargs.setdefault(
            "help_text",
            f"Exactly {settings.EMAIL_VERIFICATION_CODE_LENGTH} numeric digits. Send as a string so leading zeros are preserved.",
        )
        super().__init__(**kwargs)

    def to_internal_value(self, data):
        if not isinstance(data, str):
            self.fail("invalid")
        return super().to_internal_value(data)


class VerifyEmailCodeSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Account email.")
    code = VerificationCodeField()


class VerifyEmailLinkSerializer(serializers.Serializer):
    token = serializers.CharField(
        trim_whitespace=False,
        help_text="The single-use token from the verification link.",
    )


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField(
        required=False,
        trim_whitespace=False,
        help_text="The single-use token from the verification link.",
    )
    email = serializers.EmailField(
        required=False,
        help_text="Account email. Required when verifying with a code.",
    )
    code = VerificationCodeField(required=False)

    def validate_email(self, value):
        return normalize_email(value)

    def validate(self, attrs):
        has_token = "token" in attrs
        has_code_pair = "email" in attrs and "code" in attrs
        if has_token == has_code_pair or ("email" in attrs) != ("code" in attrs):
            raise serializers.ValidationError(
                "Send exactly one verification method: token, or email and code."
            )
        return attrs


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True, trim_whitespace=False)


class PasswordResetConfirmSerializer(TokenSerializer):
    new_password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)

    def validate_new_password(self, value):
        # Run validators here so errors are field-level and reported all at once.
        # The view still passes the user object for similarity checks.
        # We do a preliminary run without a user so the serializer can fail fast
        # on composition rules before the view looks up the token; the view will
        # re-run validation with the real user for similarity checking.
        try:
            password_validation.validate_password(value)
        except Exception as exc:
            raise serializers.ValidationError(
                getattr(exc, "messages", [str(exc)])
            ) from exc
        return value


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False, max_length=128)

    def validate_current_password(self, value):
        if not self.context["user"].check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value):
        user = self.context["user"]
        if user.check_password(value):
            raise serializers.ValidationError("New password must differ from the current password.")
        try:
            password_validation.validate_password(value, user=user)
        except Exception as exc:
            raise serializers.ValidationError(getattr(exc, "messages", [str(exc)])) from exc
        return value


class UserSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "first_name", "last_name", "email", "matric_number", "level", "role", "permissions")

    def get_permissions(self, obj) -> list[str]:
        if obj.role == User.Role.ADMIN:
            return sorted(item.codename for item in OFFICER_PERMISSIONS)
        if obj.role != User.Role.OFFICER:
            return []
        return sorted(
            Permission.objects.filter(
                user=obj,
                content_type__app_label="accounts",
                codename__in=OFFICER_PERMISSION_CODENAMES,
            ).values_list("codename", flat=True)
        )


class MessageSerializer(serializers.Serializer):
    message = serializers.CharField()


class LoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    session_id = serializers.UUIDField()
    csrf_token = serializers.CharField()
    user = UserSerializer()


class RefreshResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    session_id = serializers.UUIDField()
    csrf_token = serializers.CharField()


class CsrfResponseSerializer(serializers.Serializer):
    csrf_token = serializers.CharField()


class PermissionDefinitionSerializer(serializers.Serializer):
    codename = serializers.CharField()
    name = serializers.CharField()
    area = serializers.CharField()


class AuthSessionSerializer(serializers.ModelSerializer):
    current = serializers.SerializerMethodField()
    active = serializers.SerializerMethodField()

    class Meta:
        model = AuthSession
        fields = ("id", "user_agent", "ip_address", "created_at", "last_active_at", "active", "current")

    def get_current(self, obj) -> bool:
        return str(obj.id) == str(self.context.get("current_session_id"))

    def get_active(self, obj) -> bool:
        return obj.revoked_at is None


class OfficerPermissionsSerializer(serializers.Serializer):
    permissions = serializers.ListField(
        child=serializers.ChoiceField(choices=sorted(OFFICER_PERMISSION_CODENAMES)),
        allow_empty=True,
    )

    def validate_permissions(self, value):
        if len(value) != len(set(value)):
            raise serializers.ValidationError("Permission values must be unique.")
        return value
