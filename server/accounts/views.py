from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.middleware.csrf import get_token
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError

from audit.models import AuditLog
from audit.services import record_event

from .constants import OFFICER_PERMISSION_CODENAMES, OFFICER_PERMISSIONS
from .cookies import clear_refresh_cookie, set_refresh_cookie
from .emails import send_password_changed_email, send_password_reset_email, send_verification_email
from .exceptions import GenericLoginError, InvalidRefreshSession, MissingRefreshSession
from .models import AuthSession, OneTimeToken, User
from .permissions import IsAdminRole
from .serializers import (
    AuthSessionSerializer,
    ChangePasswordSerializer,
    CsrfResponseSerializer,
    EmailSerializer,
    LoginResponseSerializer,
    LoginSerializer,
    MessageSerializer,
    OfficerPermissionsSerializer,
    PasswordResetConfirmSerializer,
    PermissionDefinitionSerializer,
    RefreshResponseSerializer,
    RegistrationSerializer,
    TokenSerializer,
    UserSerializer,
)
from .services import (
    check_login_lock,
    clear_login_failures,
    issue_one_time_token,
    issue_session_tokens,
    record_login_failure,
    revoke_all_sessions,
    revoke_other_sessions,
    revoke_session_for_refresh_reuse,
    revoke_session,
    rotate_session_refresh,
)
from .throttles import (
    ChangePasswordThrottle,
    LoginThrottle,
    PasswordResetThrottle,
    RegistrationThrottle,
    ResendVerificationThrottle,
)
from .utils import (
    get_client_ip,
    get_user_agent,
    identifier_digest,
    normalize_email,
    normalize_identifier,
    token_digest,
)


def request_context(request):
    return {"ip_address": get_client_ip(request), "user_agent": get_user_agent(request)}


def registration_conflict_errors(exc, validated_data):
    errors = {}
    constraint_name = getattr(getattr(getattr(exc, "__cause__", None), "diag", None), "constraint_name", "")
    error_text = f"{constraint_name} {exc}".lower()
    email = validated_data["email"]
    matric_number = validated_data["matric_number"]
    if (
        "accounts_user_email_ci_unique" in error_text
        or "accounts_user.email" in error_text
        or User.objects.filter(email__iexact=email).exists()
    ):
        errors["email"] = ["An account with this email already exists."]
    if (
        "accounts_user_matric_ci_unique" in error_text
        or "accounts_user.matric_number" in error_text
        or User.objects.filter(matric_number__iexact=matric_number).exists()
    ):
        errors["matric_number"] = ["An account with this matric number already exists."]
    return errors


class RegistrationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [RegistrationThrottle]

    @extend_schema(request=RegistrationSerializer, responses={201: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            with transaction.atomic():
                user = serializer.save()
        except IntegrityError as exc:
            errors = registration_conflict_errors(exc, serializer.validated_data)
            if not errors:
                raise
            raise ValidationError(errors)
        _, raw_token = issue_one_time_token(
            user,
            OneTimeToken.Purpose.EMAIL_VERIFICATION,
            timedelta(hours=settings.EMAIL_VERIFICATION_HOURS),
        )
        transaction.on_commit(
            lambda user=user, raw_token=raw_token: send_verification_email(user, raw_token)
        )
        record_event(AuditLog.Event.REGISTRATION, subject=user, **request_context(request))
        return Response(
            {"message": "Registration successful. Check your email to verify your account."},
            status=status.HTTP_201_CREATED,
        )


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(request=TokenSerializer, responses={200: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        serializer = TokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = OneTimeToken.objects.select_for_update().filter(
            purpose=OneTimeToken.Purpose.EMAIL_VERIFICATION,
            digest=token_digest(serializer.validated_data["token"]),
        ).select_related("user").first()
        if not token or not token.is_usable:
            raise ValidationError({"token": ["This verification link is invalid or has expired."]})
        token.used_at = timezone.now()
        token.save(update_fields=("used_at",))
        user = token.user
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=("is_active",))
        record_event(AuditLog.Event.EMAIL_VERIFIED, subject=user, **request_context(request))
        return Response({"message": "Email verified. You can now sign in."})


class ResendVerificationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [ResendVerificationThrottle]

    @extend_schema(request=EmailSerializer, responses={200: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(email__iexact=serializer.validated_data["email"], is_active=False).first()
        if user:
            _, raw_token = issue_one_time_token(
                user,
                OneTimeToken.Purpose.EMAIL_VERIFICATION,
                timedelta(hours=settings.EMAIL_VERIFICATION_HOURS),
            )
            transaction.on_commit(
                lambda user=user, raw_token=raw_token: send_verification_email(user, raw_token)
            )
            record_event(AuditLog.Event.VERIFICATION_RESENT, subject=user, **request_context(request))
        return Response({"message": "If the account is awaiting verification, a new link has been sent."})


@method_decorator(ensure_csrf_cookie, name="dispatch")
@method_decorator(csrf_protect, name="dispatch")
class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [LoginThrottle]

    @extend_schema(
        request=LoginSerializer,
        responses={200: LoginResponseSerializer},
        description=(
            "Authenticate by email or matric number. The refresh token is set only in an "
            "HttpOnly cookie; send the CSRF cookie value in X-CSRFToken."
        ),
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = normalize_identifier(serializer.validated_data["identifier"])
        password = serializer.validated_data["password"]
        check_login_lock(identifier)
        user = authenticate(request=request, identifier=identifier, password=password)
        if user is None:
            record_login_failure(identifier)
            record_event(
                AuditLog.Event.LOGIN_FAILED,
                metadata={"identifier_hash": identifier_digest(identifier)},
                **request_context(request),
            )
            raise GenericLoginError()
        clear_login_failures(identifier)
        session, access, refresh = issue_session_tokens(user, **request_context(request))
        record_event(
            AuditLog.Event.LOGIN_SUCCEEDED,
            actor=user,
            subject=user,
            metadata={"session_id": str(session.id)},
            **request_context(request),
        )
        response = Response(
            {
                "access": access,
                "session_id": session.id,
                "csrf_token": get_token(request),
                "user": UserSerializer(user).data,
            }
        )
        set_refresh_cookie(response, refresh)
        return response


@method_decorator(csrf_protect, name="dispatch")
class RefreshView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        request=None,
        responses={200: RefreshResponseSerializer},
        description="Rotate the HttpOnly refresh cookie. Requires a valid X-CSRFToken header.",
    )
    def post(self, request):
        raw_refresh = request.COOKIES.get(settings.REFRESH_COOKIE_NAME)
        if not raw_refresh:
            raise MissingRefreshSession()
        try:
            session, access, refresh = rotate_session_refresh(raw_refresh)
        except TokenError:
            revoke_session_for_refresh_reuse(raw_refresh)
            raise InvalidRefreshSession()
        response = Response(
            {
                "access": access,
                "session_id": session.id,
                "csrf_token": get_token(request),
            }
        )
        set_refresh_cookie(response, refresh)
        return response


@method_decorator(csrf_protect, name="dispatch")
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={200: MessageSerializer})
    def post(self, request):
        session = request.auth_session
        revoke_session(session, "logout")
        record_event(
            AuditLog.Event.LOGOUT,
            actor=request.user,
            subject=request.user,
            metadata={"session_id": str(session.id)},
            **request_context(request),
        )
        response = Response({"message": "Signed out successfully."})
        clear_refresh_cookie(response)
        return response


class LogoutAllView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={200: MessageSerializer})
    def post(self, request):
        count = revoke_all_sessions(request.user, "logout_all")
        record_event(
            AuditLog.Event.LOGOUT_ALL,
            actor=request.user,
            subject=request.user,
            metadata={"sessions_revoked": count},
            **request_context(request),
        )
        response = Response({"message": "All sessions have been signed out."})
        clear_refresh_cookie(response)
        return response


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [PasswordResetThrottle]

    @extend_schema(request=EmailSerializer, responses={200: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = normalize_email(serializer.validated_data["email"])
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user:
            _, raw_token = issue_one_time_token(
                user,
                OneTimeToken.Purpose.PASSWORD_RESET,
                timedelta(minutes=settings.PASSWORD_RESET_MINUTES),
            )
            transaction.on_commit(
                lambda user=user, raw_token=raw_token: send_password_reset_email(user, raw_token)
            )
            record_event(AuditLog.Event.PASSWORD_RESET_REQUESTED, subject=user, **request_context(request))
        return Response({"message": "If an active account uses that email, a reset link has been sent."})


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [PasswordResetThrottle]

    @extend_schema(request=PasswordResetConfirmSerializer, responses={200: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = OneTimeToken.objects.select_for_update().filter(
            purpose=OneTimeToken.Purpose.PASSWORD_RESET,
            digest=token_digest(serializer.validated_data["token"]),
        ).select_related("user").first()
        if not token or not token.is_usable:
            raise ValidationError({"token": ["This password reset link is invalid or has expired."]})
        user = token.user
        new_password = serializer.validated_data["new_password"]
        # Re-run with the real user so UserAttributeSimilarityValidator can compare
        # the password against email, first_name, last_name, and matric_number.
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": getattr(exc, "messages", [str(exc)])}) from exc
        user.set_password(new_password)
        user.save(update_fields=("password",))
        token.used_at = timezone.now()
        token.save(update_fields=("used_at",))
        revoke_all_sessions(user, "password_reset")
        record_event(AuditLog.Event.PASSWORD_RESET_COMPLETED, subject=user, **request_context(request))
        return Response({"message": "Password reset successful. Sign in with your new password."})


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserSerializer})
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ChangePasswordThrottle]

    @extend_schema(request=ChangePasswordSerializer, responses={200: MessageSerializer})
    @transaction.atomic
    def post(self, request):
        user = User.objects.select_for_update().get(pk=request.user.pk)
        serializer = ChangePasswordSerializer(data=request.data, context={"user": user})
        serializer.is_valid(raise_exception=True)
        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=("password",))
        revoked_count = revoke_other_sessions(user, request.auth_session, "password_changed")
        record_event(
            AuditLog.Event.PASSWORD_CHANGED,
            actor=user,
            subject=user,
            metadata={"sessions_revoked": revoked_count},
            **request_context(request),
        )
        transaction.on_commit(lambda user=user: send_password_changed_email(user))
        return Response({"message": "Password changed successfully."})


class SessionListView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: AuthSessionSerializer(many=True)})
    def get(self, request):
        sessions = request.user.auth_sessions.all()
        return Response(
            AuthSessionSerializer(
                sessions,
                many=True,
                context={"current_session_id": request.auth.get("session_id")},
            ).data
        )


class SessionRevokeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={200: MessageSerializer})
    def post(self, request, session_id):
        session = request.user.auth_sessions.filter(id=session_id).first()
        if not session:
            raise NotFound("Session was not found.")
        revoke_session(session, "user_revoked")
        record_event(
            AuditLog.Event.SESSION_REVOKED,
            actor=request.user,
            subject=request.user,
            metadata={"session_id": str(session.id)},
            **request_context(request),
        )
        response = Response({"message": "Session revoked."})
        if str(session.id) == str(request.auth.get("session_id")):
            clear_refresh_cookie(response)
        return response


class AvailablePermissionsView(APIView):
    permission_classes = [IsAdminRole]

    @extend_schema(responses={200: PermissionDefinitionSerializer(many=True)})
    def get(self, request):
        return Response(
            [
                {"codename": item.codename, "name": item.name, "area": item.area}
                for item in OFFICER_PERMISSIONS
            ]
        )


class OfficerRoleBase(APIView):
    permission_classes = [IsAdminRole]

    def target_user(self, request, user_id):
        user = get_user_model().objects.select_for_update().filter(pk=user_id).first()
        if not user:
            raise NotFound("User was not found.")
        if user.pk == request.user.pk:
            raise ValidationError({"user": ["You cannot change your own role or permissions."]})
        return user

    def permission_objects(self, codenames):
        permissions = list(
            Permission.objects.filter(
                content_type__app_label="accounts",
                codename__in=codenames,
            )
        )
        if len(permissions) != len(codenames):
            raise ValidationError({"permissions": ["One or more permissions are unavailable. Run migrations."]})
        return permissions


class PromoteOfficerView(OfficerRoleBase):
    @extend_schema(request=OfficerPermissionsSerializer, responses={200: UserSerializer})
    @transaction.atomic
    def post(self, request, user_id):
        serializer = OfficerPermissionsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = self.target_user(request, user_id)
        if target.role == User.Role.ADMIN:
            raise ValidationError({"user": ["An admin cannot be changed into an officer."]})
        if target.role == User.Role.OFFICER:
            raise ValidationError({"user": ["This user is already an officer. Edit their permissions instead."]})
        old_role = target.role
        target.role = User.Role.OFFICER
        target.is_staff = False
        target.save(update_fields=("role", "is_staff"))
        permissions = serializer.validated_data["permissions"]
        target.groups.clear()
        target.user_permissions.set(self.permission_objects(permissions))
        context = request_context(request)
        record_event(
            AuditLog.Event.ROLE_CHANGED,
            actor=request.user,
            subject=target,
            metadata={"from": old_role, "to": User.Role.OFFICER},
            **context,
        )
        record_event(
            AuditLog.Event.PERMISSIONS_CHANGED,
            actor=request.user,
            subject=target,
            metadata={"permissions": sorted(permissions)},
            **context,
        )
        return Response(UserSerializer(target).data)


class EditOfficerPermissionsView(OfficerRoleBase):
    @extend_schema(request=OfficerPermissionsSerializer, responses={200: UserSerializer})
    @transaction.atomic
    def put(self, request, user_id):
        serializer = OfficerPermissionsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = self.target_user(request, user_id)
        if target.role != User.Role.OFFICER:
            raise ValidationError({"user": ["This user is not an officer."]})
        permissions = serializer.validated_data["permissions"]
        old_permissions = sorted(
            target.user_permissions.filter(
                content_type__app_label="accounts",
                codename__in=OFFICER_PERMISSION_CODENAMES,
            ).values_list("codename", flat=True)
        )
        target.groups.clear()
        target.user_permissions.set(self.permission_objects(permissions))
        record_event(
            AuditLog.Event.PERMISSIONS_CHANGED,
            actor=request.user,
            subject=target,
            metadata={"from": old_permissions, "to": sorted(permissions)},
            **request_context(request),
        )
        return Response(UserSerializer(target).data)


class DemoteOfficerView(OfficerRoleBase):
    @extend_schema(request=None, responses={200: UserSerializer})
    @transaction.atomic
    def post(self, request, user_id):
        target = self.target_user(request, user_id)
        if target.role != User.Role.OFFICER:
            raise ValidationError({"user": ["This user is not an officer."]})
        old_permissions = sorted(
            target.user_permissions.filter(
                content_type__app_label="accounts",
                codename__in=OFFICER_PERMISSION_CODENAMES,
            ).values_list("codename", flat=True)
        )
        target.role = User.Role.STUDENT
        target.user_permissions.clear()
        target.groups.clear()
        target.save(update_fields=("role",))
        context = request_context(request)
        record_event(
            AuditLog.Event.ROLE_CHANGED,
            actor=request.user,
            subject=target,
            metadata={"from": User.Role.OFFICER, "to": User.Role.STUDENT},
            **context,
        )
        record_event(
            AuditLog.Event.PERMISSIONS_CHANGED,
            actor=request.user,
            subject=target,
            metadata={"from": old_permissions, "to": []},
            **context,
        )
        return Response(UserSerializer(target).data)


@method_decorator(ensure_csrf_cookie, name="dispatch")
class CsrfView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(responses={200: CsrfResponseSerializer})
    def get(self, request):
        return Response({"csrf_token": get_token(request)})
