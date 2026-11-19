from django.urls import path

from .views import (
    AvailablePermissionsView,
    CsrfView,
    DemoteOfficerView,
    EditOfficerPermissionsView,
    LoginView,
    LogoutAllView,
    LogoutView,
    MeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    PromoteOfficerView,
    RefreshView,
    RegistrationView,
    ResendVerificationView,
    SessionListView,
    SessionRevokeView,
    VerifyEmailView,
)

app_name = "accounts"

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="register"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path("resend-verification/", ResendVerificationView.as_view(), name="resend-verification"),
    path("login/", LoginView.as_view(), name="login"),
    path("refresh/", RefreshView.as_view(), name="refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("logout-all/", LogoutAllView.as_view(), name="logout-all"),
    path("password-reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("csrf/", CsrfView.as_view(), name="csrf"),
    path("me/", MeView.as_view(), name="me"),
    path("sessions/", SessionListView.as_view(), name="sessions"),
    path("sessions/<uuid:session_id>/revoke/", SessionRevokeView.as_view(), name="session-revoke"),
    path("roles/permissions/", AvailablePermissionsView.as_view(), name="available-permissions"),
    path("roles/users/<int:user_id>/promote/", PromoteOfficerView.as_view(), name="promote-officer"),
    path("roles/users/<int:user_id>/permissions/", EditOfficerPermissionsView.as_view(), name="edit-officer-permissions"),
    path("roles/users/<int:user_id>/demote/", DemoteOfficerView.as_view(), name="demote-officer"),
]
