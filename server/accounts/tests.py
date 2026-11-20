import re
import os
import subprocess
import sys
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core import mail
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory, APITestCase, force_authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken

from audit.models import AuditLog

from .admin import NicesaUserAdmin
from .forms import NicesaAdminPasswordChangeForm, NicesaUserCreationForm
from .models import AuthSession, LoginAttempt, OneTimeToken, User
from .permissions import HasNicesaPermission
from .services import issue_session_tokens
from .throttles import (
    ChangePasswordThrottle,
    LoginThrottle,
    PasswordResetThrottle,
    RegistrationThrottle,
    ResendVerificationThrottle,
)
from .validators import PasswordCompositionValidator


TEST_SETTINGS = {
    "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
    "PASSWORD_HASHERS": ["django.contrib.auth.hashers.MD5PasswordHasher"],
    "SECRET_KEY": "test-only-secret-key-that-is-longer-than-thirty-two-bytes",
    "SIMPLE_JWT": {
        **settings.SIMPLE_JWT,
        "SIGNING_KEY": "test-only-jwt-signing-key-longer-than-thirty-two-bytes",
    },
}
PASSWORD = "A-Strong-Student-Passphrase-204!"
NEW_PASSWORD = "Another-Strong-Passphrase-905!"


class AuthTestMixin:
    def setUp(self):
        super().setUp()
        cache.clear()

    def registration_payload(self, **changes):
        payload = {
            "first_name": "Ada",
            "last_name": "Okafor",
            "email": "Ada.Okafor@STU.UI.EDU.NG",
            "matric_number": "  ce/2024/001  ",
            "level": 200,
            "password": PASSWORD,
        }
        payload.update(changes)
        return payload

    def create_active_user(self, email="ada.okafor@stu.ui.edu.ng", matric="CE/2024/001", **extra):
        return User.objects.create_user(
            email=email,
            matric_number=matric,
            password=PASSWORD,
            first_name="Ada",
            last_name="Okafor",
            level=200,
            is_active=True,
            **extra,
        )

    def login(self, identifier, password=PASSWORD, client=None, **headers):
        client = client or self.client
        return client.post(
            "/api/v1/auth/login/",
            {"identifier": identifier, "password": password},
            **headers,
        )

    def authenticate(self, identifier, client=None):
        client = client or self.client
        response = self.login(identifier, client=client)
        self.assertEqual(response.status_code, 200, response.data)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}")
        return response

    def extract_email_token(self, index=-1):
        match = re.search(r"https?://\S+", mail.outbox[index].body)
        self.assertIsNotNone(match)
        return parse_qs(urlparse(match.group(0)).query)["token"][0]

    def post_with_commits(self, path, data, client=None, **headers):
        client = client or self.client
        with self.captureOnCommitCallbacks(execute=True):
            return client.post(path, data, **headers)


@override_settings(**TEST_SETTINGS)
class RegistrationAndVerificationTests(AuthTestMixin, APITestCase):
    def test_student_registration_normalizes_and_requires_verification(self):
        response = self.post_with_commits("/api/v1/auth/register/", self.registration_payload())

        self.assertEqual(response.status_code, 201, response.data)
        user = User.objects.get()
        self.assertEqual(user.email, "ada.okafor@stu.ui.edu.ng")
        self.assertEqual(user.matric_number, "CE/2024/001")
        self.assertEqual(user.role, User.Role.STUDENT)
        self.assertFalse(user.is_active)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.REGISTRATION, subject=user).exists())

    def test_registration_requires_all_student_fields(self):
        payload = self.registration_payload()
        payload.pop("first_name")
        payload.pop("matric_number")
        response = self.client.post("/api/v1/auth/register/", payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("first_name", response.data["error"]["fields"])
        self.assertIn("matric_number", response.data["error"]["fields"])

    def test_registration_rejects_non_student_email_and_invalid_level(self):
        response = self.client.post(
            "/api/v1/auth/register/",
            self.registration_payload(email="ada@example.com", level=600),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.data["error"]["fields"])
        self.assertIn("level", response.data["error"]["fields"])

    def test_registration_uniqueness_is_case_insensitive(self):
        self.create_active_user()
        response = self.client.post(
            "/api/v1/auth/register/",
            self.registration_payload(email="ADA.OKAFOR@stu.ui.edu.ng", matric_number="ce/2024/999"),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.data["error"]["fields"])

    def test_registration_rejects_normalized_duplicate_matric_number(self):
        self.create_active_user()
        response = self.client.post(
            "/api/v1/auth/register/",
            self.registration_payload(
                email="different@stu.ui.edu.ng",
                matric_number="  ce/2024/001 ",
            ),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("matric_number", response.data["error"]["fields"])

    def test_registration_validates_matric_length_after_normalization(self):
        normalized_short = self.registration_payload(
            matric_number=f"{' ' * 70}ce/2024/001{' ' * 70}"
        )
        accepted = self.client.post("/api/v1/auth/register/", normalized_short)
        rejected = self.client.post(
            "/api/v1/auth/register/",
            self.registration_payload(
                email="other@stu.ui.edu.ng",
                matric_number="CE/" + "1" * 62,
            ),
        )

        self.assertEqual(accepted.status_code, 201, accepted.data)
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("matric_number", rejected.data["error"]["fields"])

    def test_registration_translates_database_email_and_matric_conflicts(self):
        cases = (
            ("accounts_user_email_ci_unique", "email"),
            ("accounts_user_matric_ci_unique", "matric_number"),
        )
        for constraint, field in cases:
            with self.subTest(field=field), mock.patch(
                "accounts.views.RegistrationSerializer.save",
                side_effect=IntegrityError(f"UNIQUE constraint failed: index '{constraint}'"),
            ):
                response = self.client.post(
                    "/api/v1/auth/register/",
                    self.registration_payload(
                        email=f"{field}@stu.ui.edu.ng",
                        matric_number=f"CE/2024/{field}",
                    ),
                )
            self.assertEqual(response.status_code, 400, response.data)
            self.assertIn(field, response.data["error"]["fields"])

    def test_verification_email_is_deferred_until_commit(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            response = self.client.post("/api/v1/auth/register/", self.registration_payload())

        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(len(callbacks), 1)
        callbacks[0]()
        self.assertEqual(len(mail.outbox), 1)

    def test_verification_is_single_use_and_activates_account(self):
        self.post_with_commits("/api/v1/auth/register/", self.registration_payload())
        token = self.extract_email_token()

        first = self.client.post("/api/v1/auth/verify-email/", {"token": token})
        second = self.client.post("/api/v1/auth/verify-email/", {"token": token})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)
        self.assertTrue(User.objects.get().is_active)
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.EMAIL_VERIFIED).exists())

    def test_expired_verification_token_is_rejected(self):
        self.post_with_commits("/api/v1/auth/register/", self.registration_payload())
        token = self.extract_email_token()
        OneTimeToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))

        response = self.client.post("/api/v1/auth/verify-email/", {"token": token})

        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.get().is_active)

    def test_resend_is_generic_and_invalidates_previous_link(self):
        self.post_with_commits("/api/v1/auth/register/", self.registration_payload())
        old_token = self.extract_email_token()
        known = self.post_with_commits(
            "/api/v1/auth/resend-verification/",
            {"email": "ADA.OKAFOR@stu.ui.edu.ng"},
        )
        new_token = self.extract_email_token()
        unknown = self.client.post(
            "/api/v1/auth/resend-verification/",
            {"email": "unknown@stu.ui.edu.ng"},
        )

        self.assertEqual(known.data, unknown.data)
        self.assertNotEqual(old_token, new_token)
        self.assertEqual(
            self.client.post("/api/v1/auth/verify-email/", {"token": old_token}).status_code,
            400,
        )
        self.assertEqual(
            self.client.post("/api/v1/auth/verify-email/", {"token": new_token}).status_code,
            200,
        )


@override_settings(**TEST_SETTINGS)
class LoginAndSessionTests(AuthTestMixin, APITestCase):
    def test_login_accepts_email_and_normalized_matric_number(self):
        self.create_active_user()

        email_response = self.login("ADA.OKAFOR@STU.UI.EDU.NG")
        matric_response = self.login(" ce/2024/001 ")

        self.assertEqual(email_response.status_code, 200, email_response.data)
        self.assertEqual(matric_response.status_code, 200, matric_response.data)
        self.assertIn(settings.REFRESH_COOKIE_NAME, email_response.cookies)
        self.assertTrue(email_response.cookies[settings.REFRESH_COOKIE_NAME]["httponly"])
        self.assertNotIn("refresh", email_response.data)
        self.assertEqual(AuthSession.objects.count(), 2)

    def test_tokens_do_not_carry_roles_or_permissions(self):
        self.create_active_user()
        login = self.login("CE/2024/001")
        token = AccessToken(login.data["access"])

        self.assertIn("session_id", token)
        self.assertNotIn("role", token)
        self.assertNotIn("permissions", token)

    def test_login_errors_do_not_reveal_identifier_existence_or_inactive_state(self):
        self.create_active_user()
        User.objects.create_user(
            email="inactive@stu.ui.edu.ng",
            matric_number="CE/2024/777",
            password=PASSWORD,
            is_active=False,
        )

        known = self.login("ada.okafor@stu.ui.edu.ng", "wrong")
        unknown = self.login("nobody@stu.ui.edu.ng", "wrong")
        inactive = self.login("inactive@stu.ui.edu.ng", PASSWORD)

        self.assertEqual(known.status_code, 401)
        self.assertEqual(known.data, unknown.data)
        self.assertEqual(known.data, inactive.data)

    @override_settings(LOGIN_MAX_FAILURES=3, LOGIN_LOCKOUT_MINUTES=15)
    def test_identifier_is_temporarily_locked_after_repeated_failures(self):
        self.create_active_user()
        for _ in range(3):
            self.login("CE/2024/001", "wrong")

        response = self.login("CE/2024/001", PASSWORD)

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.data["error"]["code"], "login_locked")
        self.assertGreaterEqual(AuditLog.objects.filter(event=AuditLog.Event.LOGIN_FAILED).count(), 3)

    def test_csrf_is_required_for_login_refresh_and_logout(self):
        self.create_active_user()
        client = APIClient(enforce_csrf_checks=True)
        csrf = client.get("/api/v1/auth/csrf/")
        token = csrf.data["csrf_token"]

        rejected = self.login("CE/2024/001", client=client)
        login = self.login("CE/2024/001", client=client, HTTP_X_CSRFTOKEN=token)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['access']}")
        refresh = client.post("/api/v1/auth/refresh/", HTTP_X_CSRFTOKEN=token)
        logout = client.post("/api/v1/auth/logout/", HTTP_X_CSRFTOKEN=token)

        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(rejected.json()["error"]["code"], "csrf_failed")
        self.assertEqual(login.status_code, 200, login.data)
        self.assertEqual(refresh.status_code, 200, refresh.data)
        self.assertEqual(logout.status_code, 200, logout.data)

    def test_refresh_rotates_and_reuse_revokes_the_session(self):
        user = self.create_active_user()
        login = self.login("CE/2024/001")
        old_refresh = login.cookies[settings.REFRESH_COOKIE_NAME].value

        refreshed = self.client.post("/api/v1/auth/refresh/")
        new_access = refreshed.data["access"]
        new_refresh = refreshed.cookies[settings.REFRESH_COOKIE_NAME].value
        self.assertNotEqual(old_refresh, new_refresh)

        self.client.cookies[settings.REFRESH_COOKIE_NAME] = old_refresh
        replay = self.client.post("/api/v1/auth/refresh/")
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {new_access}")
        rejected_access = self.client.get("/api/v1/auth/me/")

        self.assertEqual(replay.status_code, 401, replay.data)
        self.assertEqual(rejected_access.status_code, 401)
        self.assertFalse(AuthSession.objects.get(user=user).is_active)

    def test_logout_revokes_access_immediately_and_is_audited(self):
        user = self.create_active_user()
        login = self.authenticate("CE/2024/001")

        logout = self.client.post("/api/v1/auth/logout/")
        me = self.client.get("/api/v1/auth/me/")

        self.assertEqual(logout.status_code, 200)
        self.assertEqual(me.status_code, 401)
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.LOGOUT, subject=user).exists())
        self.assertEqual(str(login.data["session_id"]), str(AuthSession.objects.get().id))

    def test_sessions_can_be_listed_and_one_session_revoked(self):
        self.create_active_user()
        first_client = APIClient()
        second_client = APIClient()
        first_login = self.authenticate("CE/2024/001", client=first_client)
        second_login = self.authenticate("CE/2024/001", client=second_client)

        sessions = first_client.get("/api/v1/auth/sessions/")
        revoke = first_client.post(
            f"/api/v1/auth/sessions/{second_login.data['session_id']}/revoke/"
        )
        rejected = second_client.get("/api/v1/auth/me/")

        self.assertEqual(sessions.status_code, 200)
        self.assertEqual(len(sessions.data), 2)
        self.assertEqual(sum(item["current"] for item in sessions.data), 1)
        self.assertEqual(str(first_login.data["session_id"]), str(next(item["id"] for item in sessions.data if item["current"])))
        self.assertEqual(revoke.status_code, 200)
        self.assertEqual(rejected.status_code, 401)

    def test_logout_all_revokes_every_device(self):
        self.create_active_user()
        first_client = APIClient()
        second_client = APIClient()
        self.authenticate("CE/2024/001", client=first_client)
        self.authenticate("CE/2024/001", client=second_client)

        response = first_client.post("/api/v1/auth/logout-all/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(first_client.get("/api/v1/auth/me/").status_code, 401)
        self.assertEqual(second_client.get("/api/v1/auth/me/").status_code, 401)
        self.assertFalse(AuthSession.objects.filter(revoked_at__isnull=True).exists())

    def test_session_records_real_forwarded_ip_and_user_agent(self):
        self.create_active_user()
        response = self.login(
            "CE/2024/001",
            HTTP_X_FORWARDED_FOR="203.0.113.8",
            HTTP_USER_AGENT="NICESA test browser",
        )

        self.assertEqual(response.status_code, 200)
        session = AuthSession.objects.get()
        self.assertEqual(session.ip_address, "203.0.113.8")
        self.assertEqual(session.user_agent, "NICESA test browser")

    def test_login_throttle_cannot_be_bypassed_by_rotating_identifiers(self):
        cache.clear()
        with mock.patch.object(LoginThrottle, "rate", "2/minute", create=True):
            self.login("first@stu.ui.edu.ng", "wrong", REMOTE_ADDR="203.0.113.10")
            self.login("second@stu.ui.edu.ng", "wrong", REMOTE_ADDR="203.0.113.10")
            response = self.login("third@stu.ui.edu.ng", "wrong", REMOTE_ADDR="203.0.113.10")

        self.assertEqual(response.status_code, 429, response.data)

    def test_login_flow_deletes_expired_locked_attempt_rows(self):
        LoginAttempt.objects.create(
            identifier_hash="a" * 64,
            failed_count=5,
            locked_until=timezone.now() - timedelta(seconds=1),
        )

        self.login("unknown@stu.ui.edu.ng", "wrong")

        self.assertFalse(LoginAttempt.objects.filter(identifier_hash="a" * 64).exists())


@override_settings(**TEST_SETTINGS)
class PasswordResetTests(AuthTestMixin, APITestCase):
    def test_request_is_generic_for_known_and_unknown_emails(self):
        self.create_active_user()

        known = self.post_with_commits(
            "/api/v1/auth/password-reset/",
            {"email": "ada.okafor@stu.ui.edu.ng"},
        )
        unknown = self.client.post(
            "/api/v1/auth/password-reset/",
            {"email": "unknown@stu.ui.edu.ng"},
        )

        self.assertEqual(known.status_code, 200)
        self.assertEqual(known.data, unknown.data)
        self.assertEqual(len(mail.outbox), 1)

    def test_reset_is_single_use_changes_password_and_revokes_sessions(self):
        user = self.create_active_user()
        login = self.authenticate("CE/2024/001")
        self.client.credentials()
        self.post_with_commits(
            "/api/v1/auth/password-reset/",
            {"email": "ada.okafor@stu.ui.edu.ng"},
        )
        token = self.extract_email_token()

        reset = self.client.post(
            "/api/v1/auth/password-reset/confirm/",
            {"token": token, "new_password": NEW_PASSWORD},
        )
        replay = self.client.post(
            "/api/v1/auth/password-reset/confirm/",
            {"token": token, "new_password": NEW_PASSWORD},
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {login.data['access']}")
        old_access = self.client.get("/api/v1/auth/me/")
        self.client.credentials()
        old_password = self.login("CE/2024/001", PASSWORD)
        new_password = self.login("CE/2024/001", NEW_PASSWORD)

        self.assertEqual(reset.status_code, 200, reset.data)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(old_access.status_code, 401)
        self.assertEqual(old_password.status_code, 401)
        self.assertEqual(new_password.status_code, 200, new_password.data)
        self.assertTrue(
            AuditLog.objects.filter(event=AuditLog.Event.PASSWORD_RESET_COMPLETED, subject=user).exists()
        )

    def test_expired_reset_token_is_rejected(self):
        self.create_active_user()
        self.post_with_commits(
            "/api/v1/auth/password-reset/",
            {"email": "ada.okafor@stu.ui.edu.ng"},
        )
        token = self.extract_email_token()
        OneTimeToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))

        response = self.client.post(
            "/api/v1/auth/password-reset/confirm/",
            {"token": token, "new_password": NEW_PASSWORD},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("token", response.data["error"]["fields"])

    def test_reset_email_is_deferred_until_commit(self):
        self.create_active_user()
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            response = self.client.post(
                "/api/v1/auth/password-reset/",
                {"email": "ada.okafor@stu.ui.edu.ng"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(len(callbacks), 1)


@override_settings(**TEST_SETTINGS)
class ChangePasswordTests(AuthTestMixin, APITestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_active_user()

    def change_password(self, client=None, **changes):
        payload = {"current_password": PASSWORD, "new_password": NEW_PASSWORD}
        payload.update(changes)
        return (client or self.client).post("/api/v1/auth/change-password/", payload)

    def test_change_password_succeeds_audits_and_emails_after_commit(self):
        self.authenticate(self.user.email)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.change_password()

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(self.user.check_password(NEW_PASSWORD))
        self.assertTrue(
            AuditLog.objects.filter(event=AuditLog.Event.PASSWORD_CHANGED, subject=self.user).exists()
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertNotIn(PASSWORD, mail.outbox[0].body)
        self.assertNotIn(NEW_PASSWORD, mail.outbox[0].body)

    def test_wrong_current_password_is_a_field_error(self):
        self.authenticate(self.user.email)
        response = self.change_password(current_password="wrong")

        self.assertEqual(response.status_code, 400)
        self.assertIn("current_password", response.data["error"]["fields"])

    def test_weak_new_password_is_a_field_error(self):
        self.authenticate(self.user.email)
        response = self.change_password(new_password="weak")

        self.assertEqual(response.status_code, 400)
        self.assertIn("new_password", response.data["error"]["fields"])

    def test_new_password_must_differ_from_current_password(self):
        self.authenticate(self.user.email)
        response = self.change_password(new_password=PASSWORD)

        self.assertEqual(response.status_code, 400)
        self.assertIn("new_password", response.data["error"]["fields"])

    def test_change_password_requires_authentication(self):
        response = self.change_password()

        self.assertEqual(response.status_code, 401)

    def test_change_password_revokes_other_sessions_but_keeps_current_session(self):
        current_client = APIClient()
        other_client = APIClient()
        current_login = self.authenticate(self.user.email, client=current_client)
        other_login = self.authenticate(self.user.email, client=other_client)

        response = self.change_password(client=current_client)
        current_me = current_client.get("/api/v1/auth/me/")
        other_me = other_client.get("/api/v1/auth/me/")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(current_me.status_code, 200)
        self.assertEqual(other_me.status_code, 401)
        self.assertTrue(AuthSession.objects.get(pk=current_login.data["session_id"]).is_active)
        self.assertFalse(AuthSession.objects.get(pk=other_login.data["session_id"]).is_active)

    def test_change_password_is_throttled_per_user(self):
        self.authenticate(self.user.email)
        cache.clear()
        with mock.patch.object(ChangePasswordThrottle, "rate", "2/hour", create=True):
            self.change_password(current_password="wrong-one")
            self.change_password(current_password="wrong-two")
            response = self.change_password(current_password="wrong-three")

        self.assertEqual(response.status_code, 429, response.data)


@override_settings(**TEST_SETTINGS)
class ThrottlingTests(AuthTestMixin, APITestCase):
    def assert_throttled(self, throttle_class, path, payload):
        cache.clear()
        with mock.patch.object(throttle_class, "rate", "2/minute", create=True):
            self.client.post(path, payload)
            self.client.post(path, payload)
            response = self.client.post(path, payload)
        self.assertEqual(response.status_code, 429, response.data)
        self.assertEqual(response.data["error"]["code"], "throttled")

    def test_sensitive_public_endpoints_are_throttled(self):
        cases = (
            (LoginThrottle, "/api/v1/auth/login/", {"identifier": "same@stu.ui.edu.ng", "password": "wrong"}),
            (RegistrationThrottle, "/api/v1/auth/register/", {}),
            (ResendVerificationThrottle, "/api/v1/auth/resend-verification/", {"email": "same@stu.ui.edu.ng"}),
            (PasswordResetThrottle, "/api/v1/auth/password-reset/", {"email": "same@stu.ui.edu.ng"}),
        )
        for throttle_class, path, payload in cases:
            with self.subTest(path=path):
                self.assert_throttled(throttle_class, path, payload)


@override_settings(**TEST_SETTINGS)
class AuthorizationTests(AuthTestMixin, APITestCase):
    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser(email="admin@nicesa.org", password=PASSWORD)
        self.student = self.create_active_user(
            email="student@stu.ui.edu.ng",
            matric="CE/2024/002",
        )
        self.other = self.create_active_user(
            email="other@stu.ui.edu.ng",
            matric="CE/2024/003",
        )

    def promote(self, permissions, target=None):
        target = target or self.student
        return self.client.post(
            f"/api/v1/auth/roles/users/{target.pk}/promote/",
            {"permissions": permissions},
        )

    def test_createsuperuser_produces_an_admin_without_matric_number(self):
        self.assertEqual(self.admin.role, User.Role.ADMIN)
        self.assertTrue(self.admin.is_superuser)
        self.assertIsNone(self.admin.matric_number)

    def test_only_admin_can_list_available_permissions(self):
        self.authenticate(self.student.email)
        denied = self.client.get("/api/v1/auth/roles/permissions/")
        self.client.credentials()
        self.authenticate(self.admin.email)
        allowed = self.client.get("/api/v1/auth/roles/permissions/")

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.data["error"]["code"], "permission_denied")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("view_announcements", {item["codename"] for item in allowed.data})
        self.assertIn("view_audit_log", {item["codename"] for item in allowed.data})

    def test_admin_can_promote_with_exact_permissions_and_audit(self):
        self.authenticate(self.admin.email)

        response = self.promote(["view_students", "manage_events"])

        self.assertEqual(response.status_code, 200, response.data)
        self.student.refresh_from_db()
        self.assertEqual(self.student.role, User.Role.OFFICER)
        self.assertTrue(self.student.has_perm("accounts.view_students"))
        self.assertFalse(self.student.has_perm("accounts.manage_students"))
        self.assertTrue(self.student.has_perm("accounts.manage_events"))
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.ROLE_CHANGED).exists())
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.PERMISSIONS_CHANGED).exists())

    def test_admin_can_replace_permissions_and_demote(self):
        self.authenticate(self.admin.email)
        self.promote(["view_students", "manage_events"])

        edited = self.client.put(
            f"/api/v1/auth/roles/users/{self.student.pk}/permissions/",
            {"permissions": ["view_reports"]},
        )
        demoted = self.client.post(
            f"/api/v1/auth/roles/users/{self.student.pk}/demote/"
        )

        self.assertEqual(edited.status_code, 200, edited.data)
        self.assertEqual(edited.data["permissions"], ["view_reports"])
        self.assertEqual(demoted.status_code, 200, demoted.data)
        self.student.refresh_from_db()
        self.assertEqual(self.student.role, User.Role.STUDENT)
        self.assertFalse(self.student.user_permissions.exists())

    def test_officer_cannot_escalate_or_change_permissions(self):
        self.authenticate(self.admin.email)
        self.promote(["view_students"])
        self.client.credentials()
        self.authenticate(self.student.email)

        response = self.promote(["manage_students"], target=self.other)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["error"]["code"], "permission_denied")
        self.other.refresh_from_db()
        self.assertEqual(self.other.role, User.Role.STUDENT)

    def test_admin_cannot_change_own_role_or_promote_an_admin(self):
        self.authenticate(self.admin.email)
        self_change = self.promote(["view_students"], target=self.admin)
        second_admin = User.objects.create_superuser(email="second@nicesa.org", password=PASSWORD)
        other_admin = self.promote(["view_students"], target=second_admin)

        self.assertEqual(self_change.status_code, 400)
        self.assertEqual(other_admin.status_code, 400)

    def test_unknown_or_duplicate_permissions_are_rejected(self):
        self.authenticate(self.admin.email)
        unknown = self.promote(["become_admin"])
        duplicate = self.promote(["view_students", "view_students"])

        self.assertEqual(unknown.status_code, 400)
        self.assertEqual(duplicate.status_code, 400)
        self.student.refresh_from_db()
        self.assertEqual(self.student.role, User.Role.STUDENT)

    def test_permission_class_reads_current_database_state(self):
        permission = Permission.objects.get(
            content_type__app_label="accounts",
            codename="manage_events",
        )
        self.student.role = User.Role.OFFICER
        self.student.save(update_fields=("role",))
        self.student.user_permissions.add(permission)
        view = APIView()
        view.required_permission = "manage_events"
        checker = HasNicesaPermission()
        factory = APIRequestFactory()

        raw_request = factory.get("/protected/")
        force_authenticate(raw_request, user=User.objects.get(pk=self.student.pk))
        request = view.initialize_request(raw_request)
        self.assertTrue(checker.has_permission(request, view))

        self.student.user_permissions.clear()
        raw_request = factory.get("/protected/")
        force_authenticate(raw_request, user=User.objects.get(pk=self.student.pk))
        request = view.initialize_request(raw_request)
        self.assertFalse(checker.has_permission(request, view))


@override_settings(**TEST_SETTINGS)
class UserModelAndAdminTests(AuthTestMixin, APITestCase):
    def test_admin_role_requires_superuser_in_model_validation_and_database(self):
        invalid = User(
            email="invalid-admin@nicesa.org",
            role=User.Role.ADMIN,
            is_superuser=False,
        )
        with self.assertRaises(DjangoValidationError):
            invalid.full_clean()

        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create(
                email="invalid-db-admin@nicesa.org",
                role=User.Role.ADMIN,
                is_superuser=False,
            )

    def test_custom_admin_add_form_uses_email_and_custom_profile_fields(self):
        form = NicesaUserCreationForm(
            data={
                "email": "created-in-admin@stu.ui.edu.ng",
                "password1": PASSWORD,
                "password2": PASSWORD,
                "first_name": "Admin",
                "last_name": "Created",
                "matric_number": "CE/2024/050",
                "level": 200,
                "is_active": True,
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()
        self.assertEqual(user.email, "created-in-admin@stu.ui.edu.ng")
        self.assertEqual(user.matric_number, "CE/2024/050")

    def test_admin_deactivation_revokes_all_api_sessions(self):
        user = self.create_active_user()
        issue_session_tokens(user)
        issue_session_tokens(user)
        user.is_active = False
        model_admin = NicesaUserAdmin(User, admin.site)

        model_admin.save_model(RequestFactory().post("/admin/"), user, mock.Mock(), True)

        self.assertFalse(AuthSession.objects.filter(user=user, revoked_at__isnull=True).exists())

    def test_admin_password_change_revokes_all_api_sessions(self):
        user = self.create_active_user()
        issue_session_tokens(user)
        form = NicesaAdminPasswordChangeForm(
            user,
            data={"password1": NEW_PASSWORD, "password2": NEW_PASSWORD},
        )

        self.assertTrue(form.is_valid(), form.errors)
        form.save()

        self.assertFalse(AuthSession.objects.filter(user=user, revoked_at__isnull=True).exists())


class ProductionSettingsTests(SimpleTestCase):
    required = (
        "DJANGO_SECRET_KEY",
        "DATABASE_URL",
        "DJANGO_ALLOWED_HOSTS",
        "FRONTEND_VERIFY_URL",
        "FRONTEND_PASSWORD_RESET_URL",
    )

    def production_env(self):
        env = os.environ.copy()
        env.update(
            {
                "DJANGO_ENV": "production",
                "DJANGO_SECRET_KEY": "p" * 40,
                "DATABASE_URL": "sqlite:///:memory:",
                "DJANGO_ALLOWED_HOSTS": "api.example.com",
                "FRONTEND_VERIFY_URL": "https://example.com/verify-email",
                "FRONTEND_PASSWORD_RESET_URL": "https://example.com/reset-password",
                "DJANGO_DEBUG": "",
                "CORS_ALLOWED_ORIGINS": "",
                "CSRF_TRUSTED_ORIGINS": "",
            }
        )
        return env

    def import_settings(self, env):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import config.settings as settings; "
                    "print(settings.DEBUG, settings.CORS_ALLOWED_ORIGINS, settings.CSRF_TRUSTED_ORIGINS)"
                ),
            ],
            cwd=settings.BASE_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_production_requires_each_fail_closed_setting(self):
        for name in self.required:
            with self.subTest(name=name):
                env = self.production_env()
                env[name] = ""
                result = self.import_settings(env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(name, result.stderr)

    def test_production_requires_a_32_character_secret(self):
        env = self.production_env()
        env["DJANGO_SECRET_KEY"] = "too-short"

        result = self.import_settings(env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("at least 32 characters", result.stderr)

    def test_production_debug_defaults_to_false(self):
        result = self.import_settings(self.production_env())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "False [] []")


# ---------------------------------------------------------------------------
# Password policy tests
# ---------------------------------------------------------------------------

def _err_text(e):
    """Extract the message string from either a plain string or a DRF error dict."""
    return e["message"] if isinstance(e, dict) else e

class PasswordCompositionValidatorUnitTests(APITestCase):
    """Unit-tests for each composition rule in isolation."""

    def _errors(self, password):
        """Return the list of error messages raised by the validator."""
        v = PasswordCompositionValidator()
        from django.core.exceptions import ValidationError as DjVE
        try:
            v.validate(password)
            return []
        except DjVE as exc:
            return list(exc.messages)

    def test_valid_password_passes(self):
        self.assertEqual(self._errors("A-Strong-Student-Passphrase-204!"), [])

    def test_too_short_fails(self):
        # 7 chars, otherwise valid
        errors = self._errors("Abc1!xY")
        self.assertTrue(any("at least 8" in e for e in errors), errors)

    def test_minimum_length_8_passes(self):
        # Exactly 8 chars satisfying all rules — must pass.
        self.assertEqual(self._errors("Abc1!xYz"), [])

    def test_too_long_fails(self):
        # 129 chars
        pw = "Aa1!" + "x" * 125
        errors = self._errors(pw)
        self.assertTrue(any("128" in e for e in errors), errors)

    def test_missing_uppercase_fails(self):
        errors = self._errors("abcde1!xyz")
        self.assertTrue(any("uppercase" in e for e in errors), errors)

    def test_missing_lowercase_fails(self):
        errors = self._errors("ABCDE1!XYZ")
        self.assertTrue(any("lowercase" in e for e in errors), errors)

    def test_missing_digit_fails(self):
        errors = self._errors("Abcde!xyzW")
        self.assertTrue(any("digit" in e for e in errors), errors)

    def test_missing_special_character_fails(self):
        errors = self._errors("Abcde1xyzW")
        self.assertTrue(any("special" in e for e in errors), errors)

    def test_all_rules_reported_at_once(self):
        # A single-character all-lowercase password violates 5 rules.
        errors = self._errors("a")
        self.assertGreaterEqual(len(errors), 4, errors)

    def test_password_is_not_trimmed_before_validation(self):
        # Leading space should count towards length and special-char rule.
        # " Abcde1xyzW" has a space (special) and is 11 chars — should pass.
        self.assertEqual(self._errors(" Abcde1xyzW"), [])


@override_settings(**TEST_SETTINGS)
class PasswordPolicyRegistrationTests(AuthTestMixin, APITestCase):
    """Confirm the composition policy is enforced at the registration endpoint."""

    def _register(self, password):
        return self.client.post(
            "/api/v1/auth/register/",
            self.registration_payload(password=password),
        )

    def test_weak_password_rejected_at_registration(self):
        # 7-char password — too short
        response = self._register("Abc1!xY")
        self.assertEqual(response.status_code, 400)
        self.assertIn("password", response.data["error"]["fields"])

    def test_missing_uppercase_rejected_at_registration(self):
        response = self._register("abcde1!xyz")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["password"]
        self.assertTrue(any("uppercase" in _err_text(e) for e in errors), errors)

    def test_missing_lowercase_rejected_at_registration(self):
        response = self._register("ABCDE1!XYZ")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["password"]
        self.assertTrue(any("lowercase" in _err_text(e) for e in errors), errors)

    def test_missing_digit_rejected_at_registration(self):
        response = self._register("Abcde!xyzW")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["password"]
        self.assertTrue(any("digit" in _err_text(e) for e in errors), errors)

    def test_missing_special_char_rejected_at_registration(self):
        response = self._register("Abcde1xyzW")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["password"]
        self.assertTrue(any("special" in _err_text(e) for e in errors), errors)

    def test_multiple_failures_reported_simultaneously_at_registration(self):
        response = self._register("a")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["password"]
        self.assertGreaterEqual(len(errors), 4, errors)

    def test_strong_password_accepted_at_registration(self):
        response = self._register(PASSWORD)
        self.assertEqual(response.status_code, 201, response.data)


@override_settings(**TEST_SETTINGS)
class PasswordPolicyResetTests(AuthTestMixin, APITestCase):
    """Confirm the composition policy is enforced at password-reset/confirm."""

    def setUp(self):
        super().setUp()
        self.user = self.create_active_user()
        self.post_with_commits(
            "/api/v1/auth/password-reset/",
            {"email": "ada.okafor@stu.ui.edu.ng"},
        )
        self.reset_token = self.extract_email_token()

    def _confirm(self, new_password):
        return self.client.post(
            "/api/v1/auth/password-reset/confirm/",
            {"token": self.reset_token, "new_password": new_password},
        )

    def test_weak_password_rejected_at_reset(self):
        # 7-char password — too short
        response = self._confirm("Abc1!xY")
        self.assertEqual(response.status_code, 400)
        self.assertIn("new_password", response.data["error"]["fields"])

    def test_missing_uppercase_rejected_at_reset(self):
        response = self._confirm("abcde1!xyz")
        self.assertEqual(response.status_code, 400)
        errors = response.data["error"]["fields"]["new_password"]
        self.assertTrue(any("uppercase" in _err_text(e) for e in errors), errors)

    def test_strong_password_accepted_at_reset(self):
        response = self._confirm(NEW_PASSWORD)
        self.assertEqual(response.status_code, 200, response.data)
