import re
from datetime import timedelta
from unittest import mock
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth.models import Permission
from django.core import mail
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory, APITestCase, force_authenticate
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken

from audit.models import AuditLog

from .models import AuthSession, OneTimeToken, User
from .permissions import HasNicesaPermission
from .throttles import (
    LoginThrottle,
    PasswordResetThrottle,
    RegistrationThrottle,
    ResendVerificationThrottle,
)


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


@override_settings(**TEST_SETTINGS)
class RegistrationAndVerificationTests(AuthTestMixin, APITestCase):
    def test_student_registration_normalizes_and_requires_verification(self):
        response = self.client.post("/api/v1/auth/register/", self.registration_payload())

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

    def test_verification_is_single_use_and_activates_account(self):
        self.client.post("/api/v1/auth/register/", self.registration_payload())
        token = self.extract_email_token()

        first = self.client.post("/api/v1/auth/verify-email/", {"token": token})
        second = self.client.post("/api/v1/auth/verify-email/", {"token": token})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)
        self.assertTrue(User.objects.get().is_active)
        self.assertTrue(AuditLog.objects.filter(event=AuditLog.Event.EMAIL_VERIFIED).exists())

    def test_expired_verification_token_is_rejected(self):
        self.client.post("/api/v1/auth/register/", self.registration_payload())
        token = self.extract_email_token()
        OneTimeToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))

        response = self.client.post("/api/v1/auth/verify-email/", {"token": token})

        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.get().is_active)

    def test_resend_is_generic_and_invalidates_previous_link(self):
        self.client.post("/api/v1/auth/register/", self.registration_payload())
        old_token = self.extract_email_token()
        known = self.client.post(
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


@override_settings(**TEST_SETTINGS)
class PasswordResetTests(AuthTestMixin, APITestCase):
    def test_request_is_generic_for_known_and_unknown_emails(self):
        self.create_active_user()

        known = self.client.post(
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
        self.client.post(
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
        self.client.post(
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
