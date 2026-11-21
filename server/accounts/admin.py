from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import (
    NicesaAdminPasswordChangeForm,
    NicesaUserChangeForm,
    NicesaUserCreationForm,
)
from .models import AuthSession, LoginAttempt, OneTimeToken, User
from .services import revoke_all_sessions


@admin.register(User)
class NicesaUserAdmin(UserAdmin):
    add_form = NicesaUserCreationForm
    form = NicesaUserChangeForm
    change_password_form = NicesaAdminPasswordChangeForm
    ordering = ("email",)
    list_display = ("email", "matric_number", "role", "is_active", "is_staff")
    list_filter = ("role", "is_active", "is_staff", "level")
    search_fields = ("email", "matric_number", "first_name", "last_name")
    readonly_fields = ("role", "is_staff", "is_superuser", "groups", "user_permissions")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal information", {"fields": ("first_name", "last_name", "matric_number", "level")}),
        ("Access", {"fields": ("role", "is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "first_name",
                    "last_name",
                    "matric_number",
                    "level",
                    "is_active",
                ),
            },
        ),
    )

    def save_model(self, request, obj, form, change):
        was_active = None
        if change:
            was_active = User.objects.only("is_active").get(pk=obj.pk).is_active
        super().save_model(request, obj, form, change)
        if was_active and not obj.is_active:
            revoke_all_sessions(obj, "admin_deactivated")


@admin.register(AuthSession)
class AuthSessionAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "ip_address", "created_at", "last_active_at", "revoked_at")
    list_filter = ("revoked_at", "created_at")
    search_fields = ("user__email", "user__matric_number")
    readonly_fields = [field.name for field in AuthSession._meta.fields]


@admin.register(OneTimeToken)
class OneTimeTokenAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "purpose",
        "created_at",
        "expires_at",
        "code_expires_at",
        "code_failed_attempts",
        "used_at",
    )
    list_filter = ("purpose", "created_at", "used_at")
    exclude = ("digest", "code_digest")
    readonly_fields = (
        "user",
        "purpose",
        "created_at",
        "expires_at",
        "code_expires_at",
        "code_failed_attempts",
        "used_at",
    )
    search_fields = ("user__email",)

    def has_add_permission(self, request):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("identifier_hash", "failed_count", "locked_until", "updated_at")
    readonly_fields = ("identifier_hash", "failed_count", "locked_until", "updated_at")

    def has_add_permission(self, request):
        return False
