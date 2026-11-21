from django.contrib.auth.forms import AdminPasswordChangeForm, UserChangeForm, UserCreationForm
from django.db import transaction

from .models import User
from .services import revoke_all_sessions


class NicesaUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "matric_number",
            "level",
            "is_active",
        )


class NicesaUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = "__all__"


class NicesaAdminPasswordChangeForm(AdminPasswordChangeForm):
    @transaction.atomic
    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit:
            revoke_all_sessions(user, "admin_password_changed")
        return user
