from django.contrib import admin

from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("event", "actor", "subject", "ip_address", "created_at")
    list_filter = ("event", "created_at")
    search_fields = ("actor__email", "subject__email")
    readonly_fields = (
        "event", "actor", "subject", "ip_address", "user_agent", "metadata", "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
