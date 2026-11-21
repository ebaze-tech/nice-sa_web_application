from dataclasses import dataclass


EMAIL_VERIFICATION_CODE_MAX_ATTEMPTS = 5


@dataclass(frozen=True)
class PermissionDefinition:
    codename: str
    name: str
    area: str

    @property
    def qualified_name(self) -> str:
        return f"accounts.{self.codename}"


OFFICER_PERMISSIONS = (
    PermissionDefinition("view_students", "View students", "students"),
    PermissionDefinition("manage_students", "Manage students", "students"),
    PermissionDefinition("view_levies", "View levies", "levies"),
    PermissionDefinition("manage_levies", "Manage levies", "levies"),
    PermissionDefinition("view_payments", "View payments", "payments"),
    PermissionDefinition("manage_payments", "Manage payments", "payments"),
    PermissionDefinition("view_announcements", "View announcements", "announcements"),
    PermissionDefinition("manage_announcements", "Manage announcements", "announcements"),
    PermissionDefinition("view_events", "View events", "events"),
    PermissionDefinition("manage_events", "Manage events", "events"),
    PermissionDefinition("view_reports", "View reports", "reports"),
    PermissionDefinition("export_reports", "Export reports", "reports"),
    PermissionDefinition("view_audit_log", "View audit log", "audit"),
)

OFFICER_PERMISSION_CODENAMES = {item.codename for item in OFFICER_PERMISSIONS}
OFFICER_PERMISSION_NAMES = {item.qualified_name for item in OFFICER_PERMISSIONS}
