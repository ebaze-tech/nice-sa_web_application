from .models import AuditLog


def record_event(event, *, actor=None, subject=None, ip_address=None, user_agent="", metadata=None):
    return AuditLog.objects.create(
        event=event,
        actor=actor,
        subject=subject,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512],
        metadata=metadata or {},
    )
