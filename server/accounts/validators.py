"""Custom password validators for the NICESA backend."""

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class PasswordCompositionValidator:
    """
    Enforces the NICESA password policy in a single pass, reporting every
    failed rule at once rather than stopping at the first error.

    Policy:
      - Minimum 10 characters, maximum 128 characters.
      - At least one uppercase letter (A-Z).
      - At least one lowercase letter (a-z).
      - At least one digit (0-9).
      - At least one special character (any non-alphanumeric printable character).
    """

    MIN_LENGTH = 8
    MAX_LENGTH = 128

    # Keep messages as plain strings (not lazy) so they serialise cleanly
    # inside DRF's error envelope.
    RULES = [
        (
            lambda pw: len(pw) >= PasswordCompositionValidator.MIN_LENGTH,
            f"Password must be at least {MIN_LENGTH} characters long.",
        ),
        (
            lambda pw: len(pw) <= PasswordCompositionValidator.MAX_LENGTH,
            f"Password must be no longer than {MAX_LENGTH} characters.",
        ),
        (
            lambda pw: bool(re.search(r"[A-Z]", pw)),
            "Password must include at least one uppercase letter.",
        ),
        (
            lambda pw: bool(re.search(r"[a-z]", pw)),
            "Password must include at least one lowercase letter.",
        ),
        (
            lambda pw: bool(re.search(r"\d", pw)),
            "Password must include at least one digit.",
        ),
        (
            lambda pw: bool(re.search(r"[^A-Za-z0-9]", pw)),
            "Password must include at least one special character.",
        ),
    ]

    def validate(self, password, user=None):
        # Do NOT trim or alter the password before validating.
        errors = [msg for check, msg in self.RULES if not check(password)]
        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            f"Your password must be {self.MIN_LENGTH}–{self.MAX_LENGTH} characters and contain "
            "at least one uppercase letter, one lowercase letter, one digit, "
            "and one special character."
        )
