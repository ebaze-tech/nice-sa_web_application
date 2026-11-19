from django.contrib.auth.base_user import BaseUserManager

from .utils import normalize_email, normalize_matric_number


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        email = normalize_email(email)
        if not email:
            raise ValueError("An email address is required.")
        extra_fields["matric_number"] = normalize_matric_number(extra_fields.get("matric_number"))
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.full_clean(exclude={"password"})
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", self.model.Role.ADMIN)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superusers must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superusers must have is_superuser=True.")
        if extra_fields.get("role") != self.model.Role.ADMIN:
            raise ValueError("Superusers must have the admin role.")
        return self.create_user(email, password, **extra_fields)
