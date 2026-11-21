from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .utils import normalize_identifier


class IdentifierBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None, identifier=None, **kwargs):
        value = normalize_identifier(identifier if identifier is not None else username)
        if not value or password is None:
            return None

        UserModel = get_user_model()
        lookup = {"email": value} if "@" in value else {"matric_number": value}
        try:
            user = UserModel._default_manager.get(**lookup)
        except UserModel.DoesNotExist:
            UserModel().set_password(password)
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
