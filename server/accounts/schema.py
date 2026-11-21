from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SessionBoundJWTAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = "accounts.authentication.SessionBoundJWTAuthentication"
    name = "bearerAuth"

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Short-lived access token returned by the login or refresh endpoint.",
        }
