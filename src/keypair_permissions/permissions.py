from rest_framework import permissions
from .crypto import HttpCavageAuthorizationVerifier, DigestHeaderVerifier
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt


class HasHttpCryptoAuthorization(permissions.BasePermission):
    """Require Cavage-12 crypto-signed authorization at the method level."""

    def has_permission(self, request, view):
        """Return True if authorization passes signature verification."""
        authorization_verifier = HttpCavageAuthorizationVerifier(request)
        authorization_verifier.is_valid(raise_exceptions=True)
        request.authorization_verifier = authorization_verifier
        request.public_key = None
        if hasattr(authorization_verifier, 'public_key'):
            request.public_key = authorization_verifier.public_key
        return True


class HttpDigestMatches(permissions.BasePermission):
    """Require Cavage-12 crypto-signed authorization at the method level."""

    def has_permission(self, request, view):
        """Return True if authorization passes signature verification."""
        digest_verifier = DigestHeaderVerifier(request)
        digest_verifier.is_valid(raise_exceptions=True)
        request.digest_verifier = digest_verifier
        return True


class CsrfExemptMixin(object):
    """Create a CSRF Excempt mixin."""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        """Dispatch the object."""
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)
