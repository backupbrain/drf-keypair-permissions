# from django.http import HttpResponse
from django.utils.translation import ugettext as _
from rest_framework.exceptions import AuthenticationFailed


class MissingHttpHeaderException(Exception):
    """Missing HTTP Header."""

    def __init__(self, header):
        """Initialize."""
        default_message = _('HTTP header required: "{}"'.format(header))
        super().__init__(default_message)


class InvalidAuthorizationTypeFormatException(Exception):
    """Invalid Authorization Type in Authorization header."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Invalid authorization format')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class InvalidAuthorizationTypeException(Exception):
    """Invalid Authorization in Authorization header. Should be "Signature"."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Invalid authorization type')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class InvalidAuthorizationKeyParameterException(Exception):
    """Invalid Authorization Key Parameter in Authorization header."""

    def __init__(self, header):
        """Initialize."""
        default_message = _('Invalid authorization key: "{}"'.format(header))
        super().__init__(default_message)


class MissingKeyIdParameterException(Exception):
    """Missing the 'keyId='' parameter in Authorization header."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Could not find a "keyId" parameter')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class MissingAlgorithmParameterException(Exception):
    """Missing the 'algorithm='' parameter in Authorization header."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Missing algorithm')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class UnsupportedAlgorithmException(Exception):
    """Unsupported algorithm parameter in Authorization header."""

    def __init__(self, algorithm):
        """Initialize."""
        default_message = _('Unsupported algorithm "{}"'.format(algorithm))
        super().__init__(default_message)


class MissingSignatureParameterException(Exception):
    """Missing the 'signature='' parameter in Authorization header."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Missing signature')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class DuplicateHeaderParameterException(Exception):
    """Duplicate the 'header='' parameter in Authorization header."""

    def __init__(self, header):
        """Initialize."""
        default_message = _('Duplicate authorization header "{}"'.format(header))
        super().__init__(default_message)


class MissingCavageHeaderParameterException(Exception):
    """Requested an unknown Parameter Header."""

    def __init__(self, header):
        """Initialize."""
        default_message = _('Missing cavage header parameter: "{}"'.format(header))
        super().__init__(default_message)


class EmptyCavageHeaderParameterException(Exception):
    """Requested an unknown Parameter Header."""

    def __init__(self, header):
        """Initialize."""
        default_message = _('Header parameter must not be empty')
        super().__init__(default_message)


class SignatureVerificationFailedException(AuthenticationFailed):
    """Could not verify signature."""


class NoMatchingKeysFoundException(Exception):
    """Could not verify signature."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('No matching keys found')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class InvalidPublicKeyFormat(Exception):
    """Could not verify signature."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Invalid public key format')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class DigestVerificationFailedException(Exception):
    """Could not verify the digest."""

    def __init__(self, *args, **kwargs):
        """Initialize."""
        default_message = _('Digest could not be verified')
        if not (args or kwargs):
            args = (default_message, )
        super().__init__(*args, **kwargs)


class HttpResponseUnauthorized(AuthenticationFailed):
    """HTTP 401 Unauthorized Response."""
