from .crypto import HttpCavageAuthorizationVerifier, DigestHeaderVerifier


class HttpDigestRequiredMixin:
    """Force a Digest: header."""

    # should be like SHA-256=2ajR8Q+lBNm0eQW9DWWX8dZDZLB8+h0Rgmu0UCDdFrw=

    DIGEST_HEADER = 'Digest'
    CONTENT_TYPE_HEADER = 'Content-Type'
    REQUIRED_HEADERS = [
        DIGEST_HEADER,
        CONTENT_TYPE_HEADER
    ]

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        digest_verifier = DigestHeaderVerifier(request)
        digest_verifier.is_valid(raise_exceptions=True)
        request.digest_verifier = digest_verifier
        return super().dispatch(request, *args, **kwargs)


class HttpCrypoAuthorizationRequiredMixin:
    """Create a Cavage HTTP Authorization Mixin."""

    # should be Signature keyId=<key-id>,algorithm="rsa-sha256",headers="(request-target) date digest",signature=<signature-string>

    def dispatch(self, request, *args, **kwargs):
        """Dispatch the object."""
        authorization_verifier = HttpCavageAuthorizationVerifier(request, args, kwargs)
        authorization_verifier.is_valid(raise_exceptions=True)
        request.authorization_verifier = authorization_verifier
        request.public_key = None
        if hasattr(authorization_verifier, 'public_key'):
            request.public_key = authorization_verifier.public_key
        return super().dispatch(request, *args, **kwargs)
