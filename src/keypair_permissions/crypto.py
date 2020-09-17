import base64
from .models import CavageAuthorizationHeader, DigestHeader
from .exceptions import (
    UnsupportedAlgorithmException,
    SignatureVerificationFailedException,
    NoMatchingKeysFoundException,
    HttpResponseUnauthorized,
)
from .models import PublicKey


class DigestHeaderVerifier:
    """Verify a Digest."""

    in_verbose_mode = False
    raise_exceptions = True

    def __init__(self, request, *args, **kwargs):
        """Initialize class."""
        self.say("In verbose mode")
        self.request = request
        self.args = args
        self.kwargs = kwargs

    def handle_error(self, exception):
        """Return False or raise exception."""
        if self.raise_exceptions is True:
            raise exception
        else:
            return False

    def is_valid(self, raise_exceptions=True):
        """Dispatch the object."""
        try:
            self.digest_header = DigestHeader(self.request)
        except Exception as e:
            return self.handle_error(e)

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)


class HttpCavageAuthorizationVerifier:
    """Verify HTTP signatures."""

    in_verbose_mode = False
    raise_exceptions = True
    cavage_authorization_header = None
    charset = None
    public_key = None
    signature = None
    verification_string = None

    CONTENT_TYPE_HEADER = 'Content-Type'

    HEADER_ALGORITHM_HS2019 = 'hs2019'
    HEADER_ALGORITHM_RSA_SHA256 = 'rsa-sha256'
    HEADER_ALGORITHM_RSA_SHA512 = 'rsa-sha512'
    SUPPORTED_HEADER_ALGORITHMS = [
        HEADER_ALGORITHM_HS2019,
        HEADER_ALGORITHM_RSA_SHA256,
        HEADER_ALGORITHM_RSA_SHA512,
    ]

    # hs2019, --rsa-sha1--, --rsa-sha256--, --hmac-sha256--, --ecdsa-sha256--
    # hs2019 with SHA-512 hash
    def __init__(self, request, *args, **kwargs):
        """Initialize class."""
        self.say("In verbose mode")
        self.request = request
        self.args = args
        self.kwargs = kwargs

    def handle_error(self, exception):
        """Return False or raise exception."""
        if self.raise_exceptions is True:
            raise exception
        else:
            return False

    '''
    def get_rsa256_b64_message_digest(self, request_body, charset):
        """Create an RSA256 message digest."""
        expected_digest = hashlib.sha256(request_body).digest()
        expected_base64_digest = base64.b64encode(expected_digest).decode(charset)
        return expected_base64_digest
    '''

    def get_content_type_and_charset(self):
        """Get content type and charset. Default to utf-8."""
        content_type = None
        try:
            content_type, charset_info = self.request.headers[self.CONTENT_TYPE_HEADER].lower().split(";")
        except ValueError:
            message = "Could not read charset info"
            self.say("    " + message)
            charset_info = 'encoding=utf-8'
        charset_title, charset = charset_info.split("=")
        return content_type, charset

    def decode_signature(self, base64_signature, charset):
        """Base64-decode the signature."""
        self.say("    signature: {}".format(base64_signature))
        try:
            signature = base64.b64decode(base64_signature.encode(charset))
        except LookupError:
            self.say("Could not decode base64 signature")
            return self.handle_error(SignatureVerificationFailedException())
        return signature

    def get_public_key_from_id(self, public_key_id):
        """Fetch the public key from the database."""
        try:
            public_key = PublicKey.objects.get(public_key_id=public_key_id, is_active=True)
            return public_key
        except PublicKey.DoesNotExist:
            return self.handle_error(NoMatchingKeysFoundException())

    def is_valid(self, raise_exceptions=True):
        """Dispatch the object."""
        try:
            self.cavage_authorization_header = CavageAuthorizationHeader(self.request)
        except Exception as e:
            return self.handle_error(e)
        algorithm = self.cavage_authorization_header.algorithm.lower()
        if algorithm not in self.SUPPORTED_HEADER_ALGORITHMS:
            raise UnsupportedAlgorithmException(algorithm)

        base64_signature = self.cavage_authorization_header.signature
        public_key_id = self.cavage_authorization_header.public_key_id
        content_type, charset = self.get_content_type_and_charset()

        signature = self.decode_signature(base64_signature, charset)
        public_key = self.get_public_key_from_id(public_key_id)

        verification_string = self.cavage_authorization_header.get_verification_string()

        self.charset = charset
        self.public_key = public_key
        self.signature = signature
        self.verification_string = verification_string

        try:
            does_signature_validate = self.public_key.validate_signature(verification_string, signature, charset)
        except Exception as e:
            return self.handle_error(e)
        if does_signature_validate:
            return True
        else:
            return self.handle_error(SignatureVerificationFailedException())

        # if there is a digest, we need to verify that
        does_digest_match = False
        if self.cavage_authorization_header.has_digest():
            try:
                self.digest_header = DigestHeader(self.request)
                does_digest_match = True
            except Exception as e:
                self.handle_error(e)

        if does_signature_validate and does_digest_match:
            return True
        else:
            return self.handle_error(HttpResponseUnauthorized())

    def say(self, message):
        """Print debugging messages."""
        if self.in_verbose_mode is True:
            print(message)
