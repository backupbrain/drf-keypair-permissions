from django.db import models
from django.db.models.signals import pre_save
from .exceptions import (
    MissingHttpHeaderException,
    InvalidAuthorizationTypeFormatException,
    InvalidAuthorizationTypeException,
    InvalidAuthorizationKeyParameterException,
    MissingKeyIdParameterException,
    MissingAlgorithmParameterException,
    MissingSignatureParameterException,
    DuplicateHeaderParameterException,
    MissingCavageHeaderParameterException,
    EmptyCavageHeaderParameterException
)
from collections import OrderedDict
import hashlib
from .exceptions import (
    UnsupportedAlgorithmException,
    DigestVerificationFailedException,
)
from django.conf import settings
from django.utils.translation import ugettext as _
import base64
import uuid
import re
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from fastecdsa import curve, ecdsa
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.encoding.der import DEREncoder


class PublicKey(models.Model):
    """Public keys."""

    SIGNING_ALGORITHM_RSA = 'RSA'
    SIGNING_ALGORITHM_ECDSA_P256 = 'EDCA-P256'
    SIGNING_ALGORITHM_ECDSA_P384 = 'EDCA-P384'
    SIGNING_ALGORITHM_ECDSA_P521 = 'EDCA-P521'
    SIGNING_ALGORITHM_ECDSA_CURVE25519 = 'EDCA-CURVE25519'
    SUPPORTED_SIGNING_ALGORITHMS = [
        SIGNING_ALGORITHM_RSA,
        SIGNING_ALGORITHM_ECDSA_P256,
        SIGNING_ALGORITHM_ECDSA_P384,
        SIGNING_ALGORITHM_ECDSA_P521,
        SIGNING_ALGORITHM_ECDSA_CURVE25519,
    ]
    SIGNING_ALGORITHM_CHOICES = [
        (SIGNING_ALGORITHM_RSA, SIGNING_ALGORITHM_RSA),
        (SIGNING_ALGORITHM_ECDSA_P256, SIGNING_ALGORITHM_ECDSA_P256),
        (SIGNING_ALGORITHM_ECDSA_P384, SIGNING_ALGORITHM_ECDSA_P384),
        (SIGNING_ALGORITHM_ECDSA_P521, SIGNING_ALGORITHM_ECDSA_P521),
        (SIGNING_ALGORITHM_ECDSA_CURVE25519, SIGNING_ALGORITHM_ECDSA_CURVE25519),
    ]

    ECDSA_ALGORITHMS = [
        SIGNING_ALGORITHM_ECDSA_P256,
        SIGNING_ALGORITHM_ECDSA_P384,
        SIGNING_ALGORITHM_ECDSA_P521,
        SIGNING_ALGORITHM_ECDSA_CURVE25519,
    ]

    HASHING_ALGORITHM_SHA256 = 'SHA256'
    HASHING_ALGORITHM_SHA512 = 'SHA512'
    SUPPORTED_HASHING_ALGORITHMS = [
        HASHING_ALGORITHM_SHA256,
        HASHING_ALGORITHM_SHA512,
    ]
    HASHING_ALGORITHM_CHOICES = [
        (HASHING_ALGORITHM_SHA256, HASHING_ALGORITHM_SHA256),
        (HASHING_ALGORITHM_SHA512, HASHING_ALGORITHM_SHA512),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    public_key_id = models.CharField(max_length=32, null=True, blank=True)
    public_key = models.TextField(max_length=500)
    hashing_algorithm = models.CharField(max_length=32, choices=HASHING_ALGORITHM_CHOICES)
    signing_algorithm = models.CharField(max_length=32, choices=SIGNING_ALGORITHM_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        """Represent as string."""
        return str(self.public_key_id)

    def get_key_id(self):
        """Create a unique identifier for the public key."""
        return uuid.uuid4().hex

    @staticmethod
    def deflate(public_key_string):
        """Compress a public key."""
        return re.sub(r'-----(BEGIN|END) ([^ ]*) ?PUBLIC KEY-----', '', public_key_string).replace('\n', '').replace('\r', '')

    @staticmethod
    def inflate(public_key_string):
        """Add fluff to a public key if required."""
        block_length = 64
        if public_key_string.find('-----BEGIN PUBLIC KEY-----\n') != 0:
            public_key_string = '-----BEGIN PUBLIC KEY-----\n' + \
                '\n'.join(public_key_string[i:i + block_length] for i in range(0, len(public_key_string), block_length)) + \
                '\n-----END PUBLIC KEY-----'
        return public_key_string

    @property
    def deflated_public_key(self):
        """Return deflated public key."""
        return PublicKey.deflate(self.public_key)

    @property
    def inflated_public_key(self):
        """Return deflated public key."""
        return PublicKey.inflate(self.public_key)

    def validate_signature(self, verification_string, signature, charset):
        """Return True if signature is validated."""
        if self.signing_algorithm in self.ECDSA_ALGORITHMS:
            return self.__validate_fastecdsa_signature(verification_string, signature, charset)
        else:
            return self.__validate_crypto_signature(verification_string, signature, charset)

    def __validate_fastecdsa_signature(self, verification_string, signature, charset):
        """Return True if signature is valid, using FastEDSA algorithms."""
        ecdsa_public_key = PEMEncoder.decode_public_key(self.inflated_public_key)
        # signature_length = len(signature)
        r, s = DEREncoder.decode_signature(signature)
        # r_bytes, s_bytes = signature[:signature_length // 2], signature[signature_length // 2:signature_length]
        # r, s = int.from_bytes(r_bytes, 'big', signed=False), int.from_bytes(s_bytes, 'big', signed=False)
        signing_algorithm = self.signing_algorithm.upper()
        if ('SHA-' in signing_algorithm):
            signing_algorithm = signing_algorithm.replace('SHA-', 'SHA')
        if ('P-' in signing_algorithm):
            signing_algorithm = signing_algorithm.replace('P-', 'P')
        if signing_algorithm == self.SIGNING_ALGORITHM_ECDSA_P256:
            curve_algorithm = curve.P256
        elif signing_algorithm == self.SIGNING_ALGORITHM_ECDSA_P384:
            curve_algorithm = curve.P384
        elif signing_algorithm == self.SIGNING_ALGORITHM_ECDSA_P521:
            curve_algorithm = curve.P2521
        elif signing_algorithm == self.SIGNING_ALGORITHM_ECDSA_CURVE25519:
            curve_algorithm = curve.W25519
        else:
            raise UnsupportedAlgorithmException(self.signing_algorithm)
        hashing_algorithm = self.hashing_algorithm.upper().replace('-', '')
        if hashing_algorithm == self.HASHING_ALGORITHM_SHA256:
            hash_function = hashlib.sha256
        elif hashing_algorithm == self.HASHING_ALGORITHM_SHA512:
            hash_function = hashlib.sha512
        else:
            raise UnsupportedAlgorithmException(self.hashing_algorithm)

        is_valid = False
        try:
            ecdsa.verify((r, s), signature, ecdsa_public_key, curve=curve_algorithm, hashfunc=hash_function)
            is_valid = True
        except ecdsa.EcdsaError:
            is_valid = False
        return is_valid

    def __validate_crypto_signature(self, verification_string, signature, charset):
        """Return True if signature is valid, using pycryptom algorithms."""
        rsa_public_key = RSA.import_key(self.inflated_public_key)
        signer = PKCS1_v1_5.new(rsa_public_key)

        if self.hashing_algorithm == self.HASHING_ALGORITHM_SHA256:
            digest = SHA256.new()
        elif self.hashing_algorithm == self.HASHING_ALGORITHM_SHA512:
            digest = SHA512.new()
        else:
            raise UnsupportedAlgorithmException(self.hashing_algorithm)

        digest.update(verification_string.encode(charset))
        is_valid = signer.verify(digest, signature)
        return is_valid

    @classmethod
    def pre_save(cls, sender, instance, **kwargs):
        """Sent when post_save signal is sent."""
        if instance is not None:
            instance.public_key = PublicKey.deflate(instance.public_key)
            if instance.public_key_id is None or instance.public_key_id == '':
                instance.public_key_id = instance.get_key_id()
                instance.save()


pre_save.connect(PublicKey.pre_save, sender=PublicKey)


class DigestHeader:
    """Http Digest Header."""

    DIGEST_HEADER = 'Digest'
    CONTENT_TYPE_HEADER = 'Content-Type'
    REQUIRED_HEADERS = [
        DIGEST_HEADER,
    ]

    digest = None
    charset = None
    content_type = None

    def __init__(self, request):
        """Process headers."""
        self.process(request)

    def get_missing_headers(self):
        """Returns the missing headers."""
        for header in self.REQUIRED_HEADERS:
            if header not in self.headers:
                raise MissingHttpHeaderException(_('Require header "{}"'.format(header)))

    def get_content_type_and_charset(self):
        """Get content type and charset. Default to utf-8."""
        try:
            content_type, charset_info = self.headers[self.CONTENT_TYPE_HEADER].split(";")
            content_type = content_type.lower()
        except ValueError:
            content_type = None
            charset_info = 'encoding=utf-8'
        charset_title, charset = charset_info.split("=")
        self.charset = charset.lower()
        self.content_type = content_type

    def verify(self):
        """Verify the digest header."""
        try:
            digest_algorithm, base64_digest = self.headers[self.DIGEST_HEADER].split("=", 1)
            self.digest = base64.urlsafe_b64decode(base64_digest.encode(self.charset))
        except ValueError:
            raise UnsupportedAlgorithmException(digest_algorithm)

        request_body = self.request.body
        digest_algorithm = digest_algorithm.upper().replace('-', '')
        if digest_algorithm == 'SHA512':
            test_digest = hashlib.sha512(request_body).digest()
        elif digest_algorithm == 'SHA384':
            test_digest = hashlib.sha384(request_body).digest()
        elif digest_algorithm == 'SHA256':
            test_digest = hashlib.sha256(request_body).digest()
        elif digest_algorithm == 'SHA1':
            test_digest = hashlib.sha1(request_body).digest()
        elif digest_algorithm == 'MD5':
            test_digest = hashlib.md5(request_body).digest()
        else:
            raise UnsupportedAlgorithmException(digest_algorithm)
        if test_digest != self.digest:
            raise DigestVerificationFailedException()
        return True

    def process(self, request):
        """Process headers."""
        self.request = request
        self.headers = request.headers
        self.get_missing_headers()
        self.get_content_type_and_charset()
        self.verify()


class CavageAuthorizationHeader:
    """Settings extracted from Cavage Authorization header."""

    AUTH_TYPE = 'signature'
    AUTHORIZATION_HEADER = 'Authorization'
    CONTENT_TYPE_HEADER = 'Content-Type'
    DIGEST_HEADER = 'Digest'
    SIGNATURE_CREATED_HEADER = '(created)'
    DATE_HEADER = 'Date'
    REQUIRED_HEADERS = [
        AUTHORIZATION_HEADER,
    ]

    request = None
    headers = []

    content_type = None
    charset = None
    encoding = None
    auth_info = {}
    public_key_id = None
    algorithm = None
    signature = None
    digest = None
    created = None
    expires = None

    def __init__(self, request):
        """Process headers."""
        self.process(request)

    def scrub(self, string):
        """Clean quotes from the front and end of a string."""
        if string[0] == '"' and string[-1] == '"':
            string = string[1:-1]
        return string

    def get_missing_headers(self):
        """Returns the missing headers."""
        for header in self.REQUIRED_HEADERS:
            if header not in self.headers:
                raise MissingHttpHeaderException(header)

    def get_content_type_and_charset(self):
        """Get content type and charset. Default to utf-8."""
        try:
            content_type, charset_info = self.headers[self.CONTENT_TYPE_HEADER].split(";")
            content_type = content_type.lower()
        except ValueError:
            content_type = None
            charset_info = 'encoding=utf-8'
        charset_title, charset = charset_info.split("=")
        self.charset = charset.lower()
        self.content_type = content_type

    def get_digest_header(self):
        """Get the digest header if available."""
        if self.DIGEST_HEADER in self.headers:
            self.digest = self.headers[self.DIGEST_HEADER]

    def has_digest(self):
        """Return True if a digest has been set."""
        return self.digest is not None

    def get_auth_type_and_info(self):
        """Get Authorization info."""
        try:
            auth_type, parameters_string = self.headers[self.AUTHORIZATION_HEADER].split(' ', 1)
            auth_type = auth_type.lower()
        except ValueError:
            raise InvalidAuthorizationTypeFormatException()
        if auth_type != 'signature':
            raise InvalidAuthorizationTypeException()
        self.auth_type = auth_type.lower()
        return auth_type, parameters_string

    def get_request_target(self):
        """Get the request target."""
        request_target = '{} {}'.format(self.request.method, self.request.path)
        querystring = self.request.GET.urlencode()
        if len(querystring) > 0:
            request_target += '?{}'.format(querystring)
        return request_target.lower()

    def parse_signature_parameters(self, parameters_string):
        """Get signature parameters."""
        try:
            auth_info_keypairs = parameters_string.split(',')
        except ValueError:
            raise InvalidAuthorizationKeyParameterException()
        signature_parameters = {}
        for auth_info_keypair in auth_info_keypairs:
            key, value = auth_info_keypair.strip().split("=", 1)
            if value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            signature_parameters[key] = value
        self.signature_parameters = signature_parameters

        # TODO: implement 'header' checks
        # must throw errors in certain conditions
        # https://tools.ietf.org/html/draft-cavage-http-signatures-12

        if 'keyId' not in signature_parameters:
            raise MissingKeyIdParameterException()
        self.public_key_id = self.scrub(signature_parameters['keyId'])

        if 'algorithm' not in signature_parameters:
            raise MissingAlgorithmParameterException()
        self.algorithm = self.scrub(signature_parameters['algorithm'])

        if 'signature' not in signature_parameters:
            raise MissingSignatureParameterException()
        self.signature = self.scrub(signature_parameters['signature'])

        if 'created' in signature_parameters:
            self.created = self.scrub(signature_parameters['created'])
        if 'expires' in signature_parameters:
            self.created = self.scrub(signature_parameters['expires'])

        if 'headers' in signature_parameters:
            # loop through header requirements
            self.get_verification_headers(self.scrub(signature_parameters['headers']))
        else:
            cleaned_created_header = self.SIGNATURE_CREATED_HEADER[1:-1]
            if cleaned_created_header in signature_parameters:
                self.verification_headers = {
                    self.SIGNATURE_CREATED_HEADER: self.signature_parameters[cleaned_created_header]
                }
            elif self.DATE_HEADER in self.headers:
                self.verification_headers = {
                    self.DATE_HEADER: self.headers[self.DATE_HEADER]
                }
            else:
                raise MissingCavageHeaderParameterException(self.SIGNATURE_CREATED_HEADER)

    def get_verification_headers(self, header_string):
        """Process the verification header requirements."""
        required_headers = header_string.strip().split(' ')
        if len(required_headers) == 0:
            raise EmptyCavageHeaderParameterException()
        verification_headers = OrderedDict()
        for required_header_lower in required_headers:
            if required_header_lower in verification_headers:
                raise DuplicateHeaderParameterException(required_header_lower)
            if required_header_lower[0] != '(':
                required_header = required_header_lower.replace('-', ' ').title().replace(' ', '-')
                if required_header not in self.headers:
                    raise MissingHttpHeaderException(required_header)
                else:
                    verification_headers[required_header_lower] = self.headers[required_header]
            else:
                required_header = required_header_lower[1:-1]
                if required_header_lower == '(request-target)':
                    verification_headers[required_header_lower] = self.get_request_target()
                else:
                    if required_header not in self.signature_parameters:
                        raise MissingCavageHeaderParameterException(required_header)
                    else:
                        verification_headers[required_header_lower] = self.signature_parameters[required_header]
        self.verification_headers = verification_headers

    def get_verification_string(self):
        """Merge required headers into verification string."""
        output_rows = []
        for key, value in self.verification_headers.items():
            output_rows.append('{}: {}'.format(key.lower(), value))
        return '\n'.join(output_rows)

    def process(self, request):
        """Process headers."""
        self.request = request
        self.headers = request.headers
        self.get_missing_headers()

        self.get_content_type_and_charset()
        auth_type, parameters_string = self.get_auth_type_and_info()
        self.get_digest_header()
        self.parse_signature_parameters(parameters_string)
