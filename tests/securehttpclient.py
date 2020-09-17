import requests
import base64
from collections import OrderedDict
from urllib.parse import urlparse

# for RSA-based signing
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pkcs1_15

# For digests
import hashlib

# for FastECDSA-based signing
from fastecdsa import curve, ecdsa
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.encoding.der import DEREncoder


class SecureHttpClient:
    """Simple Authorization Client."""

    headers = {
        'Content-Type': 'application/json',
    }
    encoding = 'utf-8'
    data_body = ''
    method = 'GET'
    url = None

    signing_algorithm = None
    hashing_algorithm = None
    digest_algorithm = None
    private_key_string = None
    url_parts = None

    authorization_parameters = OrderedDict({
        'algorithm': 'hs2019'
    })
    required_authorization_headers = []
    signing_string = None

    def set_url(self, url):
        """Set the url."""
        self.url = url
        self.url_parts = urlparse(url)

    def get(self, url):
        """Retrieve a URL."""
        self.method = 'GET'
        self.build_secure_request()
        return requests.post(
            self.url,
            data=self.data_body.encode(self.encoding),
            headers=self.headers
        )

    def post(self):
        """Retrieve a URL."""
        self.method = 'POST'
        self.build_secure_request()
        return requests.post(
            self.url,
            data=self.data_body.encode(self.encoding),
            headers=self.headers
        )

    def build_secure_request(self):
        """Secure the request."""
        if self.digest_algorithm is not None:
            self.set_digest()
        self.build_authorization_header()

    def build_signing_string(self):
        """Build verification string."""
        request_target = '{} {}'.format(self.method.lower(), self.url_parts.path)
        if len(self.url_parts.query) > 0:
            request_target += '?{}'.format(self.url_parts.query)
        signing_rows = []
        if len(self.required_authorization_headers) > 0:
            for required_header in self.required_authorization_headers:
                if required_header[0] == '(':
                    if required_header == '(request-target)':
                        signing_rows.append(
                            '(request-target): {}'.format(request_target)
                        )
                    else:
                        cleaned_header = required_header[1:-1]
                        signing_rows.append(
                            '{}: {}'.format(
                                required_header, self.authorization_parameters[cleaned_header]
                            )
                        )
                else:
                    cleaned_header = required_header.replace('-', ' ')\
                        .title().replace(' ', '-')
                    signing_rows.append('{}: {}'.format(
                        required_header, self.headers[cleaned_header]
                    ))
        else:
            if 'created' in self.authorization_parameters:
                signing_rows.append(
                    '{}: {}'.format('(created)', self.authorization_parameters['created'])
                )
            elif 'Date' in self.headers:
                signing_rows.append(
                    '{}: {}'.format('date', self.headers['Date'])
                )
            else:
                raise Exception("Date or created required")

        signing_string = '\n'.join(signing_rows)
        self.signing_string = signing_string

    def build_authorization_header(self):
        """Build authorization headers."""
        if len(self.required_authorization_headers) > 0:
            self.authorization_parameters['headers'] = '{}'.format(
                ' '.join([
                    header.lower() for header in self.required_authorization_headers
                ])
            )
        self.build_signing_string()
        signing_bytestring = self.signing_string.encode(self.encoding)
        if self.signing_algorithm == 'RSA':
            signer = RSA.import_key(self.private_key_string)
            if self.hashing_algorithm == 'SHA256':
                hash_obj = SHA256.new(signing_bytestring)
            elif self.hashing_algorithm == 'SHA512':
                hash_obj = SHA512.new(signing_bytestring)
            else:
                raise Exception("Invalid key type")
            signature = pkcs1_15.new(signer).sign(hash_obj)
        else:
            private_key, public_key = PEMEncoder.decode_private_key(self.private_key_string)
            if self.hashing_algorithm == 'SHA256':
                hash_function = hashlib.sha256
            elif self.hashing_algorithm == 'SHA512':
                hash_function = hashlib.sha512
            else:
                raise Exception("Invalid key type")

            if self.signing_algorithm.lower() == 'p256':
                r, s = ecdsa.sign(signing_bytestring, private_key, curve=curve.P256, hashfunc=hash_function)
            else:
                raise Exception("Invalid key type")
            signature = DEREncoder.encode_signature(r, s)
        base64_signature = base64.b64encode(signature).decode(self.encoding)
        self.authorization_parameters['signature'] = '{}'.format(base64_signature)
        authorization_rows = []
        for key, value in self.authorization_parameters.items():
            if isinstance(value, str):
                authorization_rows.append('{}="{}"'.format(key, value))
            elif isinstance(value, int) or isinstance(value, float):
                authorization_rows.append('{}={}'.format(key, value))
            elif isinstance(value, bool):
                if value is True:
                    authorization_rows.append('{}=true')
                else:
                    authorization_rows.append('{}=false')
        authorization_header = 'Signature {}'.format(','.join(authorization_rows))
        self.headers['Authorization'] = authorization_header

    def set_digest(self):
        """Create a hash digest from text."""
        if self.digest_algorithm is None:
            return None
        data_string = self.data_body.encode(self.encoding)
        data_string_hash = ''
        if self.digest_algorithm == 'SHA256':
            data_string_hash = hashlib.sha256(data_string).digest()
        elif self.digest_algorithm == 'SHA512':
            data_string_hash = hashlib.sha512(data_string).digest()
        data_string_b64_hash = base64.b64encode(data_string_hash).decode(self.encoding)
        digest = '{}={}'.format(self.digest_algorithm.upper(), data_string_b64_hash)
        self.headers['Digest'] = digest
