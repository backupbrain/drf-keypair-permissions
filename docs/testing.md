# Testing

The Cavage Draft Standard suggests [several tests](https://tools.ietf.org/html/draft-cavage-http-signatures-12#appendix-C), which we can recreate.

## Server

### Setting Up

Install

```
$ pip install drf-keypair-permissions
$ ./manage.py startapp test_app
$ ./manage.py makemigrations
$ ./manage.py migrate
$ ./manage.py createsuperuser
$ ./manage.py runserver
```

Set up routes

`settings.py`:
```python
# ...

ALLOWED_HOSTS = [
	'example.com',
	'127.0.0.1',
]
# ...
INSTALLED_APPS = [
	# ...
	'rest_framework',
	'keypair_permissions',
	'test_app',
]
# ...
```

`test_app/urls.py`:
```python
from django.urls import path
from .views import (
    AuthTestApiView
)

app_name = 'test_app'

urlpatterns = [
    path('foo', AuthTestApiView.as_view()),
]

```

`test_app/views.py`:
```python
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from keypair_permissions.permissions import HasHttpCrypoAuthorization


class AuthTestApiView(GenericAPIView):
    """Test Crypto Auth Mixin."""

    permission_classes = [HasHttpCrypoAuthorization]

    def get(self, request):
        """GET method."""
        return Response(request.body)

    def post(self, request):
        """POST method."""
        return Response(request.data)

```

`urls.py`:
```python
# ...
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('test_app.urls')),
]
# ...
```

### Register public keys

You will have to go to the [admin](http://127.0.0.1/admin/keypair_permissions/publickey/) to register these public keys:

### RSA Public Key
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----
```

Signing Algorithm: `RSA`

Hashing Algorithm: `SHA256`

Set the `public_key_id` to `Test`

### ECDSA-P256 Public Key

```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG65UDNLeeH2M0FJMq5sS66Zgbfo5HmeiYvSF0rvx+fLoAoGCCqGSM49
AwEHoUQDQgAE+YwQJ7xak48kmy4IhOLo3krj998lCeN95dCTA72TWaHQtwMraLPO
Kc2Z9V6olwQNiezfiSNq83Ln7EL3AOpp9g==
-----END EC PRIVATE KEY-----
```

Signing Algorithm: `ECDSA-P256`

Hashing Algorithm: `SHA512`

Set the `public_key_id` to `P256Test`

## Client

### Setting Up

To run the tests, first we must include some libraries

```python
import requests
import base64
import json
from collections import OrderedDict
from urllib.parse import urlparse

# for RSA-based signing
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pkcs1_15

# For digests
import hashlib

# for FastECDSA-based signing
from fastecdsa import curve, ecdsa, keys
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.encoding.der import DEREncoder

```

From here we will build a text-based web browser that knows how to build the Authorization header:

```python
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
```

### Elliptic Key Algorithm Tests

The Cavage draft recommendations using the SHA12 algorithm to hash the signing string and the EDCSA-P256 algorithm to sign it. Combined, this algorithm is referred to as `hs2019`.

The following test data uses the following EDCSA-P256 key, which we will refer to as `keyId=P256Test` in the following samples:

```python

test_private_key = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG65UDNLeeH2M0FJMq5sS66Zgbfo5HmeiYvSF0rvx+fLoAoGCCqGSM49
AwEHoUQDQgAE+YwQJ7xak48kmy4IhOLo3krj998lCeN95dCTA72TWaHQtwMraLPO
Kc2Z9V6olwQNiezfiSNq83Ln7EL3AOpp9g==
-----END EC PRIVATE KEY-----"""
```

#### Default Test

If a list of headers is not included, the date is the only header that is signed by default for hs2019.  The string to sign would be:

`date: Sun, 05 Jan 2014 21:31:40 GMT`

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
url = 'http://127.0.0.1:8002/foo'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.signing_algorithm = 'ECDSA-P256'
client.hashing_algorithm = 'SHA512'
client.data_body = data_body
client.authorization_parameters['keyId'] = 'P256Test'
client.authorization_parameters['algorithm'] = 'hs2019'
client.private_key_string = test_private_key
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

Output:
```
date: Sun, 05 Jan 2014 21:31:40 GMT

Signature algorithm="hs2019",keyId="P256Test",signature="MEUCIGGB0P3P/iZCzCbX1fj1Q6AbYPJr9dEBYcsuiLoS3q6uAiEAkEjvmWfuN1UDPmYCkBywnI/MwisCuNEmlAxPB3ZBVgc="

200
```

#### Basic Test

The minimum recommended data to sign is the (request-target), host, and date.  In this case, the test would look like this:

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
host = 'example.com'
required_headers = ['(request-target)', 'host', 'date']

url = 'http://127.0.0.1:8000/foo?param=value&pet=dog'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.headers['Host'] = host
client.signing_algorithm = 'ECDSA-P256'
client.hashing_algorithm = 'SHA512'
client.data_body = data_body
client.authorization_parameters['keyId'] = 'P256Test'
client.authorization_parameters['algorithm'] = 'hs2019'
client.private_key_string = test_private_key
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

Output:
```
(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT

Signature algorithm="hs2019",keyId="P256Test",headers="(request-target) host date",signature="MEUCIQCtmaLAdg5gTruZntyRo/Wy5qEEeyoq94leGtms0VSHYwIgJ6qux2OnOeYWZ8MS3IuY0fcL0GdgrlGBSPFx9z2KCWM="

200
```

#### All Headers Test

A strong signature including all of the headers and a digest of the body of the HTTP request would look like this:

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
host = 'example.com'
required_headers = [
    '(request-target)',
    '(created)',
    '(expires)',
    'host',
    'date',
    'content-type',
    'digest',
    'content-length'
]

url = 'http://127.0.0.1:8002/foo?param=value&pet=dog'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.data_body = data_body
client.headers['Date'] = date
client.headers['Host'] = host
client.headers['Content-Type'] = 'application/json'
client.headers['Content-Length'] = str(len(client.data_body))
client.signing_algorithm = 'ECDSA-P256'
client.hashing_algorithm = 'SHA512'
client.digest_algorithm = 'SHA256'
client.authorization_parameters['keyId'] = 'P256Test'
client.authorization_parameters['keyId'] = 'P-256-DAQcDQgAE+-None'
client.authorization_parameters['algorithm'] = 'hs2019'
client.authorization_parameters['created'] = 1402170695
client.authorization_parameters['expires'] = 1402170699
client.private_key_string = test_private_key
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Digest'])
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

```
(request-target): post /foo?param=value&pet=dog
(created): 1402170695
(expires): 1402170699
host: application/json
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json; encoding=utf-8
digest: SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18

Signature algorithm="hs2019",keyId="P256Test",headers="(request-target) (created) (expires) host date content-type digest content-length",signature="MEYCIQDE2WaRqfvu7TvJcGLfrNpPnboin/hGBdWwKr/8WwXJOwIhAKD0uTs5HE5SGKpJLffwy50TfS19F/kiNV51QM3PUBiY",created=1402170695,expires=1402170699

200
```

### Recommended Tests from the Cavage Draft Standard

The Cavage draft recommendations comes with several tests and also the following warning:

**WARNING: THESE TEST VECTORS ARE OLD AND POSSIBLY WRONG.  THE NEXT VERSION OF THIS SPECIFICATION WILL CONTAIN THE PROPER TEST VECTORS.**

The following test data uses the following RSA 2048-bit keys, which we will refer to as `keyId=Test` in the following samples:

```python

test_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----"""
```

#### Default Test
If a list of headers is not included, the date is the only header that is signed by default for rsa-sha256.  The string to sign would be:

`date: Sun, 05 Jan 2014 21:31:40 GMT`

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
url = 'http://127.0.0.1:8002/foo'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.signing_algorithm = 'RSA'
client.hashing_algorithm = 'SHA256'
client.data_body = data_body
client.authorization_parameters['keyId'] = 'Test'
client.authorization_parameters['algorithm'] = 'rsa-sha256'
client.private_key_string = test_private_key
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

Output:
```
date: Sun, 05 Jan 2014 21:31:40 GMT

Signature algorithm="rsa-sha256",keyId="Test",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="

200
```

#### Basic Test

The minimum recommended data to sign is the (request-target), host, and date.  We can test this:

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
host = 'example.com'
required_headers = ['(request-target)', 'host', 'date']

url = 'http://127.0.0.1:8000/foo/?param=value&pet=dog'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.headers['Host'] = host
client.signing_algorithm = 'RSA'
client.hashing_algorithm = 'SHA256'
client.data_body = data_body
client.authorization_parameters['keyId'] = 'Test'
client.authorization_parameters['algorithm'] = 'rsa-sha256'
client.private_key_string = test_private_key
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

Output:
```
(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT

Signature algorithm="rsa-sha256",keyId="Test",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",headers="(request-target) host date"

200
```

#### All Headers Test

A strong signature including all of the headers and a digest of the body of the HTTP request would be build like this:

```python
date = 'Sun, 05 Jan 2014 21:31:40 GMT'
host = 'example.com'
required_headers = [
    '(request-target)',
    '(created)',
    '(expires)',
    'host',
    'date',
    'content-type',
    'digest',
    'content-length'
]

url = 'http://127.0.0.1:8000/foo?param=value&pet=dog'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.data_body = data_body
client.headers['Date'] = date
client.headers['Host'] = host
client.headers['Content-Type'] = 'application/json'
client.headers['Content-Length'] = str(len(client.data_body))
client.signing_algorithm = 'RSA'
client.hashing_algorithm = 'SHA256'
client.digest_algorithm = 'SHA256'
client.authorization_parameters['keyId'] = 'Test'
client.authorization_parameters['algorithm'] = 'rsa-sha256'
client.authorization_parameters['created'] = 1402170695
client.authorization_parameters['expires'] = 1402170699
client.private_key_string = test_private_key
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Digest'])
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
```

```
(request-target): post /foo?param=value&pet=dog
(created): 1402170695
(expires): 1402170699
host: application/json
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json; encoding=utf-8
digest: SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18

Signature algorithm="rsa-sha256",keyId="Test",signature="j3Uo3HDtxBAkSJBYuOyVFfaFZQNNFdyPG/tuzP8sUYWcUoT4DcOBp7W01K96g7tksH/+oqKjUAIXuFIkOHtQK96HPyrIi1LF7sKbm5j4Autl/XfA4q76NRQEnNYujLq6lGI8rju2Jau/yLVd0CSbEji3flVqLLvJZp8jCth0LnY=",created=1402170695,expires=1402170699,headers="(request-target) (created) (expires) host date content-type digest content-length"

200
```

