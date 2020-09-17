#!/usr/bin/env/python3
from keys import rsa_private_key_string, rsa_public_key_id
from securehttpclient import SecureHttpClient

"""
Test basic recommended settings for ECDSA-P256.

If a list of headers is not included,
the date is the only header that is signed by default for hs2019.
The string to sign would be:

-----------------------------------
(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT
-----------------------------------

Resulting Signature:
Signature algorithm="rsa-sha256",keyId="Test",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",headers="(request-target) host date"
"""

date = 'Sun, 05 Jan 2014 21:31:40 GMT'
host = 'example.com'
required_headers = ['(request-target)', 'host', 'date']

url = 'http://127.0.0.1:8000/foo?param=value&pet=dog'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.headers['Host'] = host
client.signing_algorithm = 'RSA'
client.hashing_algorithm = 'SHA256'
client.data_body = data_body
client.authorization_parameters['keyId'] = rsa_public_key_id
client.authorization_parameters['algorithm'] = 'rsa-sha256'
client.private_key_string = rsa_private_key_string
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
