#!/usr/bin/env/python3
from keys import p256_private_key_string, p256_public_key_id
from securehttpclient import SecureHttpClient

"""
Test all possible headers settings for ECDSA-P256.

A strong signature including all of the headers and a digest of
the body of the HTTP request would result in the following signing string:

-----------------------------------
(request-target): post /foo?param=value&pet=dog
(created): 1402170695
(expires): 1402170699
host: application/json
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json; encoding=utf-8
digest: SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18
-----------------------------------

Resulting Signature:
Signature algorithm="hs2019",keyId="P256Test",headers="(request-target) (created) (expires) host date content-type digest content-length",signature="MEYCIQDE2WaRqfvu7TvJcGLfrNpPnboin/hGBdWwKr/8WwXJOwIhAKD0uTs5HE5SGKpJLffwy50TfS19F/kiNV51QM3PUBiY",created=1402170695,expires=1402170699
"""

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
client.authorization_parameters['keyId'] = p256_public_key_id
client.authorization_parameters['algorithm'] = 'hs2019'
client.authorization_parameters['created'] = 1402170695
client.authorization_parameters['expires'] = 1402170699
client.private_key_string = p256_private_key_string
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
