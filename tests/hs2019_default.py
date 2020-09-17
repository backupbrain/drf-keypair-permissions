#!/usr/bin/env/python3
from keys import p256_private_key_string, p256_public_key_id
from securehttpclient import SecureHttpClient

"""
Test default settings for ECDSA-P256.

If a list of headers is not included,
the date is the only header that is signed by default for hs2019.
The string to sign would be:

-----------------------------------
date: Sun, 05 Jan 2014 21:31:40 GMT
-----------------------------------

Resulting Signature:
Signature algorithm="hs2019",keyId="P256Test",headers="(request-target) host date",signature="MEUCIQCtmaLAdg5gTruZntyRo/Wy5qEEeyoq94leGtms0VSHYwIgJ6qux2OnOeYWZ8MS3IuY0fcL0GdgrlGBSPFx9z2KCWM="
"""

date = 'Sun, 05 Jan 2014 21:31:40 GMT'
url = 'http://127.0.0.1:8002/foo'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.signing_algorithm = 'ECDSA-P256'
client.hashing_algorithm = 'SHA512'
client.data_body = data_body
client.authorization_parameters['keyId'] = p256_public_key_id
client.authorization_parameters['algorithm'] = 'hs2019'
client.private_key_string = p256_private_key_string
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
