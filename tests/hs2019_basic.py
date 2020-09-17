#!/usr/bin/env/python3
from keys import p256_private_key_string, p256_public_key_id
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
Signature algorithm="hs2019",keyId="P256Test",signature="MEUCIGGB0P3P/iZCzCbX1fj1Q6AbYPJr9dEBYcsuiLoS3q6uAiEAkEjvmWfuN1UDPmYCkBywnI/MwisCuNEmlAxPB3ZBVgc="
"""

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
client.authorization_parameters['keyId'] = p256_public_key_id
client.authorization_parameters['algorithm'] = 'hs2019'
client.private_key_string = p256_private_key_string
client.required_authorization_headers = required_headers
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
