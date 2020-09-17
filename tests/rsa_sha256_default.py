#!/usr/bin/env/python3
from keys import rsa_private_key_string, rsa_public_key_id
from securehttpclient import SecureHttpClient

"""
Test default settings for RSA-SHA256.

If a list of headers is not included,
the date is the only header that is signed by default for hs2019.
The string to sign would be:

-----------------------------------
date: Sun, 05 Jan 2014 21:31:40 GMT
-----------------------------------

Resulting Signature:
Signature algorithm="rsa-sha256",keyId="Test",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM="

"""

date = 'Sun, 05 Jan 2014 21:31:40 GMT'
url = 'http://127.0.0.1:8002/foo'
data_body = '{"hello": "world"}'

client = SecureHttpClient()
client.headers['Date'] = date
client.signing_algorithm = 'RSA'
client.hashing_algorithm = 'SHA256'
client.data_body = data_body
client.authorization_parameters['keyId'] = rsa_public_key_id
client.authorization_parameters['algorithm'] = 'rsa-sha256'
client.private_key_string = rsa_private_key_string
client.set_url(url)

client.build_secure_request()
print(client.signing_string)
print("")
print(client.headers['Authorization'])

print("")
response = client.post()
print(response.status_code)
