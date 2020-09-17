
# Testing

These tests are designed to be run from the console.

They represent two algorithms and three tests of each algorithm.

## Algorithms
The algorithms are:

1. `hs2019`
	* SHA256 hashing algorithm
	* ECDSA-P256 signing algorithm
	* Recommended security settings by IETC.
2. `rsa-sha256` (considered deprecated)
	* SHA256 hashing algorithm
	* RSA signing algorithm
	* Documented by IETC recommendation but advised against mainstream use due to vulnerabilities

## Tests
The tests are:

1. Default
	* No explicit headers defined in signature
	* Defaults to the HTTP `Date` header
2. Basic
	*  `(request-target)` url endpoint and querystring is required
	* `Host` and `Date` HTTP headers are required
3. All Headers:
	* `(request-target)` url endpoint and querystring is required
	* internal `(created)` and `(expires)` timestamp keys are required
	* `Host`, `Date`, `Content-Type`, `Digest`, and `Content-Length` HTTP headers are required

## Setting up

### Start Django Project
You will need to run a Django project with `drf-keypair-permissions` running on an echo server at the URL endpoint `/foo` _(without a trailing slash)_.

More information about setup is available at [drf-keypair-permissions.readthedocs.io/](https://drf-keypair-permissions.readthedocs.io/)

### Save Public Keys

You will then go to the [admin](http://127.0.0.1:8000/admin/keypair_permissions/publickey/) need to import two `PublicKeys` and save the resulting `.public_key_id` into the appropriate `<algorithm>_public_key_id` in `keys.py`

#### HS2019
The `hs2019` public key has these settings:
**Public key:**
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG65UDNLeeH2M0FJMq5sS66Zgbfo5HmeiYvSF0rvx+fLoAoGCCqGSM49
AwEHoUQDQgAE+YwQJ7xak48kmy4IhOLo3krj998lCeN95dCTA72TWaHQtwMraLPO
Kc2Z9V6olwQNiezfiSNq83Ln7EL3AOpp9g==
-----END EC PRIVATE KEY-----
```
Hashing algorithm: `SHA512`
Signing algorithm: `EDSA-P256`

Record the resulting `PublicKey.public_key_id` as `p256_public_key_id` in `keys.py`

#### RSA-SHA256
The `hs2019` public key has these settings:
**Public key:**
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----
```
Hashing algorithm: `SHA256`
Signing algorithm: `RSA`

Record the resulting `PublicKey.public_key_id` as `rsa_public_key_id` in `keys.py`

## Running
To run, choose a test and run. Tests include:
* `hs2019_default.py`: Tests default settings for `hs2019`
* `hs2019_basic.py`: Tests basic settings for `hs2019`
* `hs2019_all_headers.py`: Tests all headers for `hs2019`
* `rsa_default.py`: Tests default settings for `rsa-sha256`
* `rsa_basic.py`: Tests basic settings for `rsa-sha256`
* `rsa_all_headers.py`: Tests all headers for `rsa-sha256`

Run a script:
```
$ ./hs2019_all_headers.py
```
The first output will be the signing string. This string is hashed and signed to create the Authorization `signature` and later is rebuilt on the server and hashed to verify the `signature`.
```
(request-target): post /foo?param=value&pet=dog
(created): 1402170695
(expires): 1402170699
host: application/json
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json; encoding=utf-8 
digest: SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=  content-length: 18
```
The second output is the resulting `Authorization` header which includes the `keyId`, `algorithm`, required `headers`, and the `signature`.

The server will look up a `PublicKey` from the `keyId` on its end, build and hash the signing string from the required `headers` and the algorithms described in the `PublicKey`, and verify the `signature`.

```
Signature algorithm="hs2019",keyId="P256Test",headers="(request-target) (created) (expires) host date content-type digest content-length",signature="MEYCIQDE2WaRqfvu7TvJcGLfrNpPnboin/hGBdWwKr/8WwXJOwIhAKD0uTs5HE5SGKpJLffwy50TfS19F/kiNV51QM3PUBiY",created=1402170695,expires=1402170699
```
The last  output is the HTTP status code, which we expect to be `200`:
```
200
```