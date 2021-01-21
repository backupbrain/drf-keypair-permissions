
# Crypto Keypair Authorization for Django Rest Framework

[Cavage HTTP Key-Pair Authorization](https://tools.ietf.org/html/draft-cavage-http-signatures-12) functions as an alternative for API tokens, OAuth, or JWT for REST and GraphQL APIs or web applications.

It works by having a web client sign HTTP headers and/or create a hash digest of the HTTP message body. In doing so, it verifies that the web client is the true creator of the message and that the message has not been tampered with during transport.

It can be used for:

* Authentication and resource access restriction
* Access throttling
* Collecting usage statistics
* and much, much more

Just like in traditional API token or OAuth system, a server expects to verify the the client has permission to access a resource such as a URL endpoint. However, with this system the client can also know if the server is the true creator of the HTTP response and that the message has not been tampered with during transport. Therefore this system creates two-way security for web applications.

## How Traditional API Authorization Works

With API tokens, OAuth and JWT, the server creates a token that is given to the client. The client must store the token and send it to the server with each subsequent request that is verified by the server. If the client loses the token, it no longer has access to the resource. If another client else gains access to the token, the other client can access the resource as if they are the owner of the token.

## How Key-Pair Authorization Works

With this HTTP key-pair authorization, the client generates a public key and private key. The private key is stored locally but does not need to be sent across the network. The public key is sent one time to the server, where it is stored and given an ID. This id is shared with the client. From there, only the public key ID is used to communicate about the client's public key.

When the client accesses a resource from a server, it makes a list of HTTP headers which will be used to create a cryptographic signature. This signature is signed using the client's private key and the list of headers is sent as a part of the signature. The server sends this list and the key ID it received when it registered its public key with the server in the Authorization HTTP header. The server then uses these same headers to verify the signature using the stored public key for that client.

Furthermore, the client can create a hash digest of the message body. The server can verify the hash to know that the message has not been altered since it was created. It can incorporate the digest in the signature to further verify that the digest has not been altered and that the creator of both the digest and the HTTP message body is the client.

This system has the added benefit of being able to work the other way around. It ensures that, once a server's public key is registered in a client application, all subsequent HTTP responses originated from the server.

For full documentation visit [drf-keypair-permissions.readthedocs.io](https://drf-keypair-permissions.readthedocs.io/).

### How does Key-Pair Authorization Affect HTTP Requests

A normal HTTP Request might look like this:

```
POST /foo?param=value&pet=dog
Host: example.com
Content-Length: 34
Date: Mon, 11 Jan 2021 20:54:32 GMT
Content-Type: application/json; encoding=utf-8
Accept: application/json

{"hello":"world"}
```

In this example, the HTTP client is POSTING some JSON data to the url `http://example.com/foo?param=value&pet=dog`. The HTTP headers include the date and content type.

In HTTP keypair authorization, a subset of HTTP headers are used to create a message that is signed using a private key on the client.  This signature and other information necessary to verify the signature are then described in the `Authorization` and/or `Signature` headers.

The client must share its public key with authorizing sever prior to using HTTP key-pair authorization. This public key is given an ID by the server, which is shared with the client, and which the client uses as a shorthand to tell the server which public key to use when verifying authorization.

Optionally, a digest of the HTTP message body may be included in the `Digest` header and used to create the signature also, to add an extra layer of security. If so, the algorithm is prepended to the digest with the format `ALGORITHM=DIGEST`.

```
POST /foo?param=value&pet=dog
Host: example.com
Content-Length: 34
Date: Mon, 11 Jan 2021 20:54:32 GMT
Content-Type: application/json; encoding=utf-8
Accept: application/json
Digest: SHA512=U0hBLTUxMj16RllORkk1anErY3FoT3ZIK3JSNzFHNmRZMU85bkNjMk9xczdWK0xCbkpYSWVrdEVwWTg4U0swdStjK29LR2xpaEp3NFFMdjc2d21NUHJlTEZmMms5Zz09
Authorization: algorithm="rsa-sha256",keyId="client-public-key-id",expires=1611235402,headers="(request-path) (expires) host content-length date digest",signature="TiJZTTihhUYAIlOm2PpnvJa/+15WOX2U0iKJ2LXsLecvohhRIWnwFfdHy4ci10mcv/UQgf2+bFf9lfFZUlPPdzckBNfXIqAjafM8XquJiw/t1v+pEGtJpaGASlzuWuL37gp3k8ux3l6zBKKbBVPPASkHVhz37uY1AXeMblfRbFE="

{"hello":"world"}
```

The server may then:

* Use the `keyId` in the `Authorization` header to load a locally stored copy of the client's private key,
* Reproduce the singing message by assembling the header and authorization data from the `headers` key
* Verify the `signature` data using the client's public key, and the signing message, using the `algorithm` described in the `Authorization` header.

## Why this library exists

This JavaScript module was created to give "Cavage" HTTP Signatures capabilities AJAX and REST API requests.

This enables HTTP authorization based on public key/private key encryption as an alternative to session cookies or API tokens.

For more information see [Draft Cavage HTTP Signatures 12](https://tools.ietf.org/html/draft-cavage-http-signatures-12)

Using [Django Rest Framework](https://www.django-rest-framework.org/) on the server? Try the [DRF Keypair authorization header library](https://pypi.org/project/drf-keypair-permissions/).


## Why this library exists

This Django module was created to give "Cavage" HTTP Signatures capabilities to the Django Rest Framework.

This enables HTTP authorization based on public key/private key encryption as an alternative to session cookies or API tokens.

In your Django code, it looks like this:

```python
from keypair_permissions.permissions import HasHttpCryptoAuthorization

class EchoServerApiView(GenericApiView):
    permission_classes = [HasHttpCryptoAuthorization]
    def get(self, request):
        return Response(request.body)

```

Doing so will require an `Authorization` HTTP header that looks like this:

```
HTTP/1.1 POST /foo
Authorization: Signature algorithm="hs2019",keyId="keyname",signature="MEUCIGGB0P3P/iZCzCbX1fj1Q6AbYPJr9dEBYcsuiLoS3q6uAiEAkEjvmWfuN1UDPmYCkBywnI/MwisCuNEmlAxPB3ZBVgc="
... other headers ...
```

This authorization header is created by signing Request headers with a private key on the client. The server then verifies the Request was sent by a known client by verifying the signature using the client's public key.

Additionally, a `Digest` header can be added to ensure the Request body was transported in tact:

```
Digest: SHA512=WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==
```

Each public key can be associated with a Django User, so the User can be accessed from the View:

```python
class EchoServerApiView(GenericApiView):
    permission_classes = [HasHttpCryptoAuthorization]
    def get(self, request):
        user = request.public_key.user
        return Response(request.body)
```

For more information see [Draft Cavage HTTP Signatures 12](https://tools.ietf.org/html/draft-cavage-http-signatures-12)

Using a NodeJS or JavaScript client? Try the [client-http-keypair-authorization-headers](https://github.com/backupbrain/client-http-keypair-authorization-headers/) library.



## Quickstart

Install:

```
$ pip install drf-keypair-permissions
```

Add `keypair_permissions` to your `settings.INSTALLED_APPS`:

`settings.py`:
```python
INSTALLED_APPS = [
	...
	'keypair_permissions',
]
```

Migrate the database

```
$ ./manage.py makemigrations
$ ./manage.py migrate
```

Include to your project

`views.py`:
```python
from keypair_permissions.permissions import HasHttpCryptoAuthorization
```

Set the `permission_classes` of API views to include `HasHttpCryptoAuthorization`:

```python
class EchoServerApiView(GenericApiView):
    permission_classes = [HasHttpCryptoAuthorization]
    def get(self, request):
        return Response(request.body)
```

Or use across your entire API by setting `REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']`:

```python
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'keypair_permissions.permissions.HasHttpCryptoAuthorization',
    ]
}
```

**Note:** To use in a cross-origin (CORS) environment, responses must must have CORS headers enabled.

This can be achieved like this:

Create a `middleware.py` in an app, with this code:

**myapp.middleware.py**
```python
from django import http
class CorsMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        response = self.get_response(request)
        if (request.method == "OPTIONS" and "HTTP_ACCESS_CONTROL_REQUEST_METHOD" in request.META):
            response = http.HttpResponse()
            response["Content-Length"] = "0"
            response["Access-Control-Max-Age"] = 86400
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "DELETE, GET, OPTIONS, PATCH, POST, PUT"
        response["Access-Control-Allow-Headers"] = "accept, accept-encoding, authorization, content-type, dnt, origin, user-agent, x-csrftoken, x-requested-with, authorization, signature, digest, content-length, date, host"
        return response
```

Enable the middleware in the `settings.py`

**settings.py**
```

MIDDLEWARE = [
    'myapp.middleware.CorsMiddleware',
    # ...
]
````