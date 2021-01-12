
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
