
# Crypto Keypair Authorization for Django Rest Framework

For full documentation visit [drf-keypair-permissions.readthedocs.io](https://drf-keypair-permissions.readthedocs.io/).

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