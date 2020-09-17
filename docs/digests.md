# Digests

The request body can be signed with a digest, and that digest can be put into the `Digest` HTTP header, for example:

```
HTTP 1.1/POST /
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
... (other HTTP headers)

{"hello":"world"}
```

This digest can be used both to verify that the message body is unaltered and to verify the signature.

The digest must include the hashing algorithm in the hash text in order to be verified, e.g.

```SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=```

or 

```MD5=5d41402abc4b2a76b9719d911017c592```

### Using as a Permission

You can enable the `Digest` header as a requirement for permissions using the `permissions.HttpDigestMatches` class:

```python
from keypair_permissions.permissions import HttpDigestMatches

class AuthTestApiView(GenericAPIView):

	permissions_classes = [HttpDigestMatches]

    def post(self, request):
        return response(request.body)
```

### Using as Mixin

You can use the `Digest` header as a Mixin also, using the `mixins.HttpDigestRequiredMixin` class:

```python
from keypair_permissions.mixins import HttpDigestRequiredMixin


class AuthTestApiView(HttpDigestRequiredMixin, GenericAPIView):

    def post(self, request):
        return response(request.body)

```


### Digest Algorithms

Digest algorithms are used to create a hash of the message body. The resulting hash is tagged with the hashing algorithm name and put in the `Digest` HTTP header.

The following algorithms are tested and working:

* SHA256
* SHA512
