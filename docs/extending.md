# Additional Functionality

In addition to permissions may want to use `drf-keypair-permissions` for features such as:

* [Throttling](https://www.django-rest-framework.org/api-guide/throttling/)
* Identifying per-user usage patterns
* Something else

The good news is you can extend the features of `drf-keypair-permissions` such as building relationships to `PublicKeys` and retrieving information about the `PublicKey` used to submit a request.


## Relationships

You can attach another object using a `ForeignKey` or `OneToOneField`

```python
from keypair_permissions.models import PublicKey

class ApiThrottleInformation(models.Model): 
    public_key = models.OneToOneField(
        PublicKey,
        on_delete=models.CASCADE,
        primary_key=True,
    )
    last_used = models.DateTimeField(auto_now=True)
```

## Retrieving Authorization Information

You can retrieve information such as the `PublicKey` and other information that gets attached to the `request` object after the permission has verified.

* `HasHttpCrypoAuthorization` attaches a `.authorization_verifier` to the `request` object
* `authorization_verifier` has contains a `.public_key`

```python
from keypair_permissions.permissions import HasHttpCrypoAuthorization

class AuthTestApiView(GenericAPIView):

    permissions_classes = [HasHttpCrypoAuthorization]

    def post(self, request):
        authorization_verifier = request.authorization_verifier
        public_key = authorization_verifier.public_key
        verification_string = authorization_verifier.verification_string

        print(public_key.signing_algorithm)  # 'RSA'
        print(public_key.user.id)  # '1'
        print(verification_string) # '(created): 1402170695'
        return response(request.body)
```
