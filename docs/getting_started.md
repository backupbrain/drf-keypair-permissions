# Getting Started

## Project Setup

Add the app to your 'INSTALLED_APPS'

**settings.py**:
```python
INSTALLED_APPS = [
	...
	'keypair_permissions'
]
```

Run the included migrations:

```
$ ./manage.py makemigrations
$ ./manage.py makemigrations keypair_permissions
$ ./manage.py migrate
```

## Setting Permissions

You can require Cavage-based public key authorization either on individual API endpoints or across your entire site.

### Individual API Endpoints

To require authorization on individual endpoints, include the library in the `views.py` where API endpoints are described:

```python
from keypair_permissions.permissions import HasHttpCryptoAuthorization
```

For each endpoint, set the `permission_class` of that view to include `HasHttpCryptoAuthorization`:

```python
class EchoServerApiView(GenericApiView):
    permission_classes = [HasHttpCryptoAuthorization]
    def get(self, request):
        return Response(request.body)
```


#### Combining Permission Policies

It is possible to combine permission policies, for instance `IsAuthenticated`, so that either Public key authorization or Login Cookie authorization grants access to the View:


```python
class EchoServerApiView(GenericApiView):
    permission_classes = [HasHttpCryptoAuthorization | IsAuthenticated]
    def get(self, request):
        return Response(request.body)
```

Learn more about [Django Rest Framework Permissions](https://www.django-rest-framework.org/api-guide/permissions/)

### Setting the Permission Policy Globally

The default permission policy may be set globally to public key authorization, using the `settings.DEFAULT_PERMISSION_CLASSES` setting. For example:

```python
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'keypair_permissions.permissions.HasHttpCryptoAuthorization',
    ]
}
```
