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

## CORS Policy

Most users will want to install a CORS policy, as a common use-case for keypair authorization is to cross-origin authentication. A CORS policy can be defined using a DRF CORS middleware, or by building a custom middleware.

Make sure to include the `Authorization`, `Signature`, `Date`, `Host`, `Content-Length`, and other headers in the `Access-Control-Allow-Headers` Response header they will be used to build an authorization signature. 

**myapp/middleware.py**
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

Install the CORS middleware in `settings.py`:
```python
# ... other settings
MIDDLEWARE = [
    'myapp.middleware.CorsMiddleware',
    # ... other middleware
]
# ... other settings
```
