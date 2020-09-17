# Test Django Project

This project creates an HTTP endpoint at `/foo` _(no trailing slash)_, which acts as an echo server.

This echo server requires a valid [Cavage keypair authorization header](https://tools.ietf.org/html/draft-cavage-http-signatures-12#appendix-E.2) to access.

## Setup

Migrate the database

```
$ ./manage.py makemigrations
$ ./manage.py migrate
```


## Running

Run the server
```
$ ./manage.py runserver
```

Import any keys required for testing in the [PublicKey admin](http://127.0.0.1:8000/admin/keypair_permissions/publickey/)
