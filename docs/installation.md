# Installation

You can install from pip:
```
$ pip install drf-keypair-permissions
```

Or from Github:

```
$ cd <python-project-folder>
$ git clone https://github.com/backupbrain/drf-keypair-permissions
$ ln -s drf-keypair-permissions/src/keypair_permissions keypair_permissions
$ pip install -r drf-keypair-permissions/requirements.txt  # install requirements
```

When installed, `drf-keypair-permissions` adds a "PublicKey" section to the Django Admin where you can create, view, update, and delete public keys.