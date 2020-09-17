# Working with Keys

Prior to using a public key to verify any signatures, you must register that public key with the server.

A `PublicKey` class is provided with the following fields:

| Field             | Required?                      | Type       | Description                                                        | Example                          |
|-------------------|--------------------------------|------------|--------------------------------------------------------------------|----------------------------------|
| user              | No                             | ForeignKey | User who owns this key                                             |                                  |
| public_key_id     | Yes                            | String     | UUID Generated by the server, required by client for authorization | 6b7d3d9fbf4f4cdfbecb5d7903a7bdb5 |
| public_key        | Yes                            | String     | compact-form text-encoded public key                               | MEYCIQ...jUyDrF                  |
| signing_algorithm | Yes                            | String     | The algorithm used to sign the hashed signing string               | (created) content-length         |
| hashing_algorithm | Yes if signing_algorithm='RSA' | String     | The algorithm used to hash the signing string                      |                                  |
| created_at        | Yes                            | Datetime   | Generated by Django                                                |                                  |
| is_active         | No                             | Number     | Is the PublicKey active                                            | True                             |

The `user` field may be set or not. If it is set, the key will be associated with a User.

## Deactivating keys
PublicKeys can be disabled by switching `is_active` to `False`. Doing so will prevent authorization from that key.

## Managing keys
You can manage keys in the Django admin:
`/admin/keypair_permissions/publickey/`

Here you will find a standard admin interface for adding, removing, and modifying PublicKeys.