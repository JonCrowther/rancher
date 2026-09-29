# `crud_test.go` Summary

Verifies that an admin can create, read, update and delete secrets through Steve on the local cluster, and that Steve returns the expected id and links for them.

## `TestLinks`
Creates a secret with one data key in a namespace through Steve, then reads it back by ID.
- Checks the id is `<namespace>/<name>`.
- Checks the `self`, `update`, `patch` and `remove` links point to `/v1/secrets/<namespace>/<name>`, and the `view` link to `/api/v1/namespaces/<namespace>/secrets/<name>`.

## `TestCRUD`
Creates a secret with data key `foo`, reads it, replaces its data with key `lorem`, reads it again, deletes it and reads it once more. It does this through both the global `/v1/secrets` endpoint (namespace given in the object) and the namespaced `/v1/secrets/<namespace>` endpoint.
- Checks the first read returns key `foo`.
- Checks the read after the update returns `lorem` and no longer `foo`.
- Checks the read after the delete returns 404.
