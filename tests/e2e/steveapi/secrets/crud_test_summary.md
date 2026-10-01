# `crud_test.go` Summary

Verifies that an admin can create, read, update and delete secrets through Steve on the local cluster, and that Steve returns the expected id and links for them.

## `TestLinks`
**Arrange:**
- Creates a secret with one data key (`foo`) in a namespace through Steve.

**Act:** Reads the secret back by ID.

**Assert:**
- Checks the id is `<namespace>/<name>`.
- Checks the `self`, `update`, `patch` and `remove` links point to `/v1/secrets/<namespace>/<name>`, and the `view` link points to `/api/v1/namespaces/<namespace>/secrets/<name>`.

## `TestCRUD`
**Arrange:**
- Runs the same lifecycle twice: once through the global `/v1/secrets` endpoint (namespace given on the object) and once through the namespaced `/v1/secrets/<namespace>` endpoint.

**Act 1:** Creates a secret with data key `foo`.
**Assert 1:**
- Checks a read of the secret returns data key `foo`.

**Act 2:** Updates the secret's data to key `lorem`.
**Assert 2:**
- Checks a read of the secret returns `lorem` and no longer contains `foo`.

**Act 3:** Deletes the secret.
**Assert 3:**
- Checks a read of the secret now returns 404.
