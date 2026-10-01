# `extension_test.go` Summary

Verifies that Rancher's extension API server on the local cluster serves discovery and OpenAPI only to authenticated users, authorizes only its OpenAPI endpoints, and supports creating, updating and deleting `ext.cattle.io` resources through Steve.

## `TestExtensionAPIServer`
**Act:** Queries discovery and the OpenAPI v2/v3 documents against the extension API server, as an authenticated admin and again without credentials.

**Assert:**
- Checks the admin sees the `ext.cattle.io` API group, a non-nil OpenAPI v2 document, and at least one OpenAPI v3 path.
- Checks that listing groups, fetching OpenAPI v2, and fetching OpenAPI v3 without credentials each return a Forbidden error.

## `TestExtensionAPIServerAuthorization`
**Act:** Sends a GET request to several paths under the extension API server as the admin.

**Assert:**
- Checks `/openapi/v2`, `/openapi/v3` and `/openapi/v3/version` return 200.
- Checks `/metrics`, `/healthz`, `/readyz`, `/livez` and `/version` return 403.

## `TestExtensionAPIServerCreateRequests`
**Act:** Creates a kubeconfig and a selfuser through Steve's `ext.cattle.io` endpoints.

**Assert:**
- Checks the kubeconfig create returns 201 with a generated name, clusters `["local"]` and current context `local`.
- Checks the selfuser create returns 201 with the caller's user ID populated in its status.

## `TestExtensionAPIServerUpdateRequests`
**Arrange:**
- Creates a kubeconfig for the local cluster through Steve.

**Act:** Updates the kubeconfig's description via PUT, then PUTs an update for a kubeconfig named `does-not-exist`.

**Assert:**
- Checks updating the existing kubeconfig returns 200 with the new description.
- Checks updating the missing kubeconfig returns 404 with a "not found" message.

## `TestExtensionAPIServerDeleteRequests`
**Arrange:**
- Creates a kubeconfig for the local cluster through Steve.

**Act:** Deletes the kubeconfig, then deletes a kubeconfig named `does-not-exist`.

**Assert:**
- Checks deleting the existing kubeconfig returns 204.
- Checks deleting the missing kubeconfig returns 404 with a "not found" message.
