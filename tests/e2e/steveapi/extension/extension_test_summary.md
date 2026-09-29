# `extension_test.go` Summary

Verifies that Rancher's extension API server on the local cluster serves discovery and OpenAPI only to authenticated users, authorizes only its OpenAPI endpoints, and supports creating, updating and deleting `ext.cattle.io` resources through Steve.

## `TestExtensionAPIServer`
Runs discovery against `/k8s/clusters/local/ext`, first with the admin token and then with no credentials.
- Checks the admin sees the `ext.cattle.io` API group, a non-nil OpenAPI v2 document and at least one OpenAPI v3 path.
- Checks listing groups, OpenAPI v2 and OpenAPI v3 without credentials are each forbidden.

## `TestExtensionAPIServerAuthorization`
Sends a GET to several paths under the extension API server as the admin.
- Checks `/openapi/v2`, `/openapi/v3` and `/openapi/v3/version` return 200.
- Checks `/metrics`, `/healthz`, `/readyz`, `/livez` and `/version` return 403.

## `TestExtensionAPIServerCreateRequests`
POSTs a kubeconfig for the local cluster (current context `local`, TTL 100) to `/v1/ext.cattle.io.kubeconfig`, and a selfuser to `/v1/ext.cattle.io.selfusers`.
- Checks the kubeconfig create returns 201 with a generated name, clusters `["local"]` and current context `local`.
- Checks the selfuser create returns 201 with the caller's user ID in its status.

## `TestExtensionAPIServerUpdateRequests`
Creates a kubeconfig, then PUTs it back with a new description, then PUTs a kubeconfig named `does-not-exist`.
- Checks updating the existing kubeconfig returns 200 with the new description.
- Checks updating the missing kubeconfig returns 404 with a "not found" message.

## `TestExtensionAPIServerDeleteRequests`
Creates a kubeconfig, deletes it, then deletes a kubeconfig named `does-not-exist`.
- Checks deleting the existing kubeconfig returns 204.
- Checks deleting the missing kubeconfig returns 404 with a "not found" message.
