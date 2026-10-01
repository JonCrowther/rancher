# `projects_test.go` Summary

Verifies project-scoped RBAC: that a project creator is bound as its owner with owner-level access in the project's namespaces, and that read-only project members cannot edit secrets or move namespaces between projects.

## `TestProjectCreatorGetsOwnerBindings`
**Arrange:**
- Creates a user.
- Grants the user "cluster-member" on the local cluster via CRTB.

**Act:** The user creates a project (retrying until RBAC permits it) and a namespace within it.

**Assert:**
- Checks the project becomes active and the namespace is created once RBAC propagates.
- Checks the user can list pods in the namespace.
- Checks the user has a `project-owner` (or `project-owner-aggregator`) RoleBinding in the namespace.
- Checks the user can create deployments (extensions group) in the namespace.
- Checks the user can list `pods.metrics.k8s.io` in the namespace.

## `TestReadOnlyCannotEditSecret`
**Arrange:**
- Creates a user and binds them to "read-only" on the suite's shared project (local cluster) via PRTB.
- Creates a namespace in the project.
- Admin creates a secret in the namespace (for the update check).

**Act:** The read-only user attempts to create a new secret in the namespace and attempts to update the admin-created secret.

**Assert:**
- Checks creating the secret is forbidden.
- Checks updating the existing secret is forbidden.

## `TestReadOnlyCannotMoveNamespace`
**Arrange:**
- Creates a user.
- Creates two projects (p1, p2) on the local cluster, waiting for their project namespaces to exist.
- Binds the user to "read-only" on both projects via PRTBs.
- Creates a namespace in project 1, and waits for the user to be able to see it.

**Act:** The read-only user attempts to move the namespace to project 2 by patching its `field.cattle.io/projectId` annotation.

**Assert:**
- Checks the patch attempt is forbidden.
