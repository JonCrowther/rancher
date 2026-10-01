# `project_user_test.go` Summary

Verifies that users bound to the project-member and project-owner roles can create namespaces in
their project on Rancher's local cluster.

## `TestCreateNamespaceProjectMember`
**Arrange:**
- Creates a project on the local cluster and a user with the global "user" role.
- Binds the user to the project via a ProjectRoleTemplateBinding with role "project-member".
- Waits until the user is allowed to create namespaces in the cluster (RBAC propagation).

**Act:** Creates a namespace as the bound user.

**Assert:**
- Checks the namespace is created without error.
- Checks the created namespace's name matches the requested name.

## `TestCreateNamespaceProjectOwner`
**Arrange:**
- Creates a project on the local cluster and a user with the global "user" role.
- Binds the user to the project via a ProjectRoleTemplateBinding with role "project-owner".
- Waits until the user is allowed to create namespaces in the cluster (RBAC propagation).

**Act:** Creates a namespace as the bound user.

**Assert:**
- Checks the namespace is created without error.
- Checks the created namespace's name matches the requested name.
