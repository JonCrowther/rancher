# `etcdbackups_test.go` Summary

Verifies that the "backups-manage" ClusterRoleTemplate grants access to etcdbackups resources on the local cluster, while the standard "user" global role does not.

## `TestBackupsManageRole`
**Arrange:**
- Creates a restricted user with the "user-base" global role.

**Act:** Binds the restricted user to the "backups-manage" ClusterRoleTemplate on the local cluster via a CRTB.

**Assert:**
- Checks the user eventually can list "etcdbackups" resources (management.cattle.io) in the local cluster's namespace.

## `TestStandardUsersCannotAccessBackups`
**Arrange:**
- Creates a standard user with only the "user" global role.
- Confirms the "user" role's permissions have propagated by waiting until the user can create secrets in the "cattle-global-data" namespace.

**Act:** Checks whether the user can list "etcdbackups" resources in the local cluster's namespace.

**Assert:**
- Checks access is denied — the standard "user" global role does not grant it.
