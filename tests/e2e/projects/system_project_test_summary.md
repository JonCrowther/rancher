# `system_project_test.go` Summary

Verifies that Rancher's local-cluster System project can't be deleted and that the default service
accounts in system namespaces (other than kube-system) have token automounting disabled.

## `TestSystemProjectCannotBeDeleted`
**Arrange:**
- Finds the local cluster's "System" project.

**Act:** Attempts to delete the System project.

**Assert:**
- Checks the delete is rejected with 405 Method Not Allowed.
- Checks the error body contains "System Project cannot be deleted".

## `TestSystemNamespacesDefaultServiceAccount`
**Arrange:**
- Reads the `system-namespaces` setting to get the list of system namespace names.

**Act:** Lists the `default` ServiceAccount in every namespace on the local cluster.

**Assert:**
- Checks the default ServiceAccount in each system namespace, except kube-system, has
  automountServiceAccountToken=false.
- Checks at least one such ServiceAccount was found.
