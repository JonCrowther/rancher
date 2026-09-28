# `system_project_test.go` Summary

Verifies that the local cluster's System project can't be deleted and that the system namespaces' default service accounts don't automount their tokens.

## `TestSystemProjectCannotBeDeleted`
Finds the local cluster's System project and tries to delete it.
- Checks the delete is rejected with 405 Method Not Allowed.
- Checks the error body contains "System Project cannot be deleted".

## `TestSystemNamespacesDefaultServiceAccount`
Reads the `system-namespaces` setting and lists the `default` ServiceAccount in every namespace on the local cluster.
- Checks the default ServiceAccount in each system namespace except kube-system has automountServiceAccountToken=false.
- Checks at least one such ServiceAccount was found.
