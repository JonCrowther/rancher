# `project_quotas_test.go` Summary

Verifies project resource quota API validation, the ResourceQuotas the quota controller creates in a project's namespaces on the local cluster, propagation of project quota changes to those namespaces, and project usedLimit tracking.

## `TestProjectResourceQuotaFields`
Creates a project on the local cluster with a resource quota and a namespace default resource quota of 100 pods each.
- Checks the created project's resourceQuota.limit.pods is "100".
- Checks the created project's namespaceDefaultResourceQuota.limit.pods is "100".

## `TestProjectQuotaAPIValidation`
Creates and updates projects on the local cluster with invalid quota combinations.
- Checks a resourceQuota without a namespaceDefaultResourceQuota is rejected with 422.
- Checks a namespaceDefaultResourceQuota without a resourceQuota is rejected with 422.
- Checks a namespace default quota larger than the project quota (200 > 100 pods) is rejected with 422.
- Checks an update whose namespace default quota omits a limit the project quota defines (services) is rejected with 422.

## `TestProjectContainerDefaultResourceLimit`
Creates a project on the local cluster with a containerDefaultResourceLimit (CPU and memory requests and limits), then clears it with an update.
- Checks the created project has the resourceQuota and containerDefaultResourceLimit set.
- Checks updating containerDefaultResourceLimit to null clears it.

## `TestNamespaceResourceQuotaCreated`
Creates a project on the local cluster with a 100-pod quota, then a namespace in it whose quota annotation requests 4 pods and 50 configMaps.
- Checks the controller creates a ResourceQuota in the namespace with exactly pods=4, dropping configMaps because the project quota doesn't define it.

## `TestNamespaceDefaultQuotaApplied`
Creates a project on the local cluster with a 100-pod quota and a 4-pod namespace default, then a namespace in it without a quota annotation.
- Checks the controller creates a ResourceQuota in the namespace with pods=4.

## `TestProjectQuotaUpdateAppliedToNamespace`
Creates a project on the local cluster without a quota and a namespace in it, then updates the project to a 100-pod quota with a 4-pod namespace default.
- Checks the controller creates a ResourceQuota in the existing namespace with pods=4.

## `TestAddQuotaFromProjectWithNamespacePropagation`
Creates a project on the local cluster with a 500m CPU-limit quota and a 200m namespace default, and a namespace in it, then adds a secrets limit (20 for the project, 10 per namespace) to the project.
- Checks the namespace's ResourceQuota is exactly limits.cpu=200m before the change.
- Checks the namespace's ResourceQuota becomes exactly limits.cpu=200m and secrets=10.

## `TestRemoveQuotaFromProjectWithNamespacePropagation`
Creates a project on the local cluster with CPU-limit and configMaps quotas (500m/10 for the project, 200m/5 per namespace) and a namespace in it, then removes the CPU limit and finally the configMaps limit from the project.
- Checks the namespace's ResourceQuota is exactly limits.cpu=200m and configmaps=5 before the change.
- Checks the namespace's ResourceQuota becomes exactly configmaps=5 after the CPU limit is removed.
- Checks the namespace's ResourceQuota is deleted after the last limit is removed.

## `TestNamespaceQuotaExceedsProjectLimit`
Creates a project on the local cluster with a 100-pod quota, then a namespace in it whose quota annotation requests 200 pods.
- Checks the controller creates a ResourceQuota in the namespace with pods=0.
- Checks the project's usedLimit.pods is "0" (the overused namespace isn't counted).

## `TestProjectUsedQuotaUpdated`
Creates a project on the local cluster with a 100-pod quota and a 4-pod namespace default, then a namespace in it without a quota annotation.
- Checks the project's usedLimit.pods becomes "4".

## `TestProjectUsedQuotaExactMatch`
Creates a project on the local cluster with a 10-pod quota, then two namespaces in it requesting 2 and 8 pods, and tries to reduce the project quota to 8 pods.
- Checks the project's usedLimit.pods becomes "10".
- Checks reducing the project quota below the used amount is rejected with 422.

## `TestProjectQuotaAddRemoveFields`
Creates a project on the local cluster with a 10-pod quota and two namespaces requesting 2 pods each, then adds a services limit to the project and removes it again.
- Checks the project's usedLimit.pods becomes "2" and then "4" as the namespaces are created.
- Checks adding a services limit whose namespace default (7) times the existing namespaces exceeds the project limit (10) is rejected with 422.
- Checks adding a services limit with a 2-per-namespace default succeeds, and the project's usedLimit.services becomes "4".
- Checks removing the services limit succeeds.

## `TestProjectQuotaCannotExceedWithExistingNamespaces`
Creates a project on the local cluster without a quota and four namespaces in it, then tries to set a 5-pod quota with a 2-pod namespace default.
- Checks the update is rejected with 422, since 2 pods × 4 namespaces exceeds the 5-pod limit.
