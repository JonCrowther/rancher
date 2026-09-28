# `project_quotas_test.go` Summary

Verifies project and namespace resource quota API validation, controller-created ResourceQuotas, and project usedLimit tracking.

## `TestProjectResourceQuotaFields`
Creates a project with resource quota and namespace default resource quota, then retrieves it.
- Checks project.resourceQuota.limit.pods="100".
- Checks project.namespaceDefaultResourceQuota.limit.pods="100".

## `TestProjectQuotaAPIValidation`
Tests various invalid quota configurations: resourceQuota without namespaceDefaultResourceQuota, vice versa, exceeding limits, and missing fields.
- Checks resourceQuota without namespaceDefaultResourceQuota fails with 422.
- Checks namespaceDefaultResourceQuota without resourceQuota fails with 422.
- Checks namespace quota exceeding project quota fails with 422.
- Checks namespace quota missing fields defined on project quota fails with 422.

## `TestProjectContainerDefaultResourceLimit`
Creates a project with containerDefaultResourceLimit (CPU/memory requests and limits), then clears it.
- Checks project stores the limits correctly.
- Checks updating with null clears the limit.

## `TestNamespaceResourceQuotaCreated`
Creates a project with quota and namespace with explicit quota annotation requesting 4 pods.
- Checks a k8s ResourceQuota is created with pods limit=4.

## `TestNamespaceDefaultQuotaApplied`
Creates a project with namespace default quota of 4 pods and a namespace without explicit quota.
- Checks the k8s ResourceQuota is created with the project's default limit of 4 pods.

## `TestProjectQuotaUpdateAppliedToNamespace`
Creates a project without quota, adds a namespace, then updates the project to add quota.
- Checks the controller applies the default quota to the existing namespace.

## `TestNamespaceQuotaExceedsProjectLimit`
Creates namespace requesting more pods (200) than the project allows (100).
- Checks a k8s ResourceQuota is created but with zeroed overused resources.

## `TestProjectUsedQuotaUpdated`
Creates a project with quota and a namespace with default quota.
- Checks the project's usedLimit.pods is updated to 4 (the namespace quota).

## `TestProjectUsedQuotaExactMatch`
Creates a project with 10 pod limit, then creates two namespaces using 2 and 8 pods respectively (totaling 10).
- Checks the project's usedLimit is 10.
- Checks reducing the project quota below 10 fails with 422.

## `TestProjectQuotaAddRemoveFields`
Creates a project with pod quota, adds two namespaces, then adds/removes a services field.
- Checks adding services with invalid default fails with 422.
- Checks adding services with valid default succeeds and controller propagates to existing namespaces.
- Checks removing the services field succeeds.

## `TestProjectQuotaCannotExceedWithExistingNamespaces`
Creates a project with 4 namespaces, then attempts to set quota where default × namespace count exceeds limit.
- Checks setting quota where 2 pods default × 4 namespaces = 8 > 5 limit fails with 422.
