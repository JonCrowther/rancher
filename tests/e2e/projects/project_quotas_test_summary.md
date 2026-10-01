# `project_quotas_test.go` Summary

Verifies project resource-quota API validation, propagation of a project's resource quota and
namespace-default quota to namespace `ResourceQuota` objects on Rancher's local cluster, and
tracking of the project's `usedLimit` as namespaces consume quota.

## `TestProjectResourceQuotaFields`
**Act:** Creates a project on the local cluster with a resource quota and a namespace default
resource quota of 100 pods each.

**Assert:**
- Checks the created project's `resourceQuota.limit.pods` is "100".
- Checks the created project's `namespaceDefaultResourceQuota.limit.pods` is "100".

## `TestProjectQuotaAPIValidation`
**Arrange:**
- Creates a project on the local cluster without a quota (target of the field-mismatch update
  case below).

**Act:** Attempts to create or update projects with four invalid resource-quota combinations: a
resourceQuota without a namespaceDefaultResourceQuota, a namespaceDefaultResourceQuota without a
resourceQuota, a namespace default quota (200 pods) exceeding the project quota (100 pods), and an
update whose namespace default quota (pods only) omits a field the project quota defines
(services).

**Assert:**
- Checks each of the four attempts is rejected with 422 Unprocessable Entity.

## `TestProjectContainerDefaultResourceLimit`
**Act 1:** Creates a project with a resource quota, a namespace default quota, and a
containerDefaultResourceLimit (CPU/memory requests and limits).
**Assert 1:**
- Checks the created project's resourceQuota and containerDefaultResourceLimit are set.

**Act 2:** Updates the project to clear its containerDefaultResourceLimit.
**Assert 2:**
- Checks the updated project's containerDefaultResourceLimit is nil.

## `TestNamespaceResourceQuotaCreated`
**Arrange:**
- Creates a project on the local cluster with a 100-pod resource quota and namespace default.

**Act:** Creates a namespace in the project with a quota annotation requesting 4 pods and 50
configMaps.

**Assert:**
- Checks the controller creates a ResourceQuota in the namespace with exactly pods=4, dropping
  configMaps since the project quota doesn't define it.

## `TestNamespaceDefaultQuotaApplied`
**Arrange:**
- Creates a project on the local cluster with a 100-pod resource quota and a 4-pod namespace
  default.

**Act:** Creates a namespace in the project without an explicit quota annotation.

**Assert:**
- Checks the controller creates a ResourceQuota in the namespace with pods=4 (the project's
  namespace default).

## `TestProjectQuotaUpdateAppliedToNamespace`
**Arrange:**
- Creates a project on the local cluster without a quota.
- Creates a namespace in the project.

**Act:** Updates the project to add a 100-pod resource quota and a 4-pod namespace default.

**Assert:**
- Checks the controller creates a ResourceQuota in the existing namespace with pods=4.

## `TestAddQuotaFromProjectWithNamespacePropagation`
**Arrange:**
- Creates a project on the local cluster with a 500m CPU-limit resource quota and a 200m CPU-limit
  namespace default.
- Creates a namespace in that project.

**Act:** Adds a secrets limit to the project (20) and its namespace default (10).

**Assert:**
- Checks the namespace's ResourceQuota becomes exactly limits.cpu=200m and secrets=10.

## `TestRemoveQuotaFromProjectWithNamespacePropagation`
**Arrange:**
- Creates a project on the local cluster with resource quota limits of 500m CPU and 10 ConfigMaps,
  and namespace-default limits of 200m CPU and 5 ConfigMaps.
- Creates a namespace in that project.

**Act 1:** Removes the CPU limit from the project and its namespace default.
**Assert 1:**
- Checks the namespace's ResourceQuota retains just the ConfigMaps limit (5).

**Act 2:** Removes the ConfigMaps limit as well.
**Assert 2:**
- Checks the namespace's ResourceQuota object is deleted entirely.

## `TestNamespaceQuotaExceedsProjectLimit`
**Arrange:**
- Creates a project on the local cluster with a 100-pod resource quota and namespace default.

**Act:** Creates a namespace in the project with a quota annotation requesting 200 pods (exceeding
the project limit).

**Assert:**
- Checks the controller creates a ResourceQuota in the namespace with pods=0 (the overused
  resource zeroed).
- Checks the project's usedLimit.pods remains "0" (the overused namespace isn't counted).

## `TestProjectUsedQuotaUpdated`
**Arrange:**
- Creates a project on the local cluster with a 100-pod resource quota and a 4-pod namespace
  default.

**Act:** Creates a namespace in the project without an explicit quota annotation.

**Assert:**
- Checks the project's usedLimit.pods becomes "4".

## `TestProjectUsedQuotaExactMatch`
**Arrange:**
- Creates a project on the local cluster with a 10-pod resource quota and a 2-pod namespace
  default.
- Creates two namespaces in the project requesting 2 and 8 pods respectively, so usedLimit.pods
  reaches 10 (the full quota).

**Act:** Attempts to reduce the project's quota to 8 pods and namespace default to 1 pod.

**Assert:**
- Checks the update is rejected with 422, since it would drop the limit below the already-used
  amount.

## `TestProjectQuotaAddRemoveFields`
**Arrange:**
- Creates a project on the local cluster with a 10-pod resource quota and a 2-pod namespace
  default.
- Creates two namespaces in the project, each consuming the 2-pod default (usedLimit.pods reaches
  4).

**Act 1:** Attempts to add a services limit to the project whose namespace default (7) times the
existing namespace count would exceed the project limit (10).
**Assert 1:**
- Checks the update is rejected with 422.

**Act 2:** Adds a services limit to the project (10) with a valid 2-pod-per-namespace default.
**Assert 2:**
- Checks the update succeeds.
- Checks the project's usedLimit.services becomes "4" as the controller propagates the default to
  the existing namespaces.

**Act 3:** Removes the services limit from the project.
**Assert 3:**
- Checks the update succeeds. (Does not assert usedLimit.services returns to "0" afterward, due to
  a known eventual-consistency gap between the Norman and Wrangler informers — tracked as
  rancher/rancher#55060.)

## `TestProjectQuotaCannotExceedWithExistingNamespaces`
**Arrange:**
- Creates a project on the local cluster without a quota.
- Creates 4 namespaces in the project.

**Act:** Attempts to set a 5-pod project quota with a 2-pod namespace default.

**Assert:**
- Checks the update is rejected with 422, since 2 pods × 4 existing namespaces (8) exceeds the
  5-pod limit.
