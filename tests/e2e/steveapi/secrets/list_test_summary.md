# `list_test.go` Summary

Verifies that listing secrets through Steve on the local cluster filters, sorts, pages, summarizes and scopes results correctly for users with different access. Test cases come from `list_cases_test.go` (a pure fixture file of 139 table-driven cases, including a `sqlOnlyListTests` subset for features only Steve's SQL cache supports: summaries and filtering/sorting on `metadata.fields`).

## `TestList`
**Arrange:**
- Suite setup creates 2 projects and 9 namespaces: 5 namespaces in the first project with 5 secrets each (`test1`–`test5`), 2 in the second project and 2 outside any project with 2 secrets each.
- Labels `test2` as `test-label=2` and `test3`–`test5` as `test-label-gte=3`; gives the first 3 secrets in the first namespace 15, 23 and 7 data keys; annotates `test4` in the second namespace with `management.cattle.io/project-scoped-secret-copy`.
- Creates 5 users: user-a (project-owner of the first project), user-b (get/list secrets in one namespace), user-c (get/list only `test1` and `test2` in 3 namespaces), user-d (project-owner of both projects, plus get/list in both non-project namespaces), and user-e (cluster-owner).

**Act:** Runs 139 table-driven list requests against Steve's secrets endpoint, each as one of the 5 users, either cluster-wide or scoped to one namespace, and records each response as a request/response example under `testdata/`.

**Assert:**
- Checks each user receives exactly the secrets their bindings grant, in the expected order, from only the namespaces/secrets they can see (for the cluster-owner, checks expected secrets are included or excluded as the case specifies).
- Checks label, name, namespace, annotation and `metadata.fields` filters (`=`, `!=`, `~`, `>`, OR within a filter, AND across filters) and `projectsornamespaces`/`projectsornamespaces!=` scoping narrow or exclude results correctly.
- Checks sorting by name, namespace and data-key count works ascending and descending.
- Checks `pagesize` returns the expected first page, and `page=2` with the previous response's revision returns the next page.
- Checks `summary` on name, namespace and state returns the expected per-value counts.
