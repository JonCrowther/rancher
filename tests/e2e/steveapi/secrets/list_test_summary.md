# `list_test.go` Summary

Verifies that listing secrets through Steve on the local cluster filters, sorts, pages, summarizes and scopes results correctly for users with different access.

## `TestList`
The suite first creates 2 projects and 9 namespaces: 5 namespaces in the first project with 5 secrets each (`test1`–`test5`), 2 in the second project and 2 outside any project with 2 secrets each. `test2` is labelled `test-label=2`, `test3`–`test5` are labelled `test-label-gte=3`, the first 3 secrets in the first namespace have 15, 23 and 7 data keys, and `test4` in the second namespace carries a `management.cattle.io/project-scoped-secret-copy` annotation. It then creates 5 users:
- user-a is project-owner of the first project.
- user-b can get and list secrets in one namespace.
- user-c can get and list only `test1` and `test2` in 3 namespaces.
- user-d is project-owner of both projects and can get and list secrets in both non-project namespaces.
- user-e is cluster-owner.

The test then runs 139 table-driven list requests, each as one of those users, cluster-wide or in one namespace, and writes each response as a request/response example under `testdata/`.
- Checks each user gets exactly the expected secrets, in the expected order, from only the namespaces and secrets their bindings grant (for the cluster-owner, that the expected secrets are included or excluded).
- Checks label, name, namespace, annotation and `metadata.fields` filters (with `=`, `!=`, `~`, `>`, OR within a filter and AND across filters) narrow the results.
- Checks sorting by name, namespace and data-key count, ascending and descending.
- Checks `pagesize` returns the expected first page and `page=2` with the previous response's revision returns the next one.
- Checks `projectsornamespaces` limits results to the given projects or namespaces and `projectsornamespaces!=` excludes them.
- Checks `summary` on name, namespace and state returns the expected per-value counts.
