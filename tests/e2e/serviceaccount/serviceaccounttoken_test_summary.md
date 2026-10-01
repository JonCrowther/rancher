# `serviceaccounttoken_test.go` Summary

Verifies that concurrent calls to ensure a token Secret for a service account converge on exactly one Secret, correctly referenced by the service account.

## `TestSingleSecretForServiceAccount`
**Arrange:**
- Gets a Kubernetes clientset for the cluster under test (`local`).
- Creates a namespace.
- Creates a service account in that namespace.

**Act:** Calls `EnsureSecretForServiceAccount` 10 times concurrently for the same service account.

**Assert:**
- Checks all 10 concurrent calls return no error.
- Checks exactly 1 token Secret exists for the service account despite the 10 concurrent calls.
- Checks the service account's secret-ref annotation points to that one remaining Secret, confirming it isn't an orphan.
