# `global_role_bindings_test.go` Summary

Verifies validation and immutability rules on GlobalRoleBindings' role and subject fields.

## `TestGRBCannotUpdateGlobalRoleID`
**Arrange:**
- Creates a user.
- Creates a GlobalRoleBinding binding the user to GlobalRole "nodedrivers-manage".

**Act:** Attempts to update the GlobalRoleBinding's `globalRoleId` to "settings-manage".

**Assert:**
- Checks `globalRoleId` remains "nodedrivers-manage" after the update.

## `TestGRBGlobalRoleMustExist`
**Arrange:**
- Creates a user.

**Act:** Attempts to create a GlobalRoleBinding referencing a non-existent GlobalRole ("somefakerole").

**Assert:**
- Checks the creation fails with 404 Not Found.

## `TestGRBCannotUpdateSubject`
**Arrange:**
- Creates two users (user1, user2).
- Creates a GlobalRoleBinding binding user1 to GlobalRole "nodedrivers-manage".

**Act:** Attempts to update the GlobalRoleBinding's `userId` and `groupPrincipalId` fields.

**Assert:**
- Checks `userId` remains user1's ID after attempting to change it to user2's ID.
- Checks `userId` still remains user1's ID, and `groupPrincipalId` stays empty, after attempting to set `groupPrincipalId`.

## `TestGRBTargetsUserOrGroup`
**Arrange:**
- Creates a user.

**Act:** Attempts to create GlobalRoleBindings with both `userId` and `groupPrincipalId` set, and with neither set.

**Assert:**
- Checks both attempts fail with 422 Unprocessable Entity.
