# `global_role_bindings_test.go` Summary

Verifies validation and immutability rules on global role bindings.

## `TestGRBCannotUpdateGlobalRoleID`
Creates a GlobalRoleBinding with globalRoleId "nodedrivers-manage" and attempts to change it to "settings-manage".
- Checks the globalRoleId remains "nodedrivers-manage" after update.

## `TestGRBGlobalRoleMustExist`
Attempts to create a GlobalRoleBinding referencing a non-existent global role "somefakerole".
- Checks the request fails with 404 Not Found.

## `TestGRBCannotUpdateSubject`
Creates a GlobalRoleBinding with user1 and attempts to change both userId and groupPrincipalId.
- Checks userId remains unchanged when attempting update to user2.
- Checks groupPrincipalId stays empty when attempting to set it.

## `TestGRBTargetsUserOrGroup`
Attempts to create GlobalRoleBindings with invalid subject combinations: both userId and groupPrincipalId, and neither.
- Checks both requests fail with 422 Unprocessable Entity.
