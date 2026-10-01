# `users_test.go` Summary

Verifies that the v3 users API enforces self-modification protections and password rules: a user with permission to delete or deactivate other users still can't delete or deactivate itself, usernames can't double as passwords, and passwords must meet the configured minimum length.

## `TestUserCantDeleteSelf`
**Arrange:**
- Creates a throwaway user with the `users-manage` global role.
- Creates a second throwaway user with no roles.
- Logs in as the `users-manage` user and confirms it can delete the other user, proving the role is in effect before testing the self-delete rule.

**Act:** The `users-manage` user attempts to delete itself.

**Assert:**
- Checks the deletion is rejected with 422 Unprocessable Entity.
- Checks the error message states the user cannot delete themselves.

## `TestUserCantDeactivateSelf`
**Arrange:**
- Creates a throwaway user with the `users-manage` global role.
- Creates a second throwaway user with no roles.
- Logs in as the `users-manage` user and confirms it can set the other user's `enabled` field to `false`, proving the role is in effect before testing the self-deactivate rule.

**Act:** The `users-manage` user attempts to update itself with `enabled=false`.

**Assert:**
- Checks the update is rejected with 422 Unprocessable Entity.
- Checks the error message states the user cannot deactivate themselves.

## `TestUserCantUseUsernameAsPassword`
**Act:** Attempts to create a user whose password is set to the same value as its username.

**Assert:**
- Checks the creation is rejected with 422 Unprocessable Entity.
- Checks the error message states the password cannot be the same as the username.

## `TestPasswordTooShort`
**Arrange:**
- Reads the configured `password-min-length` setting.

**Act 1:** Creates a user with a password whose length exactly equals the minimum.
**Assert 1:**
- Checks the creation succeeds.

**Act 2:** Creates a user with a password one character shorter than the minimum.
**Assert 2:**
- Checks the creation is rejected with 422 Unprocessable Entity.
- Checks the error message states the password must be at least the minimum number of characters.
</content>
