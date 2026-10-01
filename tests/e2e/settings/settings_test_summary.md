# `settings_test.go` Summary

Verifies that settings can be created, read, updated, and deleted according to their access constraints, and that read-only settings are properly protected.

## `TestCreateReadOnly`
**Act:** Attempts to create a setting named "cacerts" (a built-in read-only setting) with value "a".

**Assert:**
- Checks the request is rejected with 405 Method Not Allowed.
- Checks the error message contains "readOnly".

## `TestUpdateReadOnly`
**Arrange:**
- Retrieves the existing read-only "cacerts" setting.

**Act:** Attempts to update the setting's value.

**Assert:**
- Checks the request is rejected with 405 Method Not Allowed.
- Checks the error message contains "readOnly".

## `TestGetReadOnly`
**Act:** Retrieves the read-only "cacerts" setting by ID.

**Assert:**
- Checks the setting is retrieved without error, with ID "cacerts".
- Checks the setting has no "update" link.

## `TestDeleteReadOnly`
**Arrange:**
- Retrieves the existing read-only "cacerts" setting.

**Act:** Attempts to delete the setting.

**Assert:**
- Checks the request is rejected with 405 Method Not Allowed.
- Checks the error message contains "readOnly".

## `TestCreate`
**Act:** Creates a new setting with a randomly generated "samplesetting-" name and value "a".

**Assert:**
- Checks the setting is created without error.
- Checks the returned setting's value is "a".

## `TestCreateExisting`
**Arrange:**
- Creates a setting with a given name and value "a".

**Act:** Attempts to create another setting using that same name.

**Assert:**
- Checks the second creation fails with 409 Conflict.
- Checks the error message contains "AlreadyExists".

## `TestUpdate`
**Arrange:**
- Creates a setting with value "a".

**Act:** Updates the setting's value to "b".

**Assert:**
- Checks the update succeeds.
- Checks the returned setting's value is "b".

## `TestUpdateNonExisting`
**Arrange:**
- Creates a setting, and confirms a direct PUT to its ID returns 200 (so the helper request itself is known-good).

**Act:** Sends the same PUT request against a nonexistent setting ID.

**Assert:**
- Checks the response status is 404 Not Found.

## `TestUpdateLink`
**Arrange:**
- Creates a setting.
- Creates a standard user with global role "user".

**Act:** Retrieves the setting as both the admin client and the standard user client.

**Assert:**
- Checks the admin user sees the "update" action link on the setting.
- Checks the standard user does not see the "update" link.
</content>
