# `tokens_test.go` Summary

Verifies Rancher's handling of authentication tokens: identifying the current token, enforcing configured TTLs on created and login-issued tokens, and rejecting cross-origin websocket-upgrade requests.

## `TestCurrentToken`
**Arrange:**
- Creates a standard user and authenticates as them, since the config's admin token may be a derived API key, which Rancher never marks as current.

**Act:** Lists all of the user's tokens via the management API.

**Assert:**
- Checks exactly one token in the list is marked current.
- Checks that token's ID matches the name parsed from the client's own bearer token.
- Checks that token's UserID matches the created user.

## `TestWebsocket`
**Arrange:**
- Confirms a GET to `/v3/clusters` without websocket headers succeeds (200), establishing that the headers below are what causes the rejection.

**Act:** Sends a GET to `/v3/clusters` with websocket-upgrade headers (`Connection: upgrade`, `Upgrade: websocket`) and a foreign `Origin`.

**Assert:**
- Checks the request is rejected with 403 Forbidden.

## `TestAPITokenTTL`
**Arrange:**
- Reads the configured max TTL from the `auth-token-max-ttl-minutes` setting.

**Act:** Creates a token with `TTLMillis=0`.

**Assert:**
- Checks the created token's TTL (converted from milliseconds to minutes) equals the configured max TTL.

## `TestKubeconfigTokenTTL`
**Arrange:**
- Creates a standard user so the test doesn't depend on the config having an admin password.
- Sets the `kubeconfig-default-token-ttl-minutes` setting to `0.1` (6 seconds), restoring the original value afterward.

**Act:** Logs in as the user with `responseType=kubeconfig`, once through the public `/v3-public/localProviders/local?action=login` endpoint and once through `/v1-public/login`.

**Assert:**
- For each endpoint, checks the login response's `token` is `<id>:<secret>` form, with non-empty `expiresAt` and `type`/`baseType` both `"token"`.
- Checks the created Token object's `TTLMillis` is 6000, matching the configured setting.
- Checks the new token authenticates successfully (200) immediately after login.
- Checks the same token is rejected (401) once its TTL has elapsed, confirmed by polling for up to 30s.
