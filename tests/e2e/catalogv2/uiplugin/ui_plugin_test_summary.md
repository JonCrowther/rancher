# `ui_plugin_test.go` Summary

With 4 plugins from the rancher/ui-plugin-examples repo installed into `cattle-ui-plugin-system` and ready (`uk-locale` 0.1.1, which needs no auth, `clock` 0.2.0, `top-level-product` 0.1.0 with `plugin.noCache=true`, and `homepage` 0.4.1), verifies that Rancher's `/v1/uiplugins` endpoint serves the plugin index and files with the right authentication rules, and that the UIPlugin controller handles compressed, failing, and unreachable endpoints.

## `TestGetIndexAuthenticated`
**Act:** Fetches the `/v1/uiplugins` index with the admin session cookie.

**Assert:**
- Checks the response is 200.
- Checks the index contains all 4 installed plugins (`uk-locale`, `clock`, `top-level-product`, `homepage`).

## `TestGetIndexUnauthenticated`
**Act:** Fetches the `/v1/uiplugins` index with no session.

**Assert:**
- Checks the response is 200.
- Checks the index contains `uk-locale` and omits the 3 plugins that require authentication.

## `TestCorrectContentType`
**Act:** Fetches `top-level-product-0.1.0.umd.min.1.js` from the `top-level-product` plugin with the admin session.

**Assert:**
- Checks the response is 200.
- Checks the `Content-Type` header matches the MIME type for `.js`.

## `TestGetSingleExtensionAuthenticated`
**Act:** Fetches `clock-0.2.0.umd.min.js` from the `clock` plugin with the admin session.

**Assert:**
- Checks the response is 200.

## `TestGetSingleExtensionUnauthenticated`
**Act:** Fetches `uk-locale-0.1.1.umd.min.js` from the `uk-locale` plugin, which doesn't require authentication, with no session.

**Assert:**
- Checks the response is 200.

## `TestGetSingleUnauthorizedExtension`
**Act:** Fetches `clock-0.2.0.umd.min.js` from the `clock` plugin, which requires authentication, with no session.

**Assert:**
- Checks the response is 404.

## `TestCompressedEndpoint`
**Arrange:**
- Starts a local server that serves the homepage plugin as a `.tgz` file.

**Act:** Sets the `homepage` UIPlugin's `CompressedEndpoint` to that server with an empty `Endpoint`.

**Assert:**
- Checks a request for `main.js` from the plugin returns 200, or 425 (Too Early) if it isn't cached yet.
- Checks the UIPlugin becomes ready for its updated spec.

## `TestExponentialBackoff`
**Arrange:**
- Starts a local server that fails its first 2 requests with 500, then serves the plugin files normally.

**Act:** Sets the `homepage` UIPlugin's `Endpoint` to that server.

**Assert:**
- Checks the controller retries while the server fails, reaching a retry count of 2, and never marks the UIPlugin ready during retries.
- Checks the UIPlugin then becomes ready with its retry count reset to 0.

## `TestUnreachableCompressedEndpoint`
**Arrange:**
- Starts a local server that serves the plugin files normally.

**Act:** Sets the `homepage` UIPlugin's `Endpoint` to that server and `CompressedEndpoint` to an unreachable URL.

**Assert:**
- Checks the UIPlugin becomes ready for its updated spec by falling back to `Endpoint` when the compressed endpoint is unreachable.
