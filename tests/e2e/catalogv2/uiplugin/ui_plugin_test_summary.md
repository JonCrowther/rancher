# `ui_plugin_test.go` Summary

With 4 plugins from the rancher/ui-plugin-examples repo installed into `cattle-ui-plugin-system` and ready (`uk-locale` 0.1.1, which needs no auth, `clock` 0.2.0, `top-level-product` 0.1.0 with `plugin.noCache=true`, and `homepage` 0.4.1), verifies that Rancher's `/v1/uiplugins` endpoint serves the plugin index and files with the right authentication rules, and that the UIPlugin controller handles compressed, failing, and unreachable endpoints.

## `TestGetIndexAuthenticated`
Fetches the `/v1/uiplugins` index with the admin session cookie.
- Checks the response is 200.
- Checks the index contains all 4 installed plugins.

## `TestGetIndexUnauthenticated`
Fetches the `/v1/uiplugins` index with no session.
- Checks the response is 200.
- Checks the index contains `uk-locale` and none of the 3 plugins that require authentication.

## `TestCorrectContentType`
Fetches `top-level-product-0.1.0.umd.min.1.js` from the `top-level-product` plugin with the admin session.
- Checks the response is 200.
- Checks the `Content-Type` header is the MIME type for `.js`.

## `TestGetSingleExtensionAuthenticated`
Fetches `clock-0.2.0.umd.min.js` from the `clock` plugin with the admin session.
- Checks the response is 200.

## `TestGetSingleExtensionUnauthenticated`
Fetches `uk-locale-0.1.1.umd.min.js` from the `uk-locale` plugin, which doesn't require authentication, with no session.
- Checks the response is 200.

## `TestGetSingleUnauthorizedExtension`
Fetches `clock-0.2.0.umd.min.js` from the `clock` plugin, which requires authentication, with no session.
- Checks the response is 404.

## `TestCompressedEndpoint`
Starts a local server that serves the homepage plugin as a `.tgz`, sets it as the `homepage` UIPlugin's `CompressedEndpoint` with an empty `Endpoint`, then fetches `main.js` from the plugin.
- Checks the file request returns 200, or 425 if the plugin isn't cached yet.
- Checks the UIPlugin becomes ready for its updated spec.

## `TestExponentialBackoff`
Starts a local server that returns 500 for its first 2 requests and then serves the plugin files, and points the `homepage` UIPlugin's `Endpoint` at it.
- Checks the controller retries while the server fails, reaching a retry count of 2, and the UIPlugin is never ready during retries.
- Checks the UIPlugin then becomes ready with its retry count reset to 0.

## `TestUnreachableCompressedEndpoint`
Starts a local server that serves the plugin files, then sets it as the `homepage` UIPlugin's `Endpoint` and an unreachable URL as its `CompressedEndpoint`.
- Checks the UIPlugin becomes ready for its updated spec by falling back to `Endpoint`.
