# `cluster_repo_test.go` Summary

Verifies that HTTP, Git, and OCI ClusterRepos download their chart indexes, pick up spec changes, honor OCI tag filters and enable/disable, handle registry errors and rate limits with the right retries, and can install charts.

## `TestHTTPRepo`
Starts a local HTTP Helm repository serving the testdata charts, creates an HTTP ClusterRepo pointing at it, then changes its URL to `https://releases.rancher.com/server-charts/stable`, then deletes it.
- Checks the local server receives the User-Agent `go/rancher/<server-version-type>/<server-version> (HTTP-based Helm Repository)`.
- Checks the repo downloads and its status URL is the local server.
- Checks the URL change triggers a new download, the status URL is the new URL, and the observed generation increases.
- Checks the repo is gone after the delete.

## `TestGitRepo`
Creates a Git ClusterRepo for `https://github.com/rancher/charts`, then changes it to `https://github.com/rancher/rke2-charts`, then deletes it.
- Checks the repo downloads and its status URL is `rancher/charts`.
- Checks the URL change triggers a new download, the status URL is `rancher/rke2-charts`, and the observed generation increases.
- Checks the repo is gone after the delete.

## `TestGitRepoRetries`
Creates a Git ClusterRepo for `https://github.com/rancher/charts-small-fork` on branch `invalid-branch` with exponential backoff of 30s min wait, 60s max wait and 2 max retries, then changes the branch to `main`.
- Checks the `RepoDownloaded` condition stays False while the retry count goes 1, then 2, then back to 0 once retries are exhausted.
- Checks the branch change to `main` triggers a download with a newer download time.
- Checks the repo is gone after the delete.

## `TestOCIRepo`
Starts a local OCI registry, pushes `testingchart` 0.1.0 to `rancher/testingchart`, creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart` with plain HTTP, then changes its URL to `oci://<registry>/rancher/testingchart:0.1.0`, then deletes it.
- Checks every registry request has a User-Agent containing `go`, `rancher` and `(OCI-based Helm Repository)`.
- Checks the repo downloads and its status URL is the first URL.
- Checks the URL change triggers a new download, the status URL is the tagged URL, and the observed generation increases.
- Checks the repo is gone after the delete.

## `TestOCIRepo2`
Starts a local OCI registry with `testingchart` 0.1.0, creates an OCI ClusterRepo for the namespace URL `oci://<registry>/rancher`, then changes it to the registry root `oci://<registry>/`, then deletes it.
- Checks the repo downloads and its status URL is the namespace URL.
- Checks the URL change triggers a new download, the status URL is the root URL, and the observed generation increases.
- Checks the repo is gone after the delete.

## `TestOCIRepo3`
For each of 404, 401 and 403, starts a registry that answers every request with that status and creates an OCI ClusterRepo for `oci://<registry>/rancher`, then deletes it.
- Checks the `OCIDownloaded` condition becomes False with the message `error <code>: <status text>` (`Not Found`, `Unauthorized`, `Forbidden`).
- Checks the repo makes no retries.
- Checks no index ConfigMap is created.
- Checks the repo is gone after the delete.

## `TestOCIRepo4`
Starts a registry with `testingchart` (tags 0.1.0 and 0.0.1) and `testchart` (tags 1.0.0 and 0.1.1) whose `testchart` 1.0.0 manifest returns 429 for 1 minute after the first request, then creates an OCI ClusterRepo for the registry root with a 65s refresh interval and backoff of 1s min wait, 1s max wait and 1 max retry.
- Checks the `OCIDownloaded` condition becomes False with the retry count back at 0.
- Checks the partial index has 2 charts, with 2 `testingchart` versions that have digests.
- Checks the next refresh after the rate limit resets sets `OCIDownloaded` True with 0 retries.
- Checks the full index has 2 versions each of `testchart` and `testingchart`, with digests.
- Checks the repo is gone after the delete.

## `TestOCIRepo5`
Same as `TestOCIRepo4`, but the registry also sends `RateLimit-Remaining: 0;w=60` on HEAD requests for the `testchart` 1.0.0 manifest, and the ClusterRepo uses the default refresh interval.
- Checks the `OCIDownloaded` condition becomes False with the retry count back at 0.
- Checks the partial index has 2 charts, with 2 `testingchart` versions that have digests.
- Checks the repo later sets `OCIDownloaded` True with 0 retries.
- Checks the full index has 2 versions each of `testchart` and `testingchart`, with digests.
- Checks the repo is gone after the delete.

## `TestOCIRepoMultipleChartRepos`
Starts a local OCI registry, pushes `testingchart` 0.1.0 to 300 repositories (`rancher/testingchart-0` through `rancher/testingchart-299`), creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart-0`, then changes it to `oci://<registry>/rancher/testingchart-0:0.1.0`, then deletes it.
- Checks the repo downloads and its status URL is the first URL.
- Checks the URL change triggers a new download, the status URL is the tagged URL, and the observed generation increases.
- Checks the repo is gone after the delete.

## `TestOCIRepoWithOptions`
Starts a local OCI registry with `testingchart` 0.1.0 and 1.0.0, creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart` with tag filter `< 1.0.0`, then enables `DownloadAllTags` while keeping the filter, then removes the filter.
- Checks the repo downloads and the index only has `testingchart` versions matching `< 1.0.0`.
- Checks the index still has 1 `testingchart` version after `DownloadAllTags` is enabled with the filter kept.
- Checks the index has both `testingchart` versions after the filter is removed.
- Checks the repo is gone after the delete.

## `TestOCIRepoChartInstallation`
Starts a local OCI registry with `testingchart` 0.1.0, creates an OCI ClusterRepo for `oci://<registry>/rancher`, installs `testingchart` 0.1.0 from it as release `testreleasename` in `default`, then uninstalls it and deletes the repo.
- Checks the app reaches `deployed`.
- Checks the app has the `catalog.cattle.io/cluster-repo-name` label set to the ClusterRepo's name.
- Checks the app is deleted after the uninstall.
- Checks a second delete of the repo fails because it is already gone.

## `TestOCIEnableRepo`
Starts a local OCI registry with `testingchart` 0.1.0 and creates an OCI ClusterRepo for `oci://<registry>/rancher`, then disables the repo, pushes `testchart` 1.0.0 and force-refreshes it, then enables it and force-refreshes it again.
- Checks the index still has only 1 chart after the force refresh while disabled.
- Checks the index has 2 charts after the force refresh once re-enabled.
- Checks a second delete of the repo fails because it is already gone.
