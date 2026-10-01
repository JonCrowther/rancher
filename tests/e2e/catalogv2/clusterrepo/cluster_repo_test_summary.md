# `cluster_repo_test.go` Summary

Verifies that HTTP, Git, and OCI ClusterRepos download their chart indexes, pick up spec changes, honor OCI tag filters and enable/disable, handle registry errors and rate limits with the right retries, and can be used to install charts.

## `TestHTTPRepo`
**Arrange:**
- Starts a local HTTP Helm repository serving the testdata charts.

**Act 1:** Creates an HTTP ClusterRepo pointing at the local server.
**Assert 1:**
- Checks the local server receives User-Agent `go/rancher/<server-version-type>/<server-version> (HTTP-based Helm Repository)`.
- Checks the repo downloads and its status URL is the local server's URL.

**Act 2:** Updates the ClusterRepo's URL to `https://releases.rancher.com/server-charts/stable`.
**Assert 2:**
- Checks the URL change triggers a new download, the status URL becomes the new URL, and the observed generation increases.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestGitRepo`
**Act 1:** Creates a Git ClusterRepo for `https://github.com/rancher/charts`.
**Assert 1:**
- Checks the repo downloads and its status URL is `rancher/charts`.

**Act 2:** Updates the GitRepo URL to `https://github.com/rancher/rke2-charts`.
**Assert 2:**
- Checks the URL change triggers a new download, the status URL becomes `rancher/rke2-charts`, and the observed generation increases.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestGitRepoRetries`
**Act 1:** Creates a Git ClusterRepo for `https://github.com/rancher/charts-small-fork` on branch `invalid-branch`, with exponential backoff of 30s min wait, 60s max wait, and 2 max retries.
**Assert 1:**
- Checks the `RepoDownloaded` condition stays False while the retry count climbs from 1 to 2, then resets to 0 once retries are exhausted.

**Act 2:** Updates the branch to `main`.
**Assert 2:**
- Checks the branch change triggers a download with a newer download time.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestOCIRepo`
**Arrange:**
- Starts a local OCI registry and pushes `testingchart` 0.1.0 to `rancher/testingchart`.

**Act 1:** Creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart` with plain HTTP.
**Assert 1:**
- Checks every registry request has a User-Agent containing `go`, `rancher`, and `(OCI-based Helm Repository)`.
- Checks the repo downloads and its status URL is the first URL.

**Act 2:** Updates the URL to `oci://<registry>/rancher/testingchart:0.1.0`.
**Assert 2:**
- Checks the URL change triggers a new download, the status URL becomes the tagged URL, and the observed generation increases.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestOCIRepo2`
**Arrange:**
- Starts a local OCI registry with `testingchart` 0.1.0 pushed.

**Act 1:** Creates an OCI ClusterRepo for the namespace URL `oci://<registry>/rancher`.
**Assert 1:**
- Checks the repo downloads and its status URL is the namespace URL.

**Act 2:** Updates the URL to the registry root `oci://<registry>/`.
**Assert 2:**
- Checks the URL change triggers a new download, the status URL becomes the root URL, and the observed generation increases.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestOCIRepo3`
**Act:** For each of HTTP 404, 401, and 403, creates an OCI ClusterRepo against a registry that answers every request with that status code.

**Assert:**
- Checks the `OCIDownloaded` condition becomes False with the message `error <code>: <status text>` (`Not Found`, `Unauthorized`, `Forbidden`).
- Checks the repo makes no retries.
- Checks no index ConfigMap is created.
- Checks the repo is gone after deleting it.

## `TestOCIRepo4`
**Arrange:**
- Starts a registry with `testingchart` (tags 0.1.0 and 0.0.1) and `testchart` (tags 1.0.0 and 0.1.1), where the `testchart` 1.0.0 manifest returns 429 for 1 minute after the first request.

**Act:** Creates an OCI ClusterRepo for the registry root with a 65s refresh interval and exponential backoff of 1s min wait, 1s max wait, and 1 max retry.

**Assert:**
- Checks the `OCIDownloaded` condition becomes False with the retry count back at 0.
- Checks the partial index has 2 charts, with 2 `testingchart` versions that have digests.
- Checks the next refresh after the rate limit resets sets `OCIDownloaded` True with 0 retries.
- Checks the full index has 2 versions each of `testchart` and `testingchart`, with digests.
- Checks the repo is gone after deleting it.

## `TestOCIRepo5`
**Arrange:**
- Starts the same registry as `TestOCIRepo4`, except it also sends `RateLimit-Remaining: 0;w=60` on HEAD requests for the `testchart` 1.0.0 manifest.

**Act:** Creates an OCI ClusterRepo for the registry root with the default refresh interval.

**Assert:**
- Checks the `OCIDownloaded` condition becomes False with the retry count back at 0.
- Checks the partial index has 2 charts, with 2 `testingchart` versions that have digests.
- Checks the repo later sets `OCIDownloaded` True with 0 retries.
- Checks the full index has 2 versions each of `testchart` and `testingchart`, with digests.
- Checks the repo is gone after deleting it.

## `TestOCIRepoMultipleChartRepos`
**Arrange:**
- Starts a local OCI registry and pushes `testingchart` 0.1.0 to 300 repositories (`rancher/testingchart-0` through `rancher/testingchart-299`).

**Act 1:** Creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart-0`.
**Assert 1:**
- Checks the repo downloads and its status URL is the first URL.

**Act 2:** Updates the URL to `oci://<registry>/rancher/testingchart-0:0.1.0`.
**Assert 2:**
- Checks the URL change triggers a new download, the status URL becomes the tagged URL, and the observed generation increases.

**Act 3:** Deletes the ClusterRepo.
**Assert 3:**
- Checks the repo is gone.

## `TestOCIRepoWithOptions`
**Arrange:**
- Starts a local OCI registry with `testingchart` 0.1.0 and 1.0.0 pushed.

**Act 1:** Creates an OCI ClusterRepo for `oci://<registry>/rancher/testingchart` with tag filter `< 1.0.0`.
**Assert 1:**
- Checks the repo downloads and the index only has `testingchart` versions matching `< 1.0.0` (1 version).

**Act 2:** Enables `DownloadAllTags` while keeping the tag filter.
**Assert 2:**
- Checks the index still has only 1 `testingchart` version.

**Act 3:** Removes the tag filter, leaving `DownloadAllTags` enabled.
**Assert 3:**
- Checks the index now has both `testingchart` versions.

**Act 4:** Deletes the ClusterRepo.
**Assert 4:**
- Checks the repo is gone.

## `TestOCIRepoChartInstallation`
**Arrange:**
- Starts a local OCI registry with `testingchart` 0.1.0 pushed, creates an OCI ClusterRepo for `oci://<registry>/rancher`, and waits for it to download.

**Act 1:** Installs `testingchart` 0.1.0 from the repo as release `testreleasename` in `default`.
**Assert 1:**
- Checks the app reaches `deployed`.
- Checks the app has the `catalog.cattle.io/cluster-repo-name` label set to the ClusterRepo's name.

**Act 2:** Uninstalls the chart.
**Assert 2:**
- Checks the app is deleted.

**Act 3:** Deletes the ClusterRepo twice.
**Assert 3:**
- Checks the second delete fails because the repo is already gone.

## `TestOCIEnableRepo`
**Arrange:**
- Starts a local OCI registry with `testingchart` 0.1.0 pushed, creates an OCI ClusterRepo for `oci://<registry>/rancher`, and waits for it to download.

**Act 1:** Disables the ClusterRepo, pushes `testchart` 1.0.0, then force-refreshes it.
**Assert 1:**
- Checks the index still has only 1 chart, since the repo is disabled.

**Act 2:** Enables the ClusterRepo and force-refreshes it again.
**Assert 2:**
- Checks the index now has 2 charts.

**Act 3:** Deletes the ClusterRepo twice.
**Assert 3:**
- Checks the second delete fails because the repo is already gone.
