# `rancher_managed_charts_test.go` Summary

Verifies that giving the local cluster an AKS config makes Rancher install and keep auto-upgrading the managed `rancher-aks-operator` chart from the `rancher-charts` repo without user-supplied values, without retrying failed installs/upgrades repeatedly, and that Rancher serves chart icons from a prebuilt repo (with the suite setting `system-managed-charts-operation-timeout` to 50s and `system-feature-chart-refresh-seconds` to 21600 for the whole file, and resetting the local cluster's AKS config, the `rancher-charts` repo, and the AKS operator releases after each test).

## `TestInstallChartLatestVersion`
**Arrange:**
- Points the `rancher-charts` ClusterRepo at `rancher/charts-small-fork` branch `aks-integration-test-working-charts` and waits for it to download.

**Act:** Gives the local cluster an empty AKS config.

**Assert:**
- Checks `rancher-aks-operator` is deployed in `cattle-system` at version 104.0.2+up1.9.0.
- Checks that version matches the latest `rancher-aks-operator` version in `rancher-charts`.
- Checks the app has no user values and no chart values.

## `TestUpgradeChartToLatestVersion`
**Arrange:**
- Points `rancher-charts` at branch `aks-integration-test-working-charts` and waits for it to download.
- Removes the newest `rancher-aks-operator` entry from the repo's index ConfigMap.

**Act 1:** Gives the local cluster an empty AKS config.
**Assert 1:**
- Checks `rancher-aks-operator` is deployed at 104.0.1+up1.9.0, older than the removed version, with no values.

**Act 2:** Restores the index ConfigMap to its original content and force-refreshes the repo.
**Assert 2:**
- Checks the app is automatically upgraded to the restored latest version, reaches `deployed`, and still has no values.

## `TestUpgradeToWorkingVersion`
**Arrange:**
- Starts with the local cluster having no AKS config and `rancher-aks-operator` not installed.
- Points `rancher-charts` at branch `aks-integration-test-1` (whose current latest version fails to install) and waits for it to download.
- Removes the newest `rancher-aks-operator` entry from the index ConfigMap.

**Act 1:** Gives the local cluster an empty AKS config.
**Assert 1:**
- Checks `rancher-aks-operator` reaches `failed`, with no values.
- Checks at most 2 install operations are created for the failing version, so Rancher doesn't keep retrying.

**Act 2:** Restores the index ConfigMap to its original content and force-refreshes the repo.
**Assert 2:**
- Checks the app is automatically upgraded to the restored latest version, reaches `deployed`, with no values.

## `TestUpgradeToBrokenVersion`
**Arrange:**
- Points `rancher-charts` at branch `aks-integration-test-2` (whose current latest version later fails to install) and waits for it to download.
- Removes the newest `rancher-aks-operator` entry from the index ConfigMap.

**Act 1:** Gives the local cluster an empty AKS config.
**Assert 1:**
- Checks `rancher-aks-operator` is first deployed at 102.0.0+up1.1.0, with no values.

**Act 2:** Restores the index ConfigMap to its original content and force-refreshes the repo.
**Assert 2:**
- Checks the automatic upgrade to the restored (broken) latest version creates a new app revision that reaches `failed`, still with no values.
- Checks at most 2 operations are created for the failed upgrade, so Rancher doesn't keep retrying.

## `TestServeIcons`
**Arrange:**
- Clones `rancher/charts-small-fork` into Rancher's local catalog directory under the fixed path for ClusterRepo `rancher-charts-small-fork`, so Rancher treats it as a prebuilt repo.
- Creates that ClusterRepo on branch `main` and waits for it to download.
- Changes the `system-catalog` setting from `external` to `bundled`.

**Act:** Fetches the `rancher-compliance` chart icon, which uses a `file://` path, from the prebuilt repo.

**Assert:**
- Checks the repo downloads and has more than 1 chart.
- Checks `system-catalog` started as `external` before the change.
- Checks the icon is returned with a non-empty body.
