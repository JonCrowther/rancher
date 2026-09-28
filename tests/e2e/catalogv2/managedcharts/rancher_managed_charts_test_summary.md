# `rancher_managed_charts_test.go` Summary

Verifies that giving the local cluster an AKS config makes Rancher install and keep upgrading the managed `rancher-aks-operator` chart from the `rancher-charts` repo, without values, without retrying failed installs repeatedly, and that Rancher serves chart icons from a prebuilt repo (with the managed-charts operation timeout set to 50s and the feature-chart refresh set to 21600s for the whole file).

## `TestInstallChartLatestVersion`
Points the `rancher-charts` ClusterRepo at `rancher/charts-small-fork` branch `aks-integration-test-working-charts`, then gives the local cluster an empty AKS config.
- Checks `rancher-aks-operator` is deployed in `cattle-system` at version 104.0.2+up1.9.0.
- Checks that version is the latest `rancher-aks-operator` in `rancher-charts`.
- Checks the app has no user values and no chart values.

## `TestUpgradeChartToLatestVersion`
Points `rancher-charts` at the `aks-integration-test-working-charts` branch, removes the latest `rancher-aks-operator` version from its index ConfigMap, gives the local cluster an empty AKS config, then restores the index and force-refreshes the repo.
- Checks `rancher-aks-operator` is first deployed at 104.0.1+up1.9.0, older than the removed latest version.
- Checks the app has no values after the install.
- Checks the app is automatically upgraded to the restored latest version and is deployed.
- Checks the app still has no values after the upgrade.

## `TestUpgradeToWorkingVersion`
With the local cluster starting with no AKS config and `rancher-aks-operator` not installed, points `rancher-charts` at branch `aks-integration-test-1` (whose older version fails to install), removes the latest `rancher-aks-operator` version from the index, gives the local cluster an empty AKS config, then restores the index and force-refreshes the repo.
- Checks `rancher-aks-operator` reaches `failed` with no values.
- Checks at most 2 install operations are created for the failed version, so Rancher doesn't keep retrying.
- Checks the app is automatically upgraded to the restored latest version and is deployed with no values.

## `TestUpgradeToBrokenVersion`
Points `rancher-charts` at branch `aks-integration-test-2` (whose latest version fails to install), removes the latest `rancher-aks-operator` version from the index, gives the local cluster an empty AKS config, then restores the index and force-refreshes the repo.
- Checks `rancher-aks-operator` is first deployed at 102.0.0+up1.1.0 with no values.
- Checks the automatic upgrade to the restored latest version creates a new revision that reaches `failed`, still with no values.
- Checks at most 2 operations are created for the failed upgrade, so Rancher doesn't keep retrying.

## `TestServeIcons`
Clones `rancher/charts-small-fork` into Rancher's local catalog directory for a ClusterRepo named `rancher-charts-small-fork` so Rancher treats it as a prebuilt repo, creates that ClusterRepo on branch `main`, then changes the `system-catalog` setting from `external` to `bundled`.
- Checks the repo downloads and has more than 1 chart.
- Checks `system-catalog` starts as `external`.
- Checks the `rancher-compliance` chart icon, which uses a `file://` path, is served with a non-empty body.
