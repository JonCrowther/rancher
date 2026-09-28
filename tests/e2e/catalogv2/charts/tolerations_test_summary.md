# `tolerations_test.go` Summary

Verifies that the helm operation pods Rancher runs to install, upgrade, and uninstall a chart get tolerations for a tainted control-plane node, either from automatic CP tolerations or from custom operation tolerations.

## `TestInstallChartWithAutomaticTolerationOnTaintedCPNode`
Adds a `testTaint=testValue:PreferNoSchedule` taint to the control-plane node, then installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 from a charts-small-fork ClusterRepo into `cattle-system` with automatic CP tolerations enabled.
- Checks the app reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

## `TestInstallChartWithCustomTolerationOnTaintedCPNode`
Taints the control-plane node with `testTaint`, then installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with automatic CP tolerations disabled and a custom operation toleration for `testTaint`.
- Checks the app reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

## `TestUpgradeChartWithCustomTolerationOnTaintedCPNode`
Taints the control-plane node with `testTaint`, installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 with a custom `testTaint` toleration, then upgrades it to 104.0.2+up1.9.0 with the same custom toleration.
- Checks the install reaches `deployed` and its operation pod tolerates `testTaint`.
- Checks the upgrade reaches `deployed` as a new app revision and its operation pod tolerates `testTaint`.

## `TestUpgradeChartWithAutomaticTolerationOnTaintedCPNode`
Taints the control-plane node with `testTaint`, installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 with a custom `testTaint` toleration, then upgrades it to 104.0.2+up1.9.0 with automatic CP tolerations and no custom tolerations.
- Checks the install reaches `deployed` and its operation pod tolerates `testTaint`.
- Checks the upgrade reaches `deployed` as a new app revision and its operation pod tolerates `testTaint`.

## `TestUpgradeChartInstalledWithoutTolerationsUsingAutomaticTolerations`
Installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 on an untainted node with no automatic or custom tolerations, then taints the control-plane node with `testTaint` and upgrades to 104.0.2+up1.9.0 with automatic CP tolerations enabled.
- Checks the install reaches `deployed` and its operation pod has the 5 default operation tolerations (`cattle.io/os=linux`, `node-role.kubernetes.io/controlplane=true`, `node-role.kubernetes.io/control-plane`, `node-role.kubernetes.io/etcd`, `node.cloudprovider.kubernetes.io/uninitialized=true`).
- Checks the upgrade reaches `deployed` as a new app revision and its operation pod tolerates `testTaint`.

## `TestUninstallChartWithAutomaticTolerationOnTaintedCPNode`
Taints the control-plane node with `testTaint`, installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with a custom `testTaint` toleration, then uninstalls it with automatic CP tolerations enabled.
- Checks the install reaches `deployed` and its operation pod tolerates `testTaint`.
- Checks the app is removed or reaches `uninstalled`.
- Checks the uninstall operation pod tolerates `testTaint`.

## `TestUninstallChartWithCustomTolerationOnTaintedCPNode`
Taints the control-plane node with `testTaint`, installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with a custom `testTaint` toleration, then uninstalls it with the same custom toleration and automatic CP tolerations disabled.
- Checks the install reaches `deployed` and its operation pod tolerates `testTaint`.
- Checks the app is removed or reaches `uninstalled`.
- Checks the uninstall operation pod tolerates `testTaint`.
