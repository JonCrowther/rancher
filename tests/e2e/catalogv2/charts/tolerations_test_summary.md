# `tolerations_test.go` Summary

Verifies that the helm operation pods Rancher runs to install, upgrade, and uninstall a chart receive tolerations for a tainted control-plane node, either from automatic CP tolerations or from custom operation tolerations.

## `TestInstallChartWithAutomaticTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint=testValue:PreferNoSchedule`.

**Act:** Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 into `cattle-system` with automatic CP tolerations enabled.

**Assert:**
- Checks the app reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

## `TestInstallChartWithCustomTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint`.

**Act:** Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with automatic CP tolerations disabled and a custom operation toleration for `testTaint`.

**Assert:**
- Checks the app reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

## `TestUpgradeChartWithCustomTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint`.

**Act 1:** Installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 with automatic CP tolerations disabled and a custom operation toleration for `testTaint`.
**Assert 1:**
- Checks the install reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

**Act 2:** Upgrades the release to 104.0.2+up1.9.0 with the same custom `testTaint` toleration.
**Assert 2:**
- Checks the upgrade reaches `deployed` as a new app revision.
- Checks the upgrade operation pod tolerates `testTaint`.

## `TestUpgradeChartWithAutomaticTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint`.

**Act 1:** Installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 with automatic CP tolerations disabled and a custom operation toleration for `testTaint`.
**Assert 1:**
- Checks the install reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

**Act 2:** Upgrades the release to 104.0.2+up1.9.0 with automatic CP tolerations enabled and no custom tolerations.
**Assert 2:**
- Checks the upgrade reaches `deployed` as a new app revision.
- Checks the upgrade operation pod tolerates `testTaint`.

## `TestUpgradeChartInstalledWithoutTolerationsUsingAutomaticTolerations`
**Act 1:** Installs `rancher-aks-operator-crd` 104.0.1+up1.9.0 on an untainted node with no automatic or custom tolerations.
**Assert 1:**
- Checks the install reaches `deployed`.
- Checks the install operation pod has the 5 default operation tolerations (`cattle.io/os=linux`, `node-role.kubernetes.io/controlplane=true`, `node-role.kubernetes.io/control-plane`, `node-role.kubernetes.io/etcd`, `node.cloudprovider.kubernetes.io/uninitialized=true`).

**Act 2:** Taints the control-plane node with `testTaint`, then upgrades the release to 104.0.2+up1.9.0 with automatic CP tolerations enabled.
**Assert 2:**
- Checks the upgrade reaches `deployed` as a new app revision.
- Checks the upgrade operation pod tolerates `testTaint`.

## `TestUninstallChartWithAutomaticTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint`.

**Act 1:** Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with a custom `testTaint` toleration (automatic CP tolerations disabled).
**Assert 1:**
- Checks the install reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

**Act 2:** Uninstalls the chart with automatic CP tolerations enabled.
**Assert 2:**
- Checks the app is removed or reaches `uninstalled`.
- Checks the uninstall operation pod tolerates `testTaint`.

## `TestUninstallChartWithCustomTolerationOnTaintedCPNode`
**Arrange:**
- Taints the control-plane node with `testTaint`.

**Act 1:** Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 with a custom `testTaint` toleration.
**Assert 1:**
- Checks the install reaches `deployed`.
- Checks the install operation pod tolerates `testTaint`.

**Act 2:** Uninstalls the chart with the same custom `testTaint` toleration and automatic CP tolerations disabled.
**Assert 2:**
- Checks the app is removed or reaches `uninstalled`.
- Checks the uninstall operation pod tolerates `testTaint`.
