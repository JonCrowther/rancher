# `skip_schema_validation_test.go` Summary

Verifies that the `SkipSchemaValidation` option on a chart install or upgrade is passed through to the helm command Rancher runs.

## `TestInstallChartWithSkipSchemaValidation`
**Act:** Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 from the suite's charts-small-fork ClusterRepo into `cattle-system` with `SkipSchemaValidation` enabled.

**Assert:**
- Checks the app reaches `deployed`.
- Checks the newest operation for the release ran a helm command containing `--skip-schema-validation=true`.
- Checks the app is removed or reaches `uninstalled` after an uninstall.

## `TestUpgradeChartWithSkipSchemaValidation`
**Arrange:**
- Installs `rancher-aks-operator-crd` 104.0.2+up1.9.0 normally, without `SkipSchemaValidation`.

**Act:** Upgrades the release to the same version with `SkipSchemaValidation` enabled.

**Assert:**
- Checks the upgrade reaches `deployed` as a new app revision.
- Checks the newest operation for the release (the upgrade) ran a helm command containing `--skip-schema-validation=true`.
- Checks the app is removed or reaches `uninstalled` after an uninstall.
