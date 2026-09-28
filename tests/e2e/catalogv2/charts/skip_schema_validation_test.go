package charts

import (
	"context"
	"time"

	rv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/shepherd/pkg/api/steve/catalog/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestInstallChartWithSkipSchemaValidation tests the installation of a chart with skipSchemaValidation enabled
func (w *ChartsTestSuite) TestInstallChartWithSkipSchemaValidation() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")

	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		SkipSchemaValidation:     true,
		Charts: []types.ChartInstall{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be deployed")

	op, err := w.latestOperation(ctx, "rancher-aks-operator-crd")
	w.Require().NoError(err)
	w.Require().Contains(op.Status.Command, "--skip-schema-validation=true")

	//uninstall chart
	w.Require().NoError(w.catalogClient.UninstallChart("rancher-aks-operator-crd", namespace.System, &types.ChartUninstallAction{
		DisableHooks: false,
		Timeout:      &metav1.Duration{Duration: 60 * time.Second},
	}))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return apierrors.IsNotFound(err) || (err == nil && app.Spec.Info.Status == rv1.StatusUninstalled)
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be uninstalled")
}

// TestUpgradeChartWithSkipSchemaValidation tests the upgrade of a chart with skipSchemaValidation enabled
func (w *ChartsTestSuite) TestUpgradeChartWithSkipSchemaValidation() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")

	// Install initial version of the chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		Charts: []types.ChartInstall{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be deployed")

	// Upgrade the chart with SkipSchemaValidation set to true
	w.Require().NoError(w.catalogClient.UpgradeChart(&types.ChartUpgradeAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		SkipSchemaValidation:     true,
		Charts: []types.ChartUpgrade{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd upgrade",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 1
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd upgrade to be deployed")

	op, err := w.latestOperation(ctx, "rancher-aks-operator-crd")
	w.Require().NoError(err)
	w.Require().Contains(op.Status.Command, "--skip-schema-validation=true")

	//uninstall chart
	w.Require().NoError(w.catalogClient.UninstallChart("rancher-aks-operator-crd", namespace.System, &types.ChartUninstallAction{
		DisableHooks: false,
		Timeout:      &metav1.Duration{Duration: 60 * time.Second},
	}))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return apierrors.IsNotFound(err) || (err == nil && app.Spec.Info.Status == rv1.StatusUninstalled)
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be uninstalled")
}
