package charts

import (
	"context"
	"slices"
	"time"

	rv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/shepherd/pkg/api/steve/catalog/types"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubernetes/pkg/util/taints"
)

var defaultPodTolerations = []v1.Toleration{
	{
		Key:      "cattle.io/os",
		Operator: v1.TolerationOpEqual,
		Value:    "linux",
		Effect:   "NoSchedule",
	},
	{
		Key:      "node-role.kubernetes.io/controlplane",
		Operator: v1.TolerationOpEqual,
		Value:    "true",
		Effect:   "NoSchedule",
	},
	{
		Key:      "node-role.kubernetes.io/control-plane",
		Operator: v1.TolerationOpExists,
		Effect:   "NoSchedule",
	},
	{
		Key:      "node-role.kubernetes.io/etcd",
		Operator: v1.TolerationOpExists,
		Effect:   "NoExecute",
	},
	{
		Key:      "node.cloudprovider.kubernetes.io/uninitialized",
		Operator: v1.TolerationOpEqual,
		Value:    "true",
		Effect:   "NoSchedule",
	},
}

var testTaint = v1.Taint{
	Key:    "testTaint",
	Value:  "testValue",
	Effect: v1.TaintEffectPreferNoSchedule,
}

// taintControlPlane adds testTaint to the control plane node and registers a cleanup that removes it.
func (w *ChartsTestSuite) taintControlPlane(ctx context.Context) {
	w.Require().NoError(w.updateTaintOnNode(ctx, testTaint, taints.AddOrUpdateTaint))
	t := w.T()
	t.Cleanup(func() {
		assert.NoError(t, w.updateTaintOnNode(context.Background(), testTaint, taints.RemoveTaint), "failed to remove %s from the control plane node", testTaint.Key)
	})
}

// updateTaintOnNode updates the taint on the control plane node according to the taintFunc received
func (w *ChartsTestSuite) updateTaintOnNode(ctx context.Context, taint v1.Taint, taintFunc func(node *v1.Node, taint *v1.Taint) (*v1.Node, bool, error)) error {
	return retry.RetryOnConflict(w.backoff, func() error {
		list, err := w.corev1.Nodes().List(ctx, metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/control-plane=true"})
		if err != nil {
			return err
		}
		if len(list.Items) == 0 {
			return apierrors.NewNotFound(v1.Resource("nodes"), "node-role.kubernetes.io/control-plane=true")
		}
		node := list.Items[0]
		n, b, err := taintFunc(&node, &taint)
		if err != nil {
			return err
		}
		if b {
			_, err = w.corev1.Nodes().Update(ctx, n, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// operationPodTolerations returns the tolerations on the pod of the latest Operation for rancher-aks-operator-crd.
func (w *ChartsTestSuite) operationPodTolerations(ctx context.Context) []v1.Toleration {
	op, err := w.latestOperation(ctx, "rancher-aks-operator-crd")
	w.Require().NoError(err)
	pod, err := w.corev1.Pods(op.Status.PodNamespace).Get(ctx, op.Status.PodName, metav1.GetOptions{})
	w.Require().NoError(err)
	return pod.Spec.Tolerations
}

func hasTestTaintToleration(tolerations []v1.Toleration) bool {
	return slices.ContainsFunc(tolerations, func(tol v1.Toleration) bool { return tol.Key == testTaint.Key })
}

// TestInstallChartWithAutomaticTolerationOnTaintedCPNode tests the installation of a chart with automatic CP toleration on a tainted control plane node
func (w *ChartsTestSuite) TestInstallChartWithAutomaticTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   true,
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

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)
}

// TestInstallChartWithCustomTolerationOnTaintedCPNode tests the installation of a chart with custom toleration on a tainted control plane node
func (w *ChartsTestSuite) TestInstallChartWithCustomTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
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

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)
}

// TestUpgradeChartWithCustomTolerationOnTaintedCPNode tests the upgrade of a chart with custom toleration on a tainted control plane node
func (w *ChartsTestSuite) TestUpgradeChartWithCustomTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	//install chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
		Charts: []types.ChartInstall{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.1+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be deployed")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)

	//upgrade chart
	w.Require().NoError(w.catalogClient.UpgradeChart(&types.ChartUpgradeAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
		Charts: []types.ChartUpgrade{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 1
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd upgrade to be deployed")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "upgrade operation pod is missing the %s toleration", testTaint.Key)
}

// TestUpgradeChartWithAutomaticTolerationOnTaintedCPNode tests the upgrade of a chart with automatic CP toleration on a tainted control plane node
func (w *ChartsTestSuite) TestUpgradeChartWithAutomaticTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	//install chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
		Charts: []types.ChartInstall{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.1+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be deployed")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)

	//upgrade chart
	w.Require().NoError(w.catalogClient.UpgradeChart(&types.ChartUpgradeAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   true,
		Charts: []types.ChartUpgrade{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 1
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd upgrade to be deployed")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "upgrade operation pod is missing the %s toleration", testTaint.Key)
}

// TestUpgradeChartInstalledWithoutTolerationsUsingAutomaticTolerations tests the upgrade of a chart that was installed without automatic tolerations
// with automatic CP toleration on a tainted control plane node enabled for the upgrade
func (w *ChartsTestSuite) TestUpgradeChartInstalledWithoutTolerationsUsingAutomaticTolerations() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")

	//install chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		Charts: []types.ChartInstall{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.1+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be deployed")

	tolerations := w.operationPodTolerations(ctx)
	for _, toleration := range defaultPodTolerations {
		w.Require().Contains(tolerations, toleration)
	}

	//add taint to node
	w.taintControlPlane(ctx)

	//upgrade chart
	w.Require().NoError(w.catalogClient.UpgradeChart(&types.ChartUpgradeAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   true,
		Charts: []types.ChartUpgrade{{
			ChartName:   "rancher-aks-operator-crd",
			Version:     "104.0.2+up1.9.0",
			ReleaseName: "rancher-aks-operator-crd",
			Description: "rancher aks operator crd",
		}},
	}, w.repoName))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 1
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd upgrade to be deployed")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "upgrade operation pod is missing the %s toleration", testTaint.Key)
}

// TestUninstallChartWithAutomaticTolerationOnTaintedCPNode tests the uninstallation of a chart with automatic CP toleration on a tainted control plane node
func (w *ChartsTestSuite) TestUninstallChartWithAutomaticTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	//install chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
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

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)

	//uninstall chart
	w.Require().NoError(w.catalogClient.UninstallChart("rancher-aks-operator-crd", namespace.System, &types.ChartUninstallAction{
		DisableHooks:           false,
		Timeout:                &metav1.Duration{Duration: 60 * time.Second},
		AutomaticCPTolerations: true,
	}))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return apierrors.IsNotFound(err) || (err == nil && app.Spec.Info.Status == rv1.StatusUninstalled)
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be uninstalled")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "uninstall operation pod is missing the %s toleration", testTaint.Key)
}

// TestUninstallChartWithCustomTolerationOnTaintedCPNode tests the uninstallation of a chart with custom toleration on a tainted control plane node
func (w *ChartsTestSuite) TestUninstallChartWithCustomTolerationOnTaintedCPNode() {
	ctx := context.Background()
	w.uninstallOnCleanup(namespace.System, "rancher-aks-operator-crd")
	w.taintControlPlane(ctx)

	//install chart
	w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
		DisableHooks:             false,
		Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
		Wait:                     true,
		Namespace:                namespace.System,
		DisableOpenAPIValidation: false,
		AutomaticCPTolerations:   false,
		OperationTolerations:     []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
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

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "install operation pod is missing the %s toleration", testTaint.Key)

	//uninstall chart
	w.Require().NoError(w.catalogClient.UninstallChart("rancher-aks-operator-crd", namespace.System, &types.ChartUninstallAction{
		DisableHooks:           false,
		Timeout:                &metav1.Duration{Duration: 60 * time.Second},
		AutomaticCPTolerations: false,
		OperationTolerations:   []v1.Toleration{{Key: "testTaint", Effect: v1.TaintEffectNoSchedule, Value: "testValue"}},
	}))

	w.Require().Eventually(func() bool {
		app, err := w.catalogClient.Apps(namespace.System).Get(ctx, "rancher-aks-operator-crd", metav1.GetOptions{})
		return apierrors.IsNotFound(err) || (err == nil && app.Spec.Info.Status == rv1.StatusUninstalled)
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator-crd to be uninstalled")

	w.Require().True(hasTestTaintToleration(w.operationPodTolerations(ctx)), "uninstall operation pod is missing the %s toleration", testTaint.Key)
}
