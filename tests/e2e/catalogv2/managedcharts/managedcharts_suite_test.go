package managedcharts

import (
	"context"
	"fmt"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	stevev1 "github.com/rancher/shepherd/clients/rancher/v1"
	"github.com/rancher/shepherd/extensions/kubeconfig"
	"github.com/rancher/shepherd/pkg/api/steve/catalog/types"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type RancherManagedChartsTestSuite struct {
	suite.Suite
	client           *rancher.Client
	session          *session.Session
	restClientGetter genericclioptions.RESTClientGetter
	catalogClient    *catalog.Client
	corev1           corev1.CoreV1Interface
	clusterID        string // cluster under test; "local" is Rancher's own cluster, not a downstream
	originalBranch   string
	originalGitRepo  string
	originalSettings map[string]string // values of the settings SetupSuite changes, restored in TearDownSuite
}

func (w *RancherManagedChartsTestSuite) SetupSuite() {
	w.clusterID = "local"
	var err error
	testSession := session.NewSession()
	w.session = testSession
	w.client, err = rancher.NewClient("", testSession)
	require.NoError(w.T(), err)
	insecure := true
	w.client.RancherConfig.Insecure = &insecure
	w.catalogClient, err = w.client.GetClusterCatalogClient(w.clusterID)
	require.NoError(w.T(), err)

	kubeConfig, err := kubeconfig.GetKubeconfig(w.client, w.clusterID)
	require.NoError(w.T(), err)

	restConfig, err := (*kubeConfig).ClientConfig()
	require.NoError(w.T(), err)
	//restConfig.Insecure = true
	cset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(w.T(), err)
	w.corev1 = cset.CoreV1()

	w.restClientGetter, err = kubeconfig.NewRestGetter(restConfig, *kubeConfig)
	require.NoError(w.T(), err)

	settings := map[string]string{
		"system-managed-charts-operation-timeout": "50s",
		"system-feature-chart-refresh-seconds":    "21600",
	}
	w.originalSettings = map[string]string{}
	for name, value := range settings {
		original, err := w.settingValue(name)
		w.Require().NoError(err)
		w.originalSettings[name] = original
		w.Require().NoError(w.updateSetting(name, value))
	}

	clusterRepo, err := w.catalogClient.ClusterRepos().Get(context.TODO(), "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	w.originalBranch = clusterRepo.Spec.GitBranch
	w.originalGitRepo = clusterRepo.Spec.GitRepo
	w.Require().NoError(w.resetManagementCluster())
	w.Require().NoError(w.uninstallAKSOperator())
}

func (w *RancherManagedChartsTestSuite) TearDownSuite() {
	w.session.Cleanup()
	for name, value := range w.originalSettings {
		w.Assert().NoError(w.updateSetting(name, value), "failed to restore setting %s", name)
	}
}

func TestRancherManagedChartsTestSuite(t *testing.T) {
	suite.Run(t, new(RancherManagedChartsTestSuite))
}

// resetManagementCluster removes the AKS config from the local cluster and waits for it to be gone.
func (w *RancherManagedChartsTestSuite) resetManagementCluster() error {
	c, err := w.client.Management.Cluster.ByID(w.clusterID)
	if err != nil {
		return err
	}
	c.AKSConfig = nil
	c.AppliedSpec.AKSConfig = nil
	if _, err := w.client.Management.Cluster.Replace(c); err != nil {
		return err
	}
	return kwait.Poll(5*time.Second, 2*time.Minute, func() (done bool, err error) {
		c, err = w.client.Management.Cluster.ByID(w.clusterID)
		if err != nil {
			return false, err
		}
		return c.AKSConfig == nil, nil
	})
}

// uninstallAKSOperator uninstalls both AKS operator releases and makes sure they stay gone. Rancher's
// system-charts manager can reinstall the operator from Ensure calls it queued while the local cluster
// still had an AKS config, so after each uninstall this watches for a reinstall and uninstalls again.
func (w *RancherManagedChartsTestSuite) uninstallAKSOperator() error {
	charts := []string{"rancher-aks-operator-crd", "rancher-aks-operator"}
	for attempt := 0; attempt < 5; attempt++ {
		for _, chart := range charts {
			if err := w.uninstallApp("cattle-system", chart); err != nil {
				return err
			}
		}
		reinstalled := false
		err := kwait.Poll(2*time.Second, time.Minute, func() (done bool, err error) {
			for _, chart := range charts {
				secrets, err := w.corev1.Secrets("cattle-system").List(context.TODO(), metav1.ListOptions{
					LabelSelector: fmt.Sprintf("name=%s,owner=helm", chart),
				})
				if err != nil {
					return false, err
				}
				if len(secrets.Items) > 0 {
					reinstalled = true
					return true, nil
				}
			}
			return false, nil
		})
		if !reinstalled {
			if kwait.Interrupted(err) {
				return nil
			}
			return err
		}
	}
	return fmt.Errorf("the AKS operator was still being reinstalled after 5 uninstalls")
}

// uninstallApp uninstalls chartName and waits until its helm release secrets are gone. It's a no-op if
// the chart isn't installed.
func (w *RancherManagedChartsTestSuite) uninstallApp(namespace, chartName string) error {
	return kwait.Poll(10*time.Second, 10*time.Minute, func() (done bool, err error) {
		// The uninstall fails once the release is gone, so its error is ignored in favor of the secrets check.
		w.catalogClient.UninstallChart(chartName, namespace, &types.ChartUninstallAction{})

		// Make sure that all helm release secrets are deleted before proceeding.
		helmReleaseSecretLabels := fmt.Sprintf("name=%s,owner=helm", chartName)
		secrets, err := w.corev1.Secrets(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: helmReleaseSecretLabels,
		})
		if err != nil {
			return false, nil
		}
		return len(secrets.Items) == 0, nil
	})
}

// settingValue returns the setting's stored value, which is empty when the setting uses its default.
// The Norman client reports the default in place of an empty value, so restoring what it returns
// would pin the default as an explicit value.
func (w *RancherManagedChartsTestSuite) settingValue(name string) (string, error) {
	existing, err := w.client.Steve.SteveType("management.cattle.io.setting").ByID(name)
	if err != nil {
		return "", err
	}
	var s v3.Setting
	if err := stevev1.ConvertToK8sType(existing.JSONResp, &s); err != nil {
		return "", err
	}
	return s.Value, nil
}

func (w *RancherManagedChartsTestSuite) updateSetting(name, value string) error {
	// Use the Steve client instead of the main one to be able to set a setting's value to an empty string.
	existing, err := w.client.Steve.SteveType("management.cattle.io.setting").ByID(name)
	if err != nil {
		return err
	}

	var s v3.Setting
	if err := stevev1.ConvertToK8sType(existing.JSONResp, &s); err != nil {
		return err
	}

	s.Value = value
	_, err = w.client.Steve.SteveType("management.cattle.io.setting").Update(existing, s)
	return err
}
