package uiplugin

import (
	"context"
	"fmt"
	"testing"
	"time"

	rv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	"github.com/rancher/shepherd/extensions/kubeconfig"
	"github.com/rancher/shepherd/pkg/api/steve/catalog/types"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/kube"
	release "helm.sh/helm/v4/pkg/release/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

var (
	PollInterval = time.Duration(500 * time.Millisecond)
	propagation  = metav1.DeletePropagationForeground
)

type UIPluginTestSuite struct {
	suite.Suite
	client           *rancher.Client
	session          *session.Session
	restClientGetter genericclioptions.RESTClientGetter
	catalogClient    *catalog.Client
	corev1           corev1.CoreV1Interface
	clusterID        string // cluster under test; "local" is Rancher's own cluster, not a downstream
	repoName         string // suite-shared ClusterRepo serving the ui-plugin-examples charts
}

func (w *UIPluginTestSuite) SetupSuite() {
	w.clusterID = "local"
	ctx := context.Background()
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
	cset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(w.T(), err)
	w.corev1 = cset.CoreV1()

	w.restClientGetter, err = kubeconfig.NewRestGetter(restConfig, *kubeConfig)
	require.NoError(w.T(), err)

	w.repoName = namegen.AppendRandomString("extensions-examples")
	_, err = w.catalogClient.ClusterRepos().Create(ctx, &rv1.ClusterRepo{
		ObjectMeta: metav1.ObjectMeta{Name: w.repoName},
		Spec:       rv1.RepoSpec{GitRepo: "https://github.com/rancher/ui-plugin-examples", GitBranch: "main"},
	}, metav1.CreateOptions{})
	w.Require().NoError(err)
	// The catalog client doesn't register its creates with the session, so register the delete here.
	w.session.RegisterCleanupFunc(func() error {
		err := w.catalogClient.ClusterRepos().Delete(context.Background(), w.repoName, metav1.DeleteOptions{PropagationPolicy: &propagation})
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	})
	w.Require().NoError(w.pollUntilDownloaded(w.repoName, metav1.Time{}))

	plugins := []types.ChartInstall{
		{ChartName: "uk-locale", Version: "0.1.1", ReleaseName: "uk-locale", Description: "locale"},
		{ChartName: "clock", Version: "0.2.0", ReleaseName: "clock", Description: "clock"},
		{
			ChartName:   "top-level-product",
			Version:     "0.1.0",
			ReleaseName: "top-level-product",
			Description: "top-level-product",
			Values: map[string]interface{}{
				"plugin": map[string]interface{}{
					"noCache": true,
				},
			},
		},
		{ChartName: "homepage", Version: "0.4.1", ReleaseName: "homepage", Description: "homepage"},
	}
	for _, plugin := range plugins {
		w.Require().NoError(w.catalogClient.InstallChart(&types.ChartInstallAction{
			DisableHooks:             false,
			Timeout:                  &metav1.Duration{Duration: 60 * time.Second},
			Wait:                     true,
			Namespace:                namespace.UIPluginNamespace,
			DisableOpenAPIValidation: false,
			Charts:                   []types.ChartInstall{plugin},
		}, w.repoName))
		w.session.RegisterCleanupFunc(func() error {
			return w.uninstallApp(namespace.UIPluginNamespace, plugin.ChartName)
		})
		w.Require().Eventually(func() bool {
			app, err := w.catalogClient.Apps(namespace.UIPluginNamespace).Get(ctx, plugin.ReleaseName, metav1.GetOptions{})
			return err == nil && app.Spec.Info.Status == rv1.StatusDeployed
		}, 6*time.Minute, PollInterval, "waiting for %s to be deployed", plugin.ReleaseName)
	}

	// The plugin controller adds a plugin to the served index once it has synced it, which it
	// reports by marking the UIPlugin ready for its current generation.
	for _, plugin := range plugins {
		w.Require().Eventually(func() bool {
			p, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(ctx, plugin.ReleaseName, metav1.GetOptions{})
			return err == nil && p.Status.ObservedGeneration == p.Generation && p.Status.Ready
		}, 2*time.Minute, PollInterval, "waiting for UIPlugin %s to be ready", plugin.ReleaseName)
	}
}

func (w *UIPluginTestSuite) TearDownSuite() {
	w.session.Cleanup()
}

func TestUIPluginTestSuite(t *testing.T) {
	suite.Run(t, new(UIPluginTestSuite))
}

func (w *UIPluginTestSuite) uninstallApp(namespace, chartName string) error {
	var cfg action.Configuration
	if err := cfg.Init(w.restClientGetter, namespace, ""); err != nil {
		return err
	}
	l := action.NewList(&cfg)
	l.All = true
	l.SetStateMask()
	releases, err := l.Run()
	if err != nil {
		return fmt.Errorf("failed to fetch all releases in the %s namespace: %w", namespace, err)
	}
	for _, r := range releases {
		rel, ok := r.(*release.Release)
		if !ok || rel.Chart.Name() != chartName {
			continue
		}
		err = kwait.Poll(10*time.Second, time.Minute, func() (done bool, err error) {
			act := action.NewUninstall(&cfg)
			act.WaitStrategy = kube.StatusWatcherStrategy
			act.Timeout = time.Minute
			if _, err = act.Run(rel.Name); err != nil {
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			return fmt.Errorf("failed to uninstall release %s: %w", rel.Name, err)
		}
	}
	return nil
}

// pollUntilDownloaded Polls until the ClusterRepo of the given name has been downloaded (by comparing prevDownloadTime against the current DownloadTime)
func (w *UIPluginTestSuite) pollUntilDownloaded(ClusterRepoName string, prevDownloadTime metav1.Time) error {
	err := kwait.Poll(PollInterval, time.Minute, func() (done bool, err error) {
		clusterRepo, err := w.catalogClient.ClusterRepos().Get(context.TODO(), ClusterRepoName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if clusterRepo.Name != ClusterRepoName {
			return false, nil
		}

		return clusterRepo.Status.DownloadTime != prevDownloadTime, nil
	})
	return err
}
