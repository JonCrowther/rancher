package charts

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
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/assert"
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

type ChartsTestSuite struct {
	suite.Suite
	client           *rancher.Client
	session          *session.Session
	restClientGetter genericclioptions.RESTClientGetter
	catalogClient    *catalog.Client
	corev1           corev1.CoreV1Interface
	backoff          kwait.Backoff
	clusterID        string // cluster under test; "local" is Rancher's own cluster, not a downstream
	repoName         string // suite-shared ClusterRepo serving the charts-small-fork charts
}

func (w *ChartsTestSuite) SetupSuite() {
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
	cset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(w.T(), err)
	w.corev1 = cset.CoreV1()

	w.restClientGetter, err = kubeconfig.NewRestGetter(restConfig, *kubeConfig)
	require.NoError(w.T(), err)

	w.repoName = namegen.AppendRandomString("charts-small-fork")
	_, err = w.catalogClient.ClusterRepos().Create(context.Background(), &rv1.ClusterRepo{
		ObjectMeta: metav1.ObjectMeta{Name: w.repoName},
		Spec:       rv1.RepoSpec{GitRepo: "https://github.com/rancher/charts-small-fork", GitBranch: "aks-integration-test-working-charts"},
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

	w.backoff = kwait.Backoff{
		Duration: 500 * time.Millisecond,
		Jitter:   0.2,
		Factor:   2,
		Steps:    10,
		Cap:      60 * time.Second,
	}
}

func (w *ChartsTestSuite) TearDownSuite() {
	w.session.Cleanup()
}

func TestChartsTestSuite(t *testing.T) {
	suite.Run(t, new(ChartsTestSuite))
}

// uninstallOnCleanup registers a cleanup that uninstalls chartName, so a test that fails mid-way
// doesn't leave the release behind for the next test's install. It's a no-op if the test already
// uninstalled it.
func (w *ChartsTestSuite) uninstallOnCleanup(namespace, chartName string) {
	t := w.T()
	t.Cleanup(func() {
		assert.NoError(t, w.uninstallApp(namespace, chartName), "failed to uninstall %s", chartName)
	})
}

func (w *ChartsTestSuite) uninstallApp(namespace, chartName string) error {
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

// latestOperation returns the most recently created Operation for the given release in cattle-system.
func (w *ChartsTestSuite) latestOperation(ctx context.Context, releaseName string) (*rv1.Operation, error) {
	list, err := w.catalogClient.Operations(namespace.System).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var latest *rv1.Operation
	for i := range list.Items {
		op := &list.Items[i]
		if op.Status.Release != releaseName {
			continue
		}
		if latest == nil || latest.CreationTimestamp.Before(&op.CreationTimestamp) {
			latest = op
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no operation found for release %s", releaseName)
	}
	return latest, nil
}

// pollUntilDownloaded Polls until the ClusterRepo of the given name has been downloaded (by comparing prevDownloadTime against the current DownloadTime)
func (w *ChartsTestSuite) pollUntilDownloaded(ClusterRepoName string, prevDownloadTime metav1.Time) error {
	err := kwait.Poll(PollInterval, time.Minute, func() (done bool, err error) {
		clusterRepo, err := w.catalogClient.ClusterRepos().Get(context.TODO(), ClusterRepoName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return clusterRepo.Status.DownloadTime != prevDownloadTime, nil
	})
	return err
}
