package managedcharts

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-git/go-git/v5"
	rv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	client "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/stretchr/testify/assert"
	"helm.sh/helm/v4/pkg/repo/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

const smallForkURL = "https://github.com/rancher/charts-small-fork"
const smallForkClusterRepoName = "rancher-charts-small-fork"

var PollInterval = time.Duration(500 * time.Millisecond)

// resetOnCleanup registers a cleanup that puts the local cluster, the rancher-charts repo and the AKS
// operator releases back the way SetupSuite left them, so the next test starts from the same state
// even if this one fails mid-way. The operator is uninstalled last because restoring rancher-charts
// makes Rancher re-run its system chart installs, which can reinstall it.
func (w *RancherManagedChartsTestSuite) resetOnCleanup() {
	t := w.T()
	t.Cleanup(func() {
		assert.NoError(t, w.resetManagementCluster(), "failed to remove the AKS config from the local cluster")
		assert.NoError(t, w.restoreRancherChartsRepo(), "failed to point rancher-charts back at its original repo")
		assert.NoError(t, w.uninstallAKSOperator(), "failed to uninstall the AKS operator")
	})
}

// restoreRancherChartsRepo points the rancher-charts ClusterRepo back at the repo and branch SetupSuite
// recorded, and waits for it to download from there.
func (w *RancherManagedChartsTestSuite) restoreRancherChartsRepo() error {
	var downloadTime metav1.Time
	changed := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		clusterRepo, err := w.catalogClient.ClusterRepos().Get(context.TODO(), "rancher-charts", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if clusterRepo.Spec.GitRepo == w.originalGitRepo && clusterRepo.Spec.GitBranch == w.originalBranch {
			return nil
		}
		clusterRepo.Spec.GitRepo = w.originalGitRepo
		clusterRepo.Spec.GitBranch = w.originalBranch
		downloadTime = clusterRepo.Status.DownloadTime
		_, err = w.catalogClient.ClusterRepos().Update(context.TODO(), clusterRepo, metav1.UpdateOptions{})
		changed = err == nil
		return err
	})
	if err != nil || !changed {
		return err
	}
	return w.pollUntilDownloaded("rancher-charts", downloadTime)
}

func (w *RancherManagedChartsTestSuite) TestInstallChartLatestVersion() {
	w.resetOnCleanup()
	ctx := context.Background()

	clusterRepo, err := w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	clusterRepo.Spec.GitRepo = "https://github.com/rancher/charts-small-fork"
	clusterRepo.Spec.GitBranch = "aks-integration-test-working-charts"
	clusterRepo, err = w.catalogClient.ClusterRepos().Update(ctx, clusterRepo, metav1.UpdateOptions{})
	w.Require().NoError(err)
	downloadTime := clusterRepo.Status.DownloadTime
	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", downloadTime))

	w.Require().NoError(w.updateManagementCluster())
	var app *rv1.App
	w.Require().Eventually(func() bool {
		app, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator to be deployed")
	w.Require().Equal("104.0.2+up1.9.0", app.Spec.Chart.Metadata.Version)

	latest, err := w.catalogClient.GetLatestChartVersion("rancher-aks-operator", catalog.RancherChartRepo)
	w.Require().NoError(err)
	w.Assert().Equal(app.Spec.Chart.Metadata.Version, latest)
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
}

func (w *RancherManagedChartsTestSuite) TestUpgradeChartToLatestVersion() {
	w.resetOnCleanup()
	ctx := context.Background()

	clusterRepo, err := w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	clusterRepo.Spec.GitRepo = "https://github.com/rancher/charts-small-fork"
	clusterRepo.Spec.GitBranch = "aks-integration-test-working-charts"
	clusterRepo, err = w.catalogClient.ClusterRepos().Update(ctx, clusterRepo, metav1.UpdateOptions{})
	w.Require().NoError(err)
	downloadTime := clusterRepo.Status.DownloadTime
	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", downloadTime))

	cfgMap, err := w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Get(context.TODO(), clusterRepo.Status.IndexConfigMapName, metav1.GetOptions{})
	w.Require().NoError(err)
	origCfg := cfgMap.DeepCopy()

	// GETTING INDEX FROM CONFIGMAP AND MODIFYING IT
	originalLatestVersion := w.updateConfigMap(cfgMap)

	//UPDATING THE CONFIGMAP
	cfgMap, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	// Wait for config map to be updated
	w.Require().Eventually(func() bool {
		version, err := w.latestAKSOperatorVersion(clusterRepo.Status.IndexConfigMapNamespace, clusterRepo.Status.IndexConfigMapName)
		return err == nil && version < originalLatestVersion
	}, 3*time.Minute, time.Second, "waiting for the index to drop rancher-aks-operator %s", originalLatestVersion)

	//Updating the cluster
	w.Require().NoError(w.updateManagementCluster())

	var app *rv1.App
	w.Require().Eventually(func() bool {
		app, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator to be deployed")
	w.Require().Equal("104.0.1+up1.9.0", app.Spec.Chart.Metadata.Version)

	w.Assert().Greater(originalLatestVersion, app.Spec.Chart.Metadata.Version)

	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)

	//REVERT CONFIGMAP TO ORIGINAL VALUE
	cfgMap.BinaryData["content"] = origCfg.BinaryData["content"]
	_, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	clusterRepo, err = w.catalogClient.ClusterRepos().Get(context.TODO(), "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)

	prevDownloadTime := clusterRepo.Status.DownloadTime

	clusterRepo.Spec.ForceUpdate = &metav1.Time{Time: time.Now()}
	_, err = w.catalogClient.ClusterRepos().Update(context.TODO(), clusterRepo.DeepCopy(), metav1.UpdateOptions{})
	w.Require().NoError(err)

	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", prevDownloadTime))

	err = kwait.Poll(2*time.Second, 3*time.Minute, func() (done bool, err error) {
		app, err = w.catalogClient.Apps("cattle-system").Get(context.TODO(), "rancher-aks-operator", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Chart.Metadata.Version == originalLatestVersion, nil
	})
	w.Require().NoError(err)
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
}

func (w *RancherManagedChartsTestSuite) TestUpgradeToWorkingVersion() {
	w.resetOnCleanup()
	ctx := context.Background()
	cluster, err := w.client.Management.Cluster.ByID(w.clusterID)
	w.Require().NoError(err)
	w.Require().Nil(cluster.AKSConfig)
	_, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
	w.Require().True(errors.IsNotFound(err), "rancher-aks-operator should not be installed before the test, got err: %v", err)

	clusterRepo, err := w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	clusterRepo.Spec.GitRepo = "https://github.com/rancher/charts-small-fork"
	clusterRepo.Spec.GitBranch = "aks-integration-test-1"
	clusterRepo, err = w.catalogClient.ClusterRepos().Update(ctx, clusterRepo, metav1.UpdateOptions{})
	w.Require().NoError(err)
	downloadTime := clusterRepo.Status.DownloadTime
	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", downloadTime))
	cfgMap, err := w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Get(context.TODO(), clusterRepo.Status.IndexConfigMapName, metav1.GetOptions{})
	w.Require().NoError(err)
	origCfg := cfgMap.DeepCopy()

	// GETTING INDEX FROM CONFIGMAP AND MODIFYING iT
	latestVersion := w.updateConfigMap(cfgMap)
	//UPDATING THE CONFIGMAP
	cfgMap, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	// Wait for config map to be updated
	w.Require().Eventually(func() bool {
		version, err := w.latestAKSOperatorVersion(clusterRepo.Status.IndexConfigMapNamespace, clusterRepo.Status.IndexConfigMapName)
		return err == nil && version < latestVersion
	}, 3*time.Minute, time.Second, "waiting for the index to drop rancher-aks-operator %s", latestVersion)
	list, err := w.catalogClient.Operations("cattle-system").List(ctx, metav1.ListOptions{})
	w.Require().NoError(err)
	numberOfOps := countNumberOfOperations(list, "rancher-aks-operator", time.Now())
	//Updating the cluster
	w.Require().NoError(w.updateManagementCluster())

	var app *rv1.App
	w.Require().Eventually(func() bool {
		app, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusFailed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator to fail")
	at := time.Now().Add(-(2 * PollInterval)).UTC()
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
	list, err = w.catalogClient.Operations("cattle-system").List(ctx, metav1.ListOptions{})
	w.Require().NoError(err)
	w.Require().LessOrEqual(countNumberOfOperations(list, "rancher-aks-operator", at), numberOfOps+2)

	//REVERT CONFIGMAP TO ORIGINAL VALUE
	cfgMap.BinaryData["content"] = origCfg.BinaryData["content"]
	_, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	clusterRepo, err = w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)

	prevDownloadTime := clusterRepo.Status.DownloadTime

	clusterRepo.Spec.ForceUpdate = &metav1.Time{Time: time.Now()}
	_, err = w.catalogClient.ClusterRepos().Update(context.TODO(), clusterRepo.DeepCopy(), metav1.UpdateOptions{})
	w.Require().NoError(err)

	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", prevDownloadTime))

	err = kwait.Poll(2*time.Second, 3*time.Minute, func() (done bool, err error) {
		app, err = w.catalogClient.Apps("cattle-system").Get(context.TODO(), "rancher-aks-operator", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Chart.Metadata.Version == latestVersion, nil
	})
	w.Require().NoError(err)
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
}

func (w *RancherManagedChartsTestSuite) TestUpgradeToBrokenVersion() {
	w.resetOnCleanup()
	ctx := context.Background()

	clusterRepo, err := w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	clusterRepo.Spec.GitRepo = "https://github.com/rancher/charts-small-fork"
	clusterRepo.Spec.GitBranch = "aks-integration-test-2"
	clusterRepo, err = w.catalogClient.ClusterRepos().Update(ctx, clusterRepo, metav1.UpdateOptions{})
	w.Require().NoError(err)

	downloadTime := clusterRepo.Status.DownloadTime
	w.Require().NoError(w.pollUntilDownloaded("rancher-charts", downloadTime))
	cfgMap, err := w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Get(context.TODO(), clusterRepo.Status.IndexConfigMapName, metav1.GetOptions{})
	w.Require().NoError(err)
	origCfg := cfgMap.DeepCopy()

	// GETTING INDEX FROM CONFIGMAP AND MODIFYING iT
	latestVersion := w.updateConfigMap(cfgMap)
	//UPDATING THE CONFIGMAP
	cfgMap, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	// Wait for config map to be updated
	w.Require().Eventually(func() bool {
		version, err := w.latestAKSOperatorVersion(clusterRepo.Status.IndexConfigMapNamespace, clusterRepo.Status.IndexConfigMapName)
		return err == nil && version < latestVersion
	}, 3*time.Minute, time.Second, "waiting for the index to drop rancher-aks-operator %s", latestVersion)

	//Updating the cluster
	w.Require().NoError(w.updateManagementCluster())

	var app *rv1.App
	w.Require().Eventually(func() bool {
		app, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusDeployed && app.Spec.Version > 0
	}, 6*time.Minute, PollInterval, "waiting for rancher-aks-operator to be deployed")
	at := time.Now().Add(-(2 * PollInterval)).UTC()
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
	w.Require().Equal("102.0.0+up1.1.0", app.Spec.Chart.Metadata.Version)

	ops := w.catalogClient.Operations("cattle-system")
	list, err := ops.List(ctx, metav1.ListOptions{})
	w.Require().NoError(err)
	numberOfOps := countNumberOfOperations(list, "rancher-aks-operator", at)

	//REVERT CONFIGMAP TO ORIGINAL VALUE
	cfgMap.BinaryData["content"] = origCfg.BinaryData["content"]
	_, err = w.corev1.ConfigMaps(clusterRepo.Status.IndexConfigMapNamespace).Update(context.TODO(), cfgMap, metav1.UpdateOptions{})
	w.Require().NoError(err)

	clusterRepo, err = w.catalogClient.ClusterRepos().Get(ctx, "rancher-charts", metav1.GetOptions{})
	w.Require().NoError(err)
	clusterRepo.Spec.ForceUpdate = &metav1.Time{Time: time.Now()}
	_, err = w.catalogClient.ClusterRepos().Update(context.TODO(), clusterRepo.DeepCopy(), metav1.UpdateOptions{})
	w.Require().NoError(err)

	previousVersion := app.Spec.Version
	w.Require().Eventually(func() bool {
		app, err = w.catalogClient.Apps("cattle-system").Get(ctx, "rancher-aks-operator", metav1.GetOptions{})
		return err == nil && app.Spec.Info.Status == rv1.StatusFailed && app.Spec.Version > previousVersion
	}, 6*time.Minute, PollInterval, "waiting for the rancher-aks-operator upgrade to fail")
	at = time.Now().Add(-(2 * PollInterval)).UTC()
	w.Require().Nil(app.Spec.Values)
	w.Require().Nil(app.Spec.Chart.Values)
	list, err = ops.List(ctx, metav1.ListOptions{})
	w.Require().NoError(err)
	w.Require().LessOrEqual(countNumberOfOperations(list, "rancher-aks-operator", at), numberOfOps+2)
}

func countNumberOfOperations(ops *rv1.OperationList, name string, at time.Time) int {
	count := 0
	for _, item := range ops.Items {
		if item.Status.Release == name && item.CreationTimestamp.Time.Before(at) {
			count += 1
		}
	}
	return count
}

// latestAKSOperatorVersion returns the newest rancher-aks-operator version in the index stored in the given ConfigMap.
func (w *RancherManagedChartsTestSuite) latestAKSOperatorVersion(namespace, name string) (string, error) {
	cfgMap, err := w.corev1.ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	gz, err := gzip.NewReader(bytes.NewBuffer(cfgMap.BinaryData["content"]))
	if err != nil {
		return "", err
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return "", err
	}
	index := &repo.IndexFile{}
	if err := json.Unmarshal(data, index); err != nil {
		return "", err
	}
	index.SortEntries()
	if len(index.Entries["rancher-aks-operator"]) == 0 {
		return "", fmt.Errorf("no rancher-aks-operator entries in the index in %s/%s", namespace, name)
	}
	return index.Entries["rancher-aks-operator"][0].Version, nil
}

func (w *RancherManagedChartsTestSuite) updateConfigMap(cfgMap *v1.ConfigMap) string {
	gz, err := gzip.NewReader(bytes.NewBuffer(cfgMap.BinaryData["content"]))
	w.Require().NoError(err)
	defer gz.Close()
	data, err := io.ReadAll(gz)
	w.Require().NoError(err)
	index := &repo.IndexFile{}
	w.Require().NoError(json.Unmarshal(data, index))
	index.SortEntries()
	latestVersion := index.Entries["rancher-aks-operator"][0].Version
	index.Entries["rancher-aks-operator"] = index.Entries["rancher-aks-operator"][1:]
	marshal, err := json.Marshal(index)
	w.Require().NoError(err)
	var compressedData bytes.Buffer
	writer := gzip.NewWriter(&compressedData)
	_, err = writer.Write(marshal)
	w.Require().NoError(err)
	w.Require().NoError(writer.Close())
	cfgMap.BinaryData["content"] = compressedData.Bytes()
	return latestVersion
}

// updateManagementCluster gives the local cluster an empty AKS config, which makes Rancher install the AKS operator.
func (w *RancherManagedChartsTestSuite) updateManagementCluster() error {
	c, err := w.client.Management.Cluster.ByID(w.clusterID)
	if err != nil {
		return err
	}
	c.AKSConfig = &client.AKSClusterConfigSpec{}
	_, err = w.client.Management.Cluster.Replace(c)
	return err
}

// pollUntilDownloaded Polls until the ClusterRepo of the given name has been downloaded (by comparing prevDownloadTime against the current DownloadTime)
func (w *RancherManagedChartsTestSuite) pollUntilDownloaded(ClusterRepoName string, prevDownloadTime metav1.Time) error {
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

func (w *RancherManagedChartsTestSuite) TestServeIcons() {
	// Clone the git repository at a spcecific location so
	// that Rancher assumes it as prebuild helm repository.
	// Since Rancher starts at build/testdata, the LocalDir would
	// be build/rancher-data.... Also since this test resides in
	// tests/e2e/catalogv2/managedcharts, the cloneDir would be
	// ../../../../build/rancher-data/...
	// The last path element is derived from the ClusterRepo name, so the name can't be randomized.
	repoURL := "https://github.com/rancher/charts-small-fork"
	cloneDir := "../../../../build/rancher-data/local-catalogs/v2/rancher-charts-small-fork/d39a2f6abd49e537e5015bbe1a4cd4f14919ba1c3353208a7ff6be37ffe00c52"

	err := os.MkdirAll(cloneDir, os.ModePerm)
	w.Require().NoError(err)
	t := w.T()
	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(cloneDir), "failed to remove %s", cloneDir)
	})

	_, err = git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:   repoURL,
		Depth: 1,
	})
	w.Require().NoError(err)

	// Testing: Chart.icon field with (file:// scheme)
	// Create ClusterRepo for charts-small-fork
	clusterRepoToCreate := rv1.NewClusterRepo("", smallForkClusterRepoName,
		rv1.ClusterRepo{
			Spec: rv1.RepoSpec{
				GitRepo:   smallForkURL,
				GitBranch: "main",
			},
		},
	)
	_, err = w.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Create(clusterRepoToCreate)
	w.Require().NoError(err)
	// The session would only delete the repo at the end of the suite, and this test runs again with the same name.
	t.Cleanup(func() {
		err := w.catalogClient.ClusterRepos().Delete(context.Background(), smallForkClusterRepoName, metav1.DeleteOptions{})
		if !errors.IsNotFound(err) {
			assert.NoError(t, err, "failed to delete ClusterRepo %s", smallForkClusterRepoName)
		}
	})
	time.Sleep(1 * time.Second)

	w.Require().NoError(w.pollUntilDownloaded(smallForkClusterRepoName, metav1.Time{}))

	// Get Charts from the ClusterRepo
	smallForkCharts, err := w.catalogClient.GetChartsFromClusterRepo(smallForkClusterRepoName)
	w.Require().NoError(err)
	w.Assert().Greater(len(smallForkCharts), 1)

	// Get the client settings to update settings.SystemCatalog
	systemCatalog, err := w.client.Management.Setting.ByID("system-catalog")
	w.Require().NoError(err)
	w.Assert().Equal("external", systemCatalog.Value)
	originalSystemCatalog, err := w.settingValue("system-catalog")
	w.Require().NoError(err)

	// Update settings.SystemCatalog to bundled
	systemCatalogUpdated, err := w.client.Management.Setting.Update(systemCatalog, map[string]interface{}{"value": "bundled"})
	w.Require().NoError(err)
	t.Cleanup(func() {
		assert.NoError(t, w.updateSetting("system-catalog", originalSystemCatalog), "failed to restore setting system-catalog")
	})
	w.Assert().Equal("bundled", systemCatalogUpdated.Value)

	imgLength, err := w.catalogClient.FetchChartIcon(smallForkClusterRepoName, "rancher-compliance")
	w.Require().NoError(err)
	w.Assert().Greater(imgLength, 0)
}
