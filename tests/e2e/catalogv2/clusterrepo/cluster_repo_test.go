package clusterrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	registryGoogle "github.com/google/go-containerregistry/pkg/registry"
	"github.com/hashicorp/go-version"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/rancher/pkg/catalogv2/oci"
	"github.com/rancher/rancher/pkg/controllers/dashboard/helm"
	"github.com/rancher/rancher/tests/e2e/defaults"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	stevev1 "github.com/rancher/shepherd/clients/rancher/v1"
	"github.com/rancher/shepherd/pkg/api/steve/catalog/types"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	rancherWait "github.com/rancher/shepherd/pkg/wait"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/registry"
	"helm.sh/helm/v4/pkg/repo/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/retry"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

// The ClusterRepo names are prefixes: each test appends a random suffix, so a repo left behind by
// a failed test can't make the next test's create fail.
const (
	HTTPClusterRepoName = "test-http-cluster-repo"
	StableHTTPRepoURL   = "https://releases.rancher.com/server-charts/stable"

	GitClusterSmallForkName = "test-git-small-fork-cluster-repo"
	GitClusterSmallForkURL  = "https://github.com/rancher/charts-small-fork"
	GitClusterRepoName      = "test-git-cluster-repo"
	RancherChartsGitRepoURL = "https://github.com/rancher/charts"
	RKE2ChartsGitRepoURL    = "https://github.com/rancher/rke2-charts"

	OCIClusterRepoName = "test-oci-cluster-repo"
)

var (
	PollInterval = time.Duration(500 * time.Millisecond)
	PollTimeout  = time.Duration(5 * time.Minute)
)

type RepoType int64

const (
	Git RepoType = iota
	HTTP
	OCI
)

// ClusterRepoParams is used to pass params to func testClusterRepo for testing
type ClusterRepoParams struct {
	Name              string   // Name of the ClusterRepo resource
	Type              RepoType // Type of the ClusterRepo resource
	URL1              string   // URL to use when creating the ClusterRepo resource
	URL2              string   // URL to use when updating the ClusterRepo resource to a new URL
	InsecurePlainHTTP bool
	StatusCode        int
	StatusCodeMessage string
	RefreshInterval   int
	TagFilter         string
}

// TestHTTPRepo tests CREATE, UPDATE, and DELETE operations of HTTP ClusterRepo resources
func (c *ClusterRepoTestSuite) TestHTTPRepo() {
	//start http server
	ts := StartHTTPRepository(c)
	c.T().Cleanup(ts.Close)

	c.testClusterRepo(ClusterRepoParams{
		Name: namegen.AppendRandomString(HTTPClusterRepoName),
		URL1: ts.URL,
		URL2: StableHTTPRepoURL,
		Type: HTTP,
	})
}

// TestGitRepo tests CREATE, UPDATE, and DELETE operations of Git ClusterRepo resources
func (c *ClusterRepoTestSuite) TestGitRepo() {
	c.testClusterRepo(ClusterRepoParams{
		Name: namegen.AppendRandomString(GitClusterRepoName),
		URL1: RancherChartsGitRepoURL,
		URL2: RKE2ChartsGitRepoURL,
		Type: Git,
	})
}

func (c *ClusterRepoTestSuite) TestGitRepoRetries() {
	c.testClusterRepoRetries(ClusterRepoParams{
		Name: namegen.AppendRandomString(GitClusterSmallForkName),
		URL1: GitClusterSmallForkURL,
		Type: Git,
	})
}

func StartHTTPRepository(c *ClusterRepoTestSuite) *httptest.Server {
	// Directory where Helm chart and index.yaml are stored
	repositoryDirectory := "../../testdata/"
	_, err := os.Stat(repositoryDirectory)
	c.Require().NoError(err)

	// Create a new test server
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverVersion, err := c.client.Management.Setting.ByID("server-version")
		assert.NoError(c.T(), err)
		if serverVersion.Value == "" {
			serverVersion.Value = serverVersion.Default
		}

		serverVersionType, err := c.client.Management.Setting.ByID("server-version-type")
		assert.NoError(c.T(), err)
		if serverVersionType.Value == "" {
			serverVersionType.Value = serverVersionType.Default
		}

		assert.Equal(c.T(), r.Header.Get("User-Agent"), fmt.Sprintf("%s/%s/%s/%s %s", "go", "rancher", serverVersionType.Value, serverVersion.Value, "(HTTP-based Helm Repository)"))
		http.StripPrefix("/", http.FileServer(http.Dir(repositoryDirectory))).ServeHTTP(w, r)
	}))

	ip := getOutboundIP()
	// Bind the server to a specific IP address (your local machine's IP)
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	c.Require().NoError(err)
	ts.Listener = listener
	ts.Start()

	return ts
}

func StartRegistry(c *ClusterRepoTestSuite) (*httptest.Server, error) {
	// Create a new registry handler
	handler := registryGoogle.New()

	// Optionally, you can customize the handler here if needed
	// e.g., add middleware, logging, etc.
	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(c.T(), r.Header["User-Agent"][0], "go")
		assert.Contains(c.T(), r.Header["User-Agent"][0], "rancher")
		assert.Contains(c.T(), r.Header["User-Agent"][0], "(OCI-based Helm Repository)")
		handler.ServeHTTP(w, r)
	})

	// Create a new test server
	ts := httptest.NewUnstartedServer(customHandler)

	ip := getOutboundIP()
	// Bind the server to a specific IP address (your local machine's IP)
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

func StartErrorRegistry(status int) (*httptest.Server, error) {
	// Start a new server
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	ip := getOutboundIP()
	// Bind the server to a specific IP address (your local machine's IP)
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

func Start429Registry(t assert.TestingT, rateLimitedHeader bool) (*httptest.Server, error) {
	testingChartPath := "../../testdata/testingchart-0.1.0.tgz"
	testChartPath := "../../testdata/testchart-1.0.0.tgz"
	helmChartTar, err := os.ReadFile(testingChartPath)
	assert.NoError(t, err)

	layerDesc := ocispec.Descriptor{
		MediaType: registry.ChartLayerMediaType,
		Digest:    digest.FromBytes(helmChartTar),
		Size:      int64(len(helmChartTar)),
	}

	helmChartTar2, err := os.ReadFile(testChartPath)
	assert.NoError(t, err)

	layerDesc2 := ocispec.Descriptor{
		MediaType: registry.ChartLayerMediaType,
		Digest:    digest.FromBytes(helmChartTar2),
		Size:      int64(len(helmChartTar2)),
	}

	configBlob := []byte("config")
	configDesc := ocispec.Descriptor{
		MediaType: registry.ConfigMediaType,
		Digest:    digest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
	}

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifestJSON, err := json.Marshal(manifest)
	assert.NoError(t, err)
	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestJSON),
		Size:      int64(len(manifestJSON)),
	}

	manifest2 := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc2},
	}
	manifestJSON2, err := json.Marshal(manifest2)
	assert.NoError(t, err)
	manifestDesc2 := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestJSON2),
		Size:      int64(len(manifestJSON2)),
	}

	manifestCount := 1
	timerStart := false

	// Create an OCI Registry Server
	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		switch r.URL.Path {
		case "/v2/testingchart/tags/list":
			t := `{"tags": ["0.1.0","0.0.1","sha256"]}`
			w.Write([]byte(t))
		case "/v2/testchart/tags/list":
			t := `{"tags": ["1.0.0","0.1.1","sha256"]}`
			w.Write([]byte(t))

		case "/v2/_catalog":
			t := `{"repositories": ["testingchart","testchart"]}`
			w.Write([]byte(t))

		case "/v2/testingchart/blobs/" + layerDesc.Digest.String():
			http.ServeFile(w, r, testingChartPath)
		case "/v2/testchart/blobs/" + layerDesc2.Digest.String():
			http.ServeFile(w, r, testChartPath)
		case "/v2/testingchart/manifests/0.1.0":
			if accept := r.Header.Get("Accept"); !strings.Contains(accept, manifestDesc.MediaType) {
				assert.NoError(t, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", manifestDesc.MediaType)
			w.Header().Set("Docker-Content-Digest", manifestDesc.Digest.String())
			if _, err := w.Write(manifestJSON); err != nil {
				assert.NoError(t, err)
			}
		case "/v2/testchart/manifests/1.0.0":
			if r.Method == http.MethodHead {
				if rateLimitedHeader {
					w.Header().Set("RateLimit-Remaining", "0;w=60")
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			manifestCount++
			if manifestCount > 1 {
				if !timerStart {
					go func() {
						d := time.NewTicker(1 * time.Minute)
						for {
							<-d.C
							manifestCount = 0
							return
						}
					}()
					timerStart = true
				}
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if accept := r.Header.Get("Accept"); !strings.Contains(accept, manifestDesc2.MediaType) {
				assert.NoError(t, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", manifestDesc2.MediaType)
			w.Header().Set("Docker-Content-Digest", manifestDesc2.Digest.String())
			if _, err := w.Write(manifestJSON2); err != nil {
				assert.NoError(t, err)
			}

		}
	})

	// Create a new test server
	ts := httptest.NewUnstartedServer(customHandler)

	ip := getOutboundIP()
	// Bind the server to a specific IP address (your local machine's IP)
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		log.Printf("Failed to bind to local IP: %v", err)
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

func AddHelmChart(u *url.URL, repoName, path, tag string) error {
	chartTar, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	configBlob := []byte("config")
	configDesc := ocispec.Descriptor{
		MediaType: registry.ConfigMediaType,
		Digest:    digest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
	}
	layerDesc := ocispec.Descriptor{
		MediaType: registry.ChartLayerMediaType,
		Digest:    digest.FromBytes(chartTar),
		Size:      int64(len(chartTar)),
	}
	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	manifestDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestJSON),
		Size:      int64(len(manifestJSON)),
	}

	target := memory.New()
	if err := target.Push(context.Background(), configDesc, bytes.NewReader(configBlob)); err != nil {
		return err
	}
	if err := target.Push(context.Background(), layerDesc, bytes.NewReader(chartTar)); err != nil {
		return err
	}
	if err := target.Push(context.Background(), manifestDesc, bytes.NewReader(manifestJSON)); err != nil {
		return err
	}
	err = target.Tag(context.Background(), manifestDesc, tag)
	if err != nil {
		return err
	}

	ociClient, err := oci.NewClient(fmt.Sprintf("oci://%s/rancher/%s", u.Host, repoName), v1.RepoSpec{}, nil)
	if err != nil {
		return err
	}

	orasRepository, err := ociClient.GetOrasRepository()
	if err != nil {
		return err
	}
	orasRepository.PlainHTTP = true

	_, err = oras.Copy(context.Background(), target, tag, orasRepository, "", oras.DefaultCopyOptions)
	if err != nil {
		return err
	}

	return nil
}

// TestOCIRepo tests CREATE, UPDATE, and DELETE operations of OCI ClusterRepo resources
func (c *ClusterRepoTestSuite) TestOCIRepo() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	//push testingchart helm chart
	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
	require.NoError(c.T(), err)

	c.testClusterRepo(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/rancher/testingchart", u.Host),
		URL2:              fmt.Sprintf("oci://%s/rancher/testingchart:0.1.0", u.Host),
		Type:              OCI,
		InsecurePlainHTTP: true,
	})
}

// TestOCIRepo2 tests CREATE, UPDATE, and DELETE operations of OCI ClusterRepo additional cases
func (c *ClusterRepoTestSuite) TestOCIRepo2() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	//push testingchart helm chart
	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
	require.NoError(c.T(), err)

	c.testClusterRepo(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/rancher", u.Host),
		URL2:              fmt.Sprintf("oci://%s/", u.Host),
		Type:              OCI,
		InsecurePlainHTTP: true,
	})
}

// TestOCIRepo3 tests 4xx response codes received from the registry
func (c *ClusterRepoTestSuite) TestOCIRepo3() {
	statusCodes := [3]int{404, 401, 403}
	statusCodeMessages := [3]string{"Not Found", "Unauthorized", "Forbidden"}
	for index, statusCode := range statusCodes {
		ts, err := StartErrorRegistry(statusCode)
		require.NoError(c.T(), err)
		c.T().Cleanup(ts.Close)
		u, err := url.Parse(ts.URL)
		require.NoError(c.T(), err)

		c.test4xxErrors(ClusterRepoParams{
			Name:              namegen.AppendRandomString(OCIClusterRepoName),
			URL1:              fmt.Sprintf("oci://%s/rancher", u.Host),
			StatusCode:        statusCodes[index],
			StatusCodeMessage: statusCodeMessages[index],
			InsecurePlainHTTP: true,
			Type:              OCI,
		})
	}
}

// TestOCIRepo4 tests 429 response code received from the registry
func (c *ClusterRepoTestSuite) TestOCIRepo4() {
	ts, err := Start429Registry(c.T(), false)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	c.test429Error(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/", u.Host),
		InsecurePlainHTTP: true,
		Type:              OCI,
		RefreshInterval:   65,
	})
}

// TestOCIRepo5 tests 429 response code received from the registry which sends RateLimited-Remaining header
func (c *ClusterRepoTestSuite) TestOCIRepo5() {
	ts, err := Start429Registry(c.T(), true)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	c.test429Error(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/", u.Host),
		InsecurePlainHTTP: true,
		Type:              OCI,
	})
}

// TestOCIRepoMultipleChartRepos tests CREATE, UPDATE, and DELETE operations of OCI ClusterRepo with many chart repos
func (c *ClusterRepoTestSuite) TestOCIRepoMultipleChartRepos() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	//push testingchart helm chart
	for i := 0; i < 300; i++ {
		err = AddHelmChart(u, fmt.Sprintf("testingchart-%d", i), "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
		require.NoError(c.T(), err)
	}

	c.testClusterRepo(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/rancher/testingchart-0", u.Host),
		URL2:              fmt.Sprintf("oci://%s/rancher/testingchart-0:0.1.0", u.Host),
		Type:              OCI,
		InsecurePlainHTTP: true,
	})
}

func (c *ClusterRepoTestSuite) TestOCIRepoWithOptions() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
	require.NoError(c.T(), err)
	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-1.0.0.tgz", "1.0.0")
	require.NoError(c.T(), err)

	c.testClusterRepoOCIOptions(ClusterRepoParams{
		Name:              namegen.AppendRandomString(OCIClusterRepoName),
		URL1:              fmt.Sprintf("oci://%s/rancher/testingchart", u.Host),
		Type:              OCI,
		InsecurePlainHTTP: true,
		TagFilter:         "< 1.0.0",
	})
}

func (c *ClusterRepoTestSuite) test429Error(params ClusterRepoParams) {
	var err error

	clusterRepo := v1.NewClusterRepo("", params.Name, v1.ClusterRepo{})
	setClusterRepoURL(&clusterRepo.Spec, params.Type, params.URL1)
	clusterRepo.Spec.InsecurePlainHTTP = params.InsecurePlainHTTP
	clusterRepo.Spec.RefreshInterval = params.RefreshInterval
	expoValues := v1.ExponentialBackOffValues{
		MinWait:    1,
		MaxWait:    1,
		MaxRetries: 1,
	}
	clusterRepo.Spec.ExponentialBackOffValues = &expoValues
	clusterRepo, err = c.catalogClient.ClusterRepos().Create(context.TODO(), clusterRepo, metav1.CreateOptions{})
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(params.Name)

	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		for _, condition := range cr.Status.Conditions {
			if v1.RepoCondition(condition.Type) == v1.OCIDownloaded {
				return condition.Status == corev1.ConditionFalse && cr.Status.NumberOfRetries == 0
			}
		}
		return false
	}, 5*time.Minute, 50*time.Millisecond, "waiting for %s to fail its download on a 429 and stop retrying", params.Name)

	index, err := c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	require.NoError(c.T(), err)

	index.SortEntries()
	assert.Equal(c.T(), len(index.Entries), 2)
	assert.Equal(c.T(), len(index.Entries["testingchart"]), 2)
	assert.NotEmpty(c.T(), index.Entries["testingchart"][0].Digest)

	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		for _, condition := range cr.Status.Conditions {
			if v1.RepoCondition(condition.Type) == v1.OCIDownloaded {
				return condition.Status == corev1.ConditionTrue
			}
		}
		return false
	}, 3*time.Minute, PollInterval, "waiting for %s to download once the rate limit resets", params.Name)

	clusterRepo, err = c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	require.NoError(c.T(), err)
	assert.Equal(c.T(), clusterRepo.Status.NumberOfRetries, 0, "Number of retries should be 0 since there were no 429s")

	index, err = c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	require.NoError(c.T(), err)

	assert.Equal(c.T(), len(index.Entries), 2)
	assert.Equal(c.T(), len(index.Entries["testchart"]), 2)
	assert.Equal(c.T(), len(index.Entries["testingchart"]), 2)
	assert.NotEmpty(c.T(), index.Entries["testchart"][0].Digest)
	assert.NotEmpty(c.T(), index.Entries["testingchart"][0].Digest)

	err = c.catalogClient.ClusterRepos().Delete(context.TODO(), params.Name, metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	_, err = c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	assert.Error(c.T(), err)
}

func (c *ClusterRepoTestSuite) test4xxErrors(params ClusterRepoParams) {
	// Create a ClusterRepo
	cr := v1.NewClusterRepo("", params.Name, v1.ClusterRepo{})
	setClusterRepoURL(&cr.Spec, params.Type, params.URL1)
	cr.Spec.InsecurePlainHTTP = params.InsecurePlainHTTP
	_, err := c.catalogClient.ClusterRepos().Create(context.TODO(), cr, metav1.CreateOptions{})
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(params.Name)

	c.Require().Eventually(func() bool {
		clusterRepo, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		for _, condition := range clusterRepo.Status.Conditions {
			if v1.RepoCondition(condition.Type) == v1.OCIDownloaded {
				return condition.Status == corev1.ConditionFalse
			}
		}
		return false
	}, 5*time.Second, PollInterval, "waiting for %s to fail its download", params.Name)

	clusterRepo, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	require.NoError(c.T(), err)
	for _, condition := range clusterRepo.Status.Conditions {
		if v1.RepoCondition(condition.Type) == v1.OCIDownloaded {
			assert.Equal(c.T(), condition.Message, fmt.Sprintf("error %d: %s", params.StatusCode, params.StatusCodeMessage))
		}
	}
	assert.Zero(c.T(), clusterRepo.Status.NumberOfRetries)

	_, err = c.corev1.ConfigMaps(helm.GetConfigMapNamespace(clusterRepo.Namespace)).Get(context.TODO(), helm.GenerateConfigMapName(clusterRepo.Name, 0, clusterRepo.UID), metav1.GetOptions{})
	assert.True(c.T(), apierrors.IsNotFound(err))

	err = c.catalogClient.ClusterRepos().Delete(context.TODO(), params.Name, metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	_, err = c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	assert.Error(c.T(), err)
}

// TestOCI tests creating an OCI clusterrepo and install a chart
func (c *ClusterRepoTestSuite) TestOCIRepoChartInstallation() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	//push testingchart helm chart
	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
	require.NoError(c.T(), err)

	repoName := namegen.AppendRandomString("oci")

	// create cluster repo
	clusterRepo := &v1.ClusterRepo{
		ObjectMeta: metav1.ObjectMeta{
			Name: repoName,
		},
		Spec: v1.RepoSpec{
			URL:               fmt.Sprintf("oci://%s/rancher", u.Host),
			InsecurePlainHTTP: true,
		},
	}
	_, err = c.catalogClient.ClusterRepos().Create(context.Background(), clusterRepo, metav1.CreateOptions{})
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(repoName)

	// Validate the ClusterRepo was created
	_, err = c.pollUntilDownloaded(repoName, metav1.Time{})
	require.NoError(c.T(), err)

	// check if chart can be fetched
	chartInstallAction := types.ChartInstallAction{
		DisableHooks: false,
		Timeout:      nil,
	}

	chartInstallAction.Charts = []types.ChartInstall{
		{
			ChartName:   "testingchart",
			Version:     "0.1.0",
			ReleaseName: "testreleasename",
		},
	}

	// Uninstall the release if the test fails before its own uninstall step, so the next run can install it.
	t := c.T()
	t.Cleanup(func() {
		_, err := c.catalogClient.Apps("default").Get(context.Background(), "testreleasename", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return
		}
		assert.NoError(t, c.catalogClient.UninstallChart("testreleasename", "default", &types.ChartUninstallAction{}), "failed to uninstall testreleasename")
	})

	err = c.catalogClient.InstallChart(&chartInstallAction, repoName)
	require.NoError(c.T(), err)

	// wait for chart to be full deployed
	watchAppInterface, err := c.catalogClient.Apps("default").Watch(context.TODO(), metav1.ListOptions{
		FieldSelector:  "metadata.name=" + "testreleasename",
		TimeoutSeconds: &defaults.WatchTimeoutSeconds,
	})
	require.NoError(c.T(), err)

	err = rancherWait.WatchWait(watchAppInterface, func(event watch.Event) (ready bool, err error) {
		app := event.Object.(*v1.App)

		state := app.Status.Summary.State
		if state == string(v1.StatusDeployed) {
			return true, nil
		}
		return false, nil
	})
	require.NoError(c.T(), err)

	appCR, err := c.catalogClient.Apps("default").Get(context.TODO(), "testreleasename", metav1.GetOptions{})
	require.NoError(c.T(), err)

	// Every AppCR installed through rancher must
	// have the catalog clusterRepoName label
	value, ok := appCR.Labels["catalog.cattle.io/cluster-repo-name"]
	assert.True(c.T(), ok)
	assert.Equal(c.T(), repoName, value)

	// Validate uninstalling the chart
	chartUninstallAction := types.ChartUninstallAction{
		DisableHooks: false,
		Timeout:      nil,
	}

	err = c.catalogClient.UninstallChart("testreleasename", "default", &chartUninstallAction)
	require.NoError(c.T(), err)

	watchAppInterface, err = c.catalogClient.Apps("default").Watch(context.TODO(), metav1.ListOptions{
		FieldSelector:  "metadata.name=" + "testreleasename",
		TimeoutSeconds: &defaults.WatchTimeoutSeconds,
	})
	require.NoError(c.T(), err)

	err = rancherWait.WatchWait(watchAppInterface, func(event watch.Event) (ready bool, err error) {
		if event.Type == watch.Deleted {
			return true, nil
		}
		return false, nil
	})
	assert.NoError(c.T(), err)

	// Validate deleting the ClusterRepo
	err = c.catalogClient.ClusterRepos().Delete(context.Background(), repoName, metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	err = c.catalogClient.ClusterRepos().Delete(context.Background(), repoName, metav1.DeleteOptions{})
	assert.Error(c.T(), err)
}

// TestOCIEnableRepo tests the enable/disable feature of clusterrepo
func (c *ClusterRepoTestSuite) TestOCIEnableRepo() {
	//start registry
	ts, err := StartRegistry(c)
	require.NoError(c.T(), err)
	c.T().Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	require.NoError(c.T(), err)

	repoName := namegen.AppendRandomString("oci")

	// Add a single helm chart
	err = AddHelmChart(u, "testingchart", "../../testdata/testingchart-0.1.0.tgz", "0.1.0")
	require.NoError(c.T(), err)

	// Create a ClusterRepo
	clusterRepo := &v1.ClusterRepo{
		ObjectMeta: metav1.ObjectMeta{
			Name: repoName,
		},
		Spec: v1.RepoSpec{
			URL:               fmt.Sprintf("oci://%s/rancher", u.Host),
			InsecurePlainHTTP: true,
		},
	}
	_, err = c.catalogClient.ClusterRepos().Create(context.Background(), clusterRepo, metav1.CreateOptions{})
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(repoName)
	_, err = c.pollUntilDownloaded(repoName, metav1.Time{})
	require.NoError(c.T(), err)

	// Disable the clusterrepo
	disabled := false
	clusterRepo, err = c.updateClusterRepo(repoName, func(cr *v1.ClusterRepo) { cr.Spec.Enabled = &disabled })
	require.NoError(c.T(), err)
	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), repoName, metav1.GetOptions{})
		return err == nil && cr.Status.ObservedGeneration >= clusterRepo.Generation
	}, time.Minute, PollInterval, "waiting for the controller to process disabling %s", repoName)

	// Add a second helm chart
	err = AddHelmChart(u, "testchart", "../../testdata/testchart-1.0.0.tgz", "1.0.0")
	require.NoError(c.T(), err)

	// ForceRefresh the clusterrepo
	clusterRepo, err = c.updateClusterRepo(repoName, func(cr *v1.ClusterRepo) { cr.Spec.ForceUpdate = &metav1.Time{Time: time.Now()} })
	require.NoError(c.T(), err)
	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), repoName, metav1.GetOptions{})
		return err == nil && cr.Status.ObservedGeneration >= clusterRepo.Generation
	}, time.Minute, PollInterval, "waiting for the controller to process the force refresh of disabled %s", repoName)

	// Check configmap for chart or version and the new chart should not exist
	index, err := c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	c.Require().NoError(err)
	assert.Equal(c.T(), len(index.Entries), 1)

	// Enable the clusterrepo
	enabled := true
	_, err = c.updateClusterRepo(repoName, func(cr *v1.ClusterRepo) { cr.Spec.Enabled = &enabled })
	require.NoError(c.T(), err)

	// ForceRefresh the clusterrepo
	clusterRepo, err = c.updateClusterRepo(repoName, func(cr *v1.ClusterRepo) { cr.Spec.ForceUpdate = &metav1.Time{Time: time.Now()} })
	require.NoError(c.T(), err)
	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), repoName, metav1.GetOptions{})
		return err == nil && cr.Status.ObservedGeneration >= clusterRepo.Generation
	}, time.Minute, PollInterval, "waiting for the controller to process the force refresh of enabled %s", repoName)

	// Check configmap for chart or version and 2 charts must exist now
	index, err = c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	c.Require().NoError(err)
	assert.Equal(c.T(), 2, len(index.Entries))

	// Validate deleting the ClusterRepo
	err = c.catalogClient.ClusterRepos().Delete(context.Background(), repoName, metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	err = c.catalogClient.ClusterRepos().Delete(context.Background(), repoName, metav1.DeleteOptions{})
	assert.Error(c.T(), err)
}

// testClusterRepo takes in ClusterRepoParams and tests CREATE, UPDATE, and DELETE operations
func (c *ClusterRepoTestSuite) testClusterRepo(params ClusterRepoParams) {
	// Create a ClusterRepo
	cr := v1.NewClusterRepo("", params.Name, v1.ClusterRepo{})
	setClusterRepoURL(&cr.Spec, params.Type, params.URL1)
	cr.Spec.InsecurePlainHTTP = params.InsecurePlainHTTP
	_, err := c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Create(cr)
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(params.Name)
	time.Sleep(1 * time.Second)

	// Validate the ClusterRepo was created and resources were downloaded
	clusterRepo, err := c.pollUntilDownloaded(params.Name, metav1.Time{})
	require.NoError(c.T(), err)

	status := c.getStatusFromClusterRepo(clusterRepo)
	assert.Equal(c.T(), params.URL1, status.URL)

	// Save download timestamp and generation count before changing the URL
	downloadTime := status.DownloadTime
	observedGeneration := status.ObservedGeneration

	// Validate updating the ClusterRepo by changing the repo URL and verifying DownloadTime was updated (meaning new resources were pulled)
	spec := c.getSpecFromClusterRepo(clusterRepo)
	setClusterRepoURL(spec, params.Type, params.URL2)
	clusterRepoUpdated := *clusterRepo
	clusterRepoUpdated.Spec = spec

	_, err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Replace(&clusterRepoUpdated)
	require.NoError(c.T(), err)

	clusterRepo, err = c.pollUntilDownloaded(params.Name, downloadTime)
	require.NoError(c.T(), err)

	status = c.getStatusFromClusterRepo(clusterRepo)
	assert.Equal(c.T(), params.URL2, status.URL)
	assert.Greater(c.T(), status.ObservedGeneration, observedGeneration)

	// Validate deleting the ClusterRepo
	err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Delete(clusterRepo)
	require.NoError(c.T(), err)

	_, err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).ByID(params.Name)
	require.Error(c.T(), err)
}

func (c *ClusterRepoTestSuite) testClusterRepoOCIOptions(params ClusterRepoParams) {
	// Create a ClusterRepo
	cr := v1.NewClusterRepo("", params.Name, v1.ClusterRepo{
		Spec: v1.RepoSpec{OCIOptions: &v1.OCIOptions{TagFilter: params.TagFilter}},
	})
	setClusterRepoURL(&cr.Spec, params.Type, params.URL1)
	cr.Spec.InsecurePlainHTTP = params.InsecurePlainHTTP
	_, err := c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Create(cr)
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(params.Name)
	time.Sleep(1 * time.Second)

	// Validate the ClusterRepo was created and resources were downloaded
	clusterRepo, err := c.pollUntilDownloaded(params.Name, metav1.Time{})
	require.NoError(c.T(), err)

	status := c.getStatusFromClusterRepo(clusterRepo)
	assert.Equal(c.T(), params.URL1, status.URL)

	//get index
	index, err := c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	require.NoError(c.T(), err)
	constraint, err := version.NewConstraint(cr.Spec.OCIOptions.TagFilter)
	require.NoError(c.T(), err, "failed to parse semver constraint %s", cr.Spec.OCIOptions.TagFilter)
	require.NotEmpty(c.T(), index.Entries["testingchart"])
	for _, chart := range index.Entries["testingchart"] {
		assert.True(c.T(), constraint.Check(version.Must(version.NewVersion(chart.Version))), "tag filter constraint failed for ", chart.Version)
	}

	// Add DownloadAllTags = true to clusterrepo but keep the filter
	spec := c.getSpecFromClusterRepo(clusterRepo)
	spec.OCIOptions.DownloadAllTags = true
	clusterRepoUpdated := *clusterRepo
	clusterRepoUpdated.Spec = spec

	_, err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Replace(&clusterRepoUpdated)
	require.NoError(c.T(), err)

	updated, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	require.NoError(c.T(), err)
	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		return err == nil && cr.Status.ObservedGeneration >= updated.Generation
	}, 3*time.Minute, PollInterval, "waiting for the controller to process DownloadAllTags on %s", params.Name)

	//get index
	index, err = c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	require.NoError(c.T(), err)

	assert.Equal(c.T(), 1, len(index.Entries["testingchart"]))

	//remove tag filter from clusterrepo
	updated, err = c.updateClusterRepo(params.Name, func(cr *v1.ClusterRepo) {
		cr.Spec.OCIOptions.TagFilter = ""
		cr.Spec.OCIOptions.DownloadAllTags = true
	})
	require.NoError(c.T(), err)
	c.Require().Eventually(func() bool {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		return err == nil && cr.Status.ObservedGeneration >= updated.Generation
	}, 3*time.Minute, PollInterval, "waiting for the controller to process removing the tag filter on %s", params.Name)

	//get index
	index, err = c.getIndex(clusterRepo.Namespace, clusterRepo.Name, clusterRepo.UID)
	require.NoError(c.T(), err)

	assert.Equal(c.T(), 2, len(index.Entries["testingchart"]))

	// Validate deleting the ClusterRepo
	err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).Delete(clusterRepo)
	require.NoError(c.T(), err)

	_, err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).ByID(params.Name)
	require.Error(c.T(), err)
}

// testClusterRepoRetries takes in ClusterRepoParams and creates a ClusterRepo with a bad branch name,
// then updates the branch name to a valid branch name after retries are done
func (c *ClusterRepoTestSuite) testClusterRepoRetries(params ClusterRepoParams) {
	// Create a ClusterRepo
	cr := v1.NewClusterRepo("", params.Name, v1.ClusterRepo{})
	setClusterRepoURL(&cr.Spec, params.Type, params.URL1)
	cr.Spec.InsecurePlainHTTP = params.InsecurePlainHTTP
	cr.Spec.GitBranch = "invalid-branch"
	expoValues := v1.ExponentialBackOffValues{
		MinWait:    30,
		MaxWait:    60,
		MaxRetries: 2,
	}
	cr.Spec.ExponentialBackOffValues = &expoValues
	cr, err := c.catalogClient.ClusterRepos().Create(context.TODO(), cr, metav1.CreateOptions{})
	require.NoError(c.T(), err)
	c.deleteRepoOnCleanup(params.Name)

	retryNumber := 1
	err = wait.Poll(1*time.Second, 10*time.Minute, func() (done bool, err error) {
		cr, err = c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		for _, condition := range cr.Status.Conditions {
			if v1.RepoCondition(condition.Type) == v1.RepoDownloaded {
				logrus.Infof("Condition Status (Actual/Wanted): %s/%s, Number of Retries (Actual/Wanted): %d/%d", condition.Status, corev1.ConditionFalse, cr.Status.NumberOfRetries, retryNumber)
				if condition.Status == corev1.ConditionFalse && cr.Status.NumberOfRetries == retryNumber {
					retryNumber++
					return false, nil
				}
				return condition.Status == corev1.ConditionFalse && cr.Status.NumberOfRetries == 0 && retryNumber == cr.Spec.ExponentialBackOffValues.MaxRetries+1, nil
			}
		}

		return false, nil
	})

	if err != nil {
		logrus.Infof("ClusterRepo Status Details:")
		logrus.Infof("ResourceVersion: %s", cr.ResourceVersion)
		logrus.Infof("Conditions: %+v", cr.Status.Conditions)
		logrus.Infof("NumberOfRetries: %d", cr.Status.NumberOfRetries)
		logrus.Infof("DownloadTime: %s", cr.Status.DownloadTime)
		logrus.Infof("ObservedGeneration: %d", cr.Status.ObservedGeneration)
		logrus.Infof("Meta Generation: %d", cr.Generation)
		logrus.Infof("Branch: %s", cr.Status.Branch)
		logrus.Infof("Commit: %s", cr.Status.Commit)
		logrus.Infof("NumberOfRetries: %d", cr.Status.NumberOfRetries)
		logrus.Infof("NextRetryAt: %s", cr.Status.NextRetryAt)
		logrus.Infof("ShouldNotSkip: %t", cr.Status.ShouldNotSkip)
		logrus.Infof("ExponentialBackOffValues: %+v", cr.Spec.ExponentialBackOffValues)
	}
	require.NoError(c.T(), err)

	downloadTime := cr.Status.DownloadTime

	_, err = c.updateClusterRepo(params.Name, func(cr *v1.ClusterRepo) { cr.Spec.GitBranch = "main" })
	require.NoError(c.T(), err)

	// Validate the resources were downloaded from the valid branch
	clusterRepo, err := c.pollUntilDownloaded(params.Name, downloadTime)
	require.NoError(c.T(), err)

	status := c.getStatusFromClusterRepo(clusterRepo)
	assert.Greater(c.T(), status.DownloadTime.Time, downloadTime.Time)

	err = c.catalogClient.ClusterRepos().Delete(context.TODO(), params.Name, metav1.DeleteOptions{})
	assert.NoError(c.T(), err)

	_, err = c.catalogClient.ClusterRepos().Get(context.TODO(), params.Name, metav1.GetOptions{})
	assert.Error(c.T(), err)
}

// deleteRepoOnCleanup registers a cleanup that deletes the named ClusterRepo, so a test that fails before
// its own delete step doesn't leave the repo behind. The catalog client doesn't register its creates with
// the session, so this is the only cleanup for repos it creates. It's a no-op if the test already deleted it.
func (c *ClusterRepoTestSuite) deleteRepoOnCleanup(name string) {
	t := c.T()
	t.Cleanup(func() {
		err := c.catalogClient.ClusterRepos().Delete(context.Background(), name, metav1.DeleteOptions{})
		if !apierrors.IsNotFound(err) {
			assert.NoError(t, err, "failed to delete ClusterRepo %s", name)
		}
	})
}

// updateClusterRepo applies mutate to the latest version of the named ClusterRepo, retrying on conflicts
// with the controller's status updates, and returns the updated repo.
func (c *ClusterRepoTestSuite) updateClusterRepo(name string, mutate func(*v1.ClusterRepo)) (*v1.ClusterRepo, error) {
	var updated *v1.ClusterRepo
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cr, err := c.catalogClient.ClusterRepos().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		mutate(cr)
		updated, err = c.catalogClient.ClusterRepos().Update(context.TODO(), cr, metav1.UpdateOptions{})
		return err
	})
	return updated, err
}

// getIndex reads the chart index the controller stored in the ClusterRepo's first index ConfigMap.
func (c *ClusterRepoTestSuite) getIndex(namespace, name string, uid ktypes.UID) (*repo.IndexFile, error) {
	configMap, err := c.corev1.ConfigMaps(helm.GetConfigMapNamespace(namespace)).Get(context.TODO(), helm.GenerateConfigMapName(name, 0, uid), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewBuffer(configMap.BinaryData["content"]))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, err
	}
	index := &repo.IndexFile{}
	if err := json.Unmarshal(data, index); err != nil {
		return nil, err
	}
	return index, nil
}

// pollUntilDownloaded Polls until the ClusterRepo of the given name has been downloaded (by comparing prevDownloadTime against the current DownloadTime)
func (c *ClusterRepoTestSuite) pollUntilDownloaded(ClusterRepoName string, prevDownloadTime metav1.Time) (*stevev1.SteveAPIObject, error) {
	var clusterRepo *stevev1.SteveAPIObject
	err := wait.Poll(PollInterval, PollTimeout, func() (done bool, err error) {
		clusterRepo, err = c.client.Steve.SteveType(catalog.ClusterRepoSteveResourceType).ByID(ClusterRepoName)
		if err != nil {
			return false, err
		}
		status := c.getStatusFromClusterRepo(clusterRepo)
		if clusterRepo.Name != ClusterRepoName {
			return false, nil
		}

		return status.DownloadTime != prevDownloadTime, nil
	})

	return clusterRepo, err
}

func (c *ClusterRepoTestSuite) getSpecFromClusterRepo(obj *stevev1.SteveAPIObject) *v1.RepoSpec {
	spec := &v1.RepoSpec{}
	err := stevev1.ConvertToK8sType(obj.Spec, spec)
	require.NoError(c.T(), err)

	return spec
}

func (c *ClusterRepoTestSuite) getStatusFromClusterRepo(obj *stevev1.SteveAPIObject) *v1.RepoStatus {
	status := &v1.RepoStatus{}
	err := stevev1.ConvertToK8sType(obj.Status, status)
	require.NoError(c.T(), err)

	return status
}

func setClusterRepoURL(spec *v1.RepoSpec, repoType RepoType, URL string) {
	switch repoType {
	case Git:
		spec.GitRepo = URL
	case HTTP:
		spec.URL = URL
	case OCI:
		spec.URL = URL
	}
}

// Get preferred outbound ip of this machine
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		logrus.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
