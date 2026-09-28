package clusterrepo

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/clients/rancher/catalog"
	"github.com/rancher/shepherd/extensions/kubeconfig"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

type ClusterRepoTestSuite struct {
	suite.Suite
	client        *rancher.Client
	session       *session.Session
	catalogClient *catalog.Client
	corev1        corev1client.CoreV1Interface
	clusterID     string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (c *ClusterRepoTestSuite) SetupSuite() {
	c.clusterID = "local"
	var err error
	testSession := session.NewSession()
	c.session = testSession

	c.client, err = rancher.NewClient("", testSession)
	require.NoError(c.T(), err)
	insecure := true
	c.client.RancherConfig.Insecure = &insecure
	c.catalogClient, err = c.client.GetClusterCatalogClient(c.clusterID)
	require.NoError(c.T(), err)

	kubeConfig, err := kubeconfig.GetKubeconfig(c.client, c.clusterID)
	require.NoError(c.T(), err)
	restConfig, err := (*kubeConfig).ClientConfig()
	require.NoError(c.T(), err)
	cset, err := kubernetes.NewForConfig(restConfig)
	require.NoError(c.T(), err)
	c.corev1 = cset.CoreV1()
}

func (c *ClusterRepoTestSuite) TearDownSuite() {
	c.session.Cleanup()
}

func TestClusterRepoTestSuite(t *testing.T) {
	suite.Run(t, new(ClusterRepoTestSuite))
}
