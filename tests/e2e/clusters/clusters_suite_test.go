package clusters

import (
	"net/http"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	"k8s.io/client-go/rest"
)

// ClustersTestSuite covers cluster-scoped behavior of the management API: cluster defaults and node
// counts, the node and node-driver schemas, persistent volume and claim validation, and the
// /k8s/proxy endpoint. Most tests use Rancher's local cluster; the downstream k8s proxy tests find
// a ready downstream cluster themselves. Its tests live in the topic files alongside this one; this
// file holds only the shared setup and helpers.
type ClustersTestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	clusterID string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *ClustersTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *ClustersTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *ClustersTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

// httpClient returns an HTTP client authenticated as the admin user, for calls to Rancher's raw
// Norman endpoints.
func (s *ClustersTestSuite) httpClient() *http.Client {
	httpClient, err := rest.HTTPClientFor(s.client.WranglerContext.RESTConfig)
	s.Require().NoError(err)
	return httpClient
}

func TestClustersTestSuite(t *testing.T) {
	suite.Run(t, new(ClustersTestSuite))
}
