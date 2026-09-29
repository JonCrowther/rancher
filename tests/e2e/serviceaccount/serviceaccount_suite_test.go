package serviceaccount

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// ServiceAccountTestSuite covers Rancher's service account token handling. Its tests live in the
// topic files in this package; this file holds only the shared setup.
type ServiceAccountTestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	clusterID string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *ServiceAccountTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *ServiceAccountTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *ServiceAccountTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestServiceAccountTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceAccountTestSuite))
}
