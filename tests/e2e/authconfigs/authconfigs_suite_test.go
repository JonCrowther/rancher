package authconfigs

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// AuthConfigTestSuite covers the management API's AuthConfig resources: which providers exist, the
// actions each exposes, and the secrets their controllers create. Its tests live in
// auth_configs_test.go; this file holds only the shared setup.
type AuthConfigTestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	clusterID string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *AuthConfigTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *AuthConfigTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *AuthConfigTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestAuthConfig(t *testing.T) {
	suite.Run(t, new(AuthConfigTestSuite))
}
