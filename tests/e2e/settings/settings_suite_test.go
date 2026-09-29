package settings

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// SettingsTestSuite covers Rancher's settings API: the read-only "cacerts" setting, and creating,
// updating and viewing ordinary settings. Its tests live in the topic files in this package; this
// file holds only the shared setup.
type SettingsTestSuite struct {
	suite.Suite
	client  *rancher.Client
	session *session.Session
}

func (s *SettingsTestSuite) SetupSuite() {
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *SettingsTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *SettingsTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestSettingsTestSuite(t *testing.T) {
	suite.Run(t, new(SettingsTestSuite))
}
