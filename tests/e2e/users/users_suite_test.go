package users

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// UsersTestSuite covers the protections the v3 users API enforces: users can't delete or deactivate
// themselves, and new passwords must meet the password rules. Its tests live in the topic files in
// this package; this file holds only the shared setup.
type UsersTestSuite struct {
	suite.Suite
	client  *rancher.Client
	session *session.Session
}

func (s *UsersTestSuite) SetupSuite() {
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)

	s.client = client
}

func (s *UsersTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *UsersTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestUsersTestSuite(t *testing.T) {
	suite.Run(t, new(UsersTestSuite))
}
