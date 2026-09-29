package tokens

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// TokensTestSuite covers Rancher's authentication tokens: the current token, token TTLs, and
// websocket origin checks. Its tests live in the topic files in this package; this file holds only
// the shared setup.
type TokensTestSuite struct {
	suite.Suite
	client  *rancher.Client
	session *session.Session
}

func (s *TokensTestSuite) SetupSuite() {
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *TokensTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *TokensTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestTokensTestSuite(t *testing.T) {
	suite.Run(t, new(TokensTestSuite))
}
