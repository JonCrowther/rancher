package tokens

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
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

// createStandardUser creates an enabled user with the "user" global role. The returned user's
// Password is set, so it can log in.
func (s *TokensTestSuite) createStandardUser(client *rancher.Client) *management.User {
	enabled := true
	pw := password.GenerateUserPassword("testpass-")
	user, err := users.CreateUserWithRole(client, &management.User{
		Username: namegen.AppendRandomString("user-"),
		Password: pw,
		Name:     "testuser",
		Enabled:  &enabled,
	}, "user")
	s.Require().NoError(err)
	user.Password = pw
	return user
}

func TestTokensTestSuite(t *testing.T) {
	suite.Run(t, new(TokensTestSuite))
}
