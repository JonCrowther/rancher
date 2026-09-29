package extension

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
)

// ExtensionAPITestSuite covers Rancher's extension API server on the local cluster: discovery and
// OpenAPI under /ext, which endpoints it authorizes, and CRUD on ext.cattle.io resources through
// Steve. Its tests live in the topic files in this package; this file holds only the shared setup.
// The tests talk to the API over raw HTTP, which the session doesn't track, so each test registers
// its own cleanup.
type ExtensionAPITestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	clusterID string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *ExtensionAPITestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *ExtensionAPITestSuite) TearDownSuite() {
	s.session.Cleanup()
}

func TestExtensionAPITestSuite(t *testing.T) {
	suite.Run(t, new(ExtensionAPITestSuite))
}
