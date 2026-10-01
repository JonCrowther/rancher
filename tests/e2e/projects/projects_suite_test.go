package projects

import (
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/api/scheme"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	authzv1 "k8s.io/api/authorization/v1"
)

func init() {
	authzv1.SchemeBuilder.AddToScheme(scheme.Scheme.Scheme)
}

// ProjectsTestSuite covers projects in Rancher's local cluster: which project roles can create
// namespaces, project resource quota validation, propagation to namespaces and usage tracking, and
// the System project and system namespaces. Its tests live in project_user_test.go,
// project_quotas_test.go and system_project_test.go; this file holds only the shared setup.
type ProjectsTestSuite struct {
	suite.Suite
	client    *rancher.Client
	session   *session.Session
	clusterID string // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *ProjectsTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client
}

func (s *ProjectsTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (s *ProjectsTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

func TestProjectsTestSuite(t *testing.T) {
	suite.Run(t, new(ProjectsTestSuite))
}
