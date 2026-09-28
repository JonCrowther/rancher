package rbac

import (
	"context"
	"strings"
	"testing"

	extnamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	extunstructured "github.com/rancher/shepherd/extensions/unstructured"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	"github.com/rancher/shepherd/pkg/api/scheme"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	authzv1.SchemeBuilder.AddToScheme(scheme.Scheme.Scheme)
}

// RBACTestSuite covers Rancher's RBAC behavior: role templates and their bindings, global roles,
// default role assignment, project access, impersonation, and features. Its tests are
// split across the files in this package by topic; this file holds only the shared setup and helpers.
type RBACTestSuite struct {
	suite.Suite
	client              *rancher.Client
	project             *management.Project
	session             *session.Session
	downstreamClusterID string
}

func (p *RBACTestSuite) SetupSuite() {
	p.downstreamClusterID = "local"
	testSession := session.NewSession()
	p.session = testSession

	client, err := rancher.NewClient("", testSession)
	p.Require().NoError(err)

	p.client = client

	// Shared by every test that doesn't need an isolated project. Created through the suite session,
	// so TearDownSuite's session cleanup deletes it.
	projectConfig := &management.Project{
		ClusterID: p.downstreamClusterID,
		Name:      namegen.AppendRandomString("rbac-suite-"),
	}

	testProject, err := client.Management.Project.Create(projectConfig)
	p.Require().NoError(err)

	p.project = testProject
}

func (p *RBACTestSuite) TearDownSuite() {
	p.session.Cleanup()
}

// newSubSession creates a new sub-session client for test isolation.
func (p *RBACTestSuite) newSubSession() *rancher.Client {
	subSession := p.session.NewSession()
	client, err := p.client.WithSession(subSession)
	p.Require().NoError(err)
	p.T().Cleanup(subSession.Cleanup)
	return client
}

// createUser creates a new user with the given global role and returns it with password set.
func (p *RBACTestSuite) createUser(client *rancher.Client, prefix, globalRole string) *management.User {
	enabled := true
	pw := password.GenerateUserPassword("testpass-")
	user, err := users.CreateUserWithRole(client, &management.User{
		Username: namegen.AppendRandomString(prefix + "-"),
		Password: pw,
		Name:     prefix,
		Enabled:  &enabled,
	}, globalRole)
	p.Require().NoError(err)
	user.Password = pw
	return user
}

// projectName extracts the project namespace name from a project ID (e.g. "local:p-xxxxx" → "p-xxxxx").
func (p *RBACTestSuite) projectName(project *management.Project) string {
	p.Require().NotNil(project)
	_, name, found := strings.Cut(project.ID, ":")
	p.Require().True(found, "projectName: invalid project ID %q, expected format <cluster>:<project>", project.ID)
	return name
}

// createNamespace creates a namespace in the given project with default settings.
func (p *RBACTestSuite) createNamespace(client *rancher.Client, projName string) *corev1.Namespace {
	ns, err := extnamespaces.CreateNamespace(client, p.downstreamClusterID, projName, namegen.AppendRandomString("testns-"), "{}", map[string]string{}, map[string]string{})
	p.Require().NoError(err)
	return ns
}

// checkAccessAllowed performs a single SelfSubjectAccessReview and returns whether access is allowed.
func checkAccessAllowed(client *rancher.Client, clusterID string, attr *authzv1.ResourceAttributes) (bool, error) {
	dynamicClient, err := client.GetDownStreamClusterClient(clusterID)
	if err != nil {
		return false, err
	}

	ssar := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: attr,
		},
	}

	ssarGVR := authzv1.SchemeGroupVersion.WithResource("selfsubjectaccessreviews")
	resp, err := dynamicClient.Resource(ssarGVR).Create(context.TODO(), extunstructured.MustToUnstructured(ssar), metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	result := &authzv1.SelfSubjectAccessReview{}
	if err := scheme.Scheme.Convert(resp, result, resp.GroupVersionKind()); err != nil {
		return false, err
	}

	return result.Status.Allowed, nil
}

func TestRBACTestSuite(t *testing.T) {
	suite.Run(t, new(RBACTestSuite))
}
