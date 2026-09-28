package projects

import (
	"github.com/rancher/rancher/tests/e2e/actions/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	extauthz "github.com/rancher/shepherd/extensions/kubeapi/authorization"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	authzv1 "k8s.io/api/authorization/v1"
)

// createProjectAndUser creates a project in the cluster under test and a user with the standard
// "user" global role, returned with its password set so the caller can act as it.
func (s *ProjectsTestSuite) createProjectAndUser(client *rancher.Client) (*management.Project, *management.User) {
	project, err := client.Management.Project.Create(&management.Project{
		ClusterID: s.clusterID,
		Name:      namegen.AppendRandomString("testproject-"),
	})
	s.Require().NoError(err)

	enabled := true
	pw := password.GenerateUserPassword("testpass-")
	user, err := users.CreateUserWithRole(client, &management.User{
		Username: namegen.AppendRandomString("testuser-"),
		Password: pw,
		Name:     "testuser",
		Enabled:  &enabled,
	}, "user")
	s.Require().NoError(err)
	user.Password = pw
	return project, user
}

// TestCreateNamespaceProjectMember asserts that a user bound to the project-member role can create
// a namespace in the project.
func (s *ProjectsTestSuite) TestCreateNamespaceProjectMember() {
	client := s.newSubSession()
	project, user := s.createProjectAndUser(client)

	_, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		ProjectID:       project.ID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  "project-member",
	})
	s.Require().NoError(err)

	userClient, err := client.AsUser(user)
	s.Require().NoError(err)

	err = extauthz.WaitForAllowed(userClient, project.ClusterID, []*authzv1.ResourceAttributes{
		{Verb: "create", Resource: "namespaces"},
	})
	s.Require().NoError(err)

	namespaceName := namegen.AppendRandomString("testns-")
	createdNamespace, err := namespaces.CreateNamespace(userClient, namespaceName, "{}", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)
	s.Equal(namespaceName, createdNamespace.Name)
}

// TestCreateNamespaceProjectOwner asserts that a user bound to the project-owner role can create a
// namespace in the project.
func (s *ProjectsTestSuite) TestCreateNamespaceProjectOwner() {
	client := s.newSubSession()
	project, user := s.createProjectAndUser(client)

	_, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		ProjectID:       project.ID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  "project-owner",
	})
	s.Require().NoError(err)

	userClient, err := client.AsUser(user)
	s.Require().NoError(err)

	err = extauthz.WaitForAllowed(userClient, project.ClusterID, []*authzv1.ResourceAttributes{
		{Verb: "create", Resource: "namespaces"},
	})
	s.Require().NoError(err)

	namespaceName := namegen.AppendRandomString("testns-")
	createdNamespace, err := namespaces.CreateNamespace(userClient, namespaceName, "{}", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)
	s.Equal(namespaceName, createdNamespace.Name)
}
