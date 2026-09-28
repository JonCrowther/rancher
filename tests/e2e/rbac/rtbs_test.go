package rbac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	extnamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	extrbac "github.com/rancher/rancher/tests/e2e/actions/kubeapi/rbac"
	"github.com/rancher/rancher/tests/e2e/actions/kubeapi/secrets"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	extauthz "github.com/rancher/shepherd/extensions/kubeapi/authorization"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// assertClusterAccessRevoked verifies that the given user client no longer has access to the downstream cluster.
func (p *RBACTestSuite) assertClusterAccessRevoked(userClient *rancher.Client) {
	p.Require().Eventually(func() bool {
		clusters, err := userClient.Management.Cluster.List(nil)
		return err == nil && len(clusters.Data) == 0
	}, 2*time.Minute, 2*time.Second, "failed revoking cluster access from user")

	_, err := userClient.Management.Cluster.ByID(p.downstreamClusterID)
	p.Require().Error(err)
	p.Require().Contains(err.Error(), "403")
}

// TestPRTBRoleTemplateInheritance tests that a user bound by a PRTB to a role template gains the
// permissions of the role templates it inherits from, both directly and through a chain of
// inheritance, and that changes to an inherited role template propagate to the user.
func (p *RBACTestSuite) TestPRTBRoleTemplateInheritance() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	createdNamespace := p.createNamespace(client, p.projectName(p.project))

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Test that user can get a specified secret once granted the permission to do so via roletemplate inheritance bounded
	// by a PRTB.

	secret, err := secrets.CreateSecretForCluster(client, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{GenerateName: "rtb-test-s-"}}, p.downstreamClusterID, createdNamespace.Name)
	p.Require().NoError(err)

	_, err = secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, secret.Name, metav1.GetOptions{})
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden before any binding, got: %v", err)

	rtB, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context: "project",
			Name:    "RoleB",
			Rules: []management.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					ResourceNames: []string{secret.Name},
					Verbs:         []string{"get"},
				},
			},
		})
	p.Require().NoError(err)

	rtA, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context:         "project",
			Name:            "RoleA",
			RoleTemplateIDs: []string{rtB.ID},
		})
	p.Require().NoError(err)

	prtb, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		ProjectID:       p.project.ID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  rtA.ID,
	})
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "get",
			Resource:  "secrets",
			Name:      secret.Name,
			Namespace: createdNamespace.Name,
		},
	})
	p.Require().NoError(err)

	secret, err = secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, secret.Name, metav1.GetOptions{})
	p.Require().NoError(err)

	// Deleting the PRTB before its remove-handler finalizer is added orphans its bindings (see rtbFinalizers).
	p.Require().EventuallyWithT(func(c *assert.CollectT) {
		finalizers, err := rtbFinalizers(client, extrbac.ProjectRoleTemplateBindingGroupVersionResource, prtb.ID)
		assert.NoError(c, err)
		assert.Contains(c, finalizers, prtbRemoveFinalizer)
	}, 2*time.Minute, 2*time.Second, "waiting for the PRTB remove-handler finalizer")

	err = client.Management.ProjectRoleTemplateBinding.Delete(prtb)
	p.Require().NoError(err)

	// Test that user can get a specified secret once granted the permission to do so via a chain of
	// roletemplate inheritance bounded by a PRTB. Here a chain means the permission is not directly inherited from the
	// parent.

	rtC, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context:         "project",
			Name:            "RoleC",
			RoleTemplateIDs: []string{rtA.ID},
		})
	p.Require().NoError(err)

	p.Require().EventuallyWithT(func(c *assert.CollectT) {
		_, err := secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, secret.Name, metav1.GetOptions{})
		assert.Truef(c, apierrors.IsForbidden(err), "expected forbidden, got: %v", err)
	}, 2*time.Minute, 2*time.Second, "waiting for secret access to be revoked after PRTB removal")

	_, err = client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		ProjectID:       p.project.ID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  rtC.ID,
	})
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "get",
			Resource:  "secrets",
			Name:      secret.Name,
			Namespace: createdNamespace.Name,
		},
	})
	p.Require().NoError(err)

	secret, err = secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, secret.Name, metav1.GetOptions{})
	p.Require().NoError(err)

	anotherSecret, err := secrets.CreateSecretForCluster(client, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{GenerateName: "rtb-test-s-"}}, p.downstreamClusterID, createdNamespace.Name)
	p.Require().NoError(err)

	_, err = secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, anotherSecret.Name, metav1.GetOptions{})
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden on a secret not covered by the role, got: %v", err)

	// Test that permissions are updated when inherited roletemplate bound by PRTB is changed.

	updatedRTB := *rtB
	updatedRTB.Rules = append(rtB.Rules, management.PolicyRule{
		APIGroups:     []string{""},
		Resources:     []string{"secrets"},
		ResourceNames: []string{anotherSecret.Name},
		Verbs:         []string{"get"},
	})

	_, err = client.Management.RoleTemplate.Update(rtB, updatedRTB)
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "get",
			Resource:  "secrets",
			Name:      secret.Name,
			Namespace: createdNamespace.Name,
		},
		{
			Verb:      "get",
			Resource:  "secrets",
			Name:      anotherSecret.Name,
			Namespace: createdNamespace.Name,
		},
	})
	p.Require().NoError(err)

	_, err = secrets.GetSecretByName(testUser, p.downstreamClusterID, createdNamespace.Name, anotherSecret.Name, metav1.GetOptions{})
	p.Require().NoError(err)
}

// TestCRTBRoleTemplateInheritance tests that a user bound by a CRTB to a role template gains the
// permissions of the role templates it inherits from, both directly and through a chain of
// inheritance, and that changes to an inherited role template propagate to the user.
func (p *RBACTestSuite) TestCRTBRoleTemplateInheritance() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	// Test that user can get a specified namespace once granted the permission to do so via roletemplate inheritance bounded
	// by a CRTB.

	pn := p.projectName(p.project)
	ns := p.createNamespace(client, pn)

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	_, err = extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns.Name)
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden before any binding, got: %v", err)

	rtB, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context: "",
			Name:    "RoleB",
			Rules: []management.PolicyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"namespaces"},
					ResourceNames: []string{ns.Name},
					Verbs:         []string{"get"},
				},
			},
		})
	p.Require().NoError(err)

	rtA, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context:         "cluster",
			Name:            "RoleA",
			RoleTemplateIDs: []string{rtB.ID},
		})
	p.Require().NoError(err)

	crtb, err := client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		ClusterID:       p.downstreamClusterID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  rtA.ID,
	})
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:     "get",
			Resource: "namespaces",
			Name:     ns.Name,
		},
	})
	p.Require().NoError(err)

	_, err = extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns.Name)
	p.Require().NoError(err)

	// Deleting the CRTB before its remove-handler finalizer is added orphans its bindings (see rtbFinalizers).
	p.Require().EventuallyWithT(func(c *assert.CollectT) {
		finalizers, err := rtbFinalizers(client, extrbac.ClusterRoleTemplateBindingGroupVersionResource, crtb.ID)
		assert.NoError(c, err)
		assert.Contains(c, finalizers, crtbRemoveFinalizer)
	}, 2*time.Minute, 2*time.Second, "waiting for the CRTB remove-handler finalizer")

	err = client.Management.ClusterRoleTemplateBinding.Delete(crtb)
	p.Require().NoError(err)

	// Ensure the user can no longer access the namespace after the CRTB is removed.
	p.Require().EventuallyWithT(func(c *assert.CollectT) {
		_, err := extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns.Name)
		assert.Truef(c, apierrors.IsForbidden(err), "expected forbidden, got: %v", err)
	}, 2*time.Minute, 2*time.Second, "waiting for namespace access to be revoked after CRTB removal")

	// Test that user can get a specified namespace once granted the permission to do so via a chain of
	// roletemplate inheritance bounded by a CRTB. Here a chain means the permission is not directly inherited from the
	// parent.

	rtC, err := client.Management.RoleTemplate.Create(
		&management.RoleTemplate{
			Context:         "cluster",
			Name:            "RoleC",
			RoleTemplateIDs: []string{rtA.ID},
		})
	p.Require().NoError(err)

	_, err = client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		ClusterID:       p.downstreamClusterID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  rtC.ID,
	})
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:     "get",
			Resource: "namespaces",
			Name:     ns.Name,
		},
	})
	p.Require().NoError(err)

	anotherNS := p.createNamespace(client, pn)

	_, err = extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, anotherNS.Name)
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden on a namespace not covered by the role, got: %v", err)

	// Test that permissions are updated when inherited roletemplate bound by CRTB is changed.

	updatedRTB := *rtB
	updatedRTB.Rules = append(rtB.Rules, management.PolicyRule{
		APIGroups:     []string{""},
		Resources:     []string{"namespaces"},
		ResourceNames: []string{anotherNS.Name},
		Verbs:         []string{"get"},
	})

	_, err = client.Management.RoleTemplate.Update(rtB, updatedRTB)
	p.Require().NoError(err)

	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:     "get",
			Resource: "namespaces",
			Name:     ns.Name,
		},
		{
			Verb:     "get",
			Resource: "namespaces",
			Name:     anotherNS.Name,
		},
	})
	p.Require().NoError(err)

	_, err = extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, anotherNS.Name)
	p.Require().NoError(err)
}

// TestAPIGroupInRoleTemplate tests that a cluster role template with API-group-scoped rules grants a
// user bound via a CRTB exactly the listed verbs on those groups' resources.
func (p *RBACTestSuite) TestAPIGroupInRoleTemplate() {
	client := p.newSubSession()

	// Skip if admin can't see any nodes.
	adminNodes, err := client.Management.Node.List(nil)
	p.Require().NoError(err)
	if len(adminNodes.Data) == 0 {
		p.T().Skip("no nodes in the cluster")
	}

	user := p.createUser(client, "testuser", "user")

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Validate the standard user cannot see any nodes initially.
	userNodes, err := testUser.Management.Node.List(nil)
	p.Require().NoError(err)
	p.Require().Empty(userNodes.Data, "standard user should not see any nodes")

	// Create a cluster-scoped role template with apiGroup-specific rules.
	rt, err := client.Management.RoleTemplate.Create(&management.RoleTemplate{
		Context: "cluster",
		Name:    namegen.AppendRandomString("test-rt-"),
		Rules: []management.PolicyRule{
			{
				APIGroups: []string{"management.cattle.io"},
				Resources: []string{"nodes", "nodepools"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"scheduling.k8s.io"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	})
	p.Require().NoError(err)

	// Wait for the role template to be available.
	p.Require().Eventually(func() bool {
		_, err := client.Management.RoleTemplate.ByID(rt.ID)
		return err == nil
	}, 2*time.Minute, 2*time.Second, "role template never became available")

	// Bind the user to the role template via a CRTB using the user's principal ID.
	p.Require().NotEmpty(user.PrincipalIDs, "test user has no principal IDs")
	_, err = client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  rt.ID,
		ClusterID:       p.downstreamClusterID,
	})
	p.Require().NoError(err)

	// Wait for the user to be able to see nodes.
	p.Require().Eventually(func() bool {
		nodes, err := testUser.Management.Node.List(nil)
		return err == nil && len(nodes.Data) > 0
	}, 2*time.Minute, 2*time.Second, "user could never see nodes")

	// Verify user can see nodes.
	userNodes, err = testUser.Management.Node.List(nil)
	p.Require().NoError(err)
	p.Require().NotEmpty(userNodes.Data)

	// Verify user cannot delete a node (role only grants get/list/watch). An access review is used
	// instead of a real delete so a regression can't remove a node from the shared cluster. Node
	// objects live in the management (local) cluster, in the namespace named after their cluster.
	allowed, err := checkAccessAllowed(testUser, "local", &authzv1.ResourceAttributes{
		Verb:      "delete",
		Group:     "management.cattle.io",
		Resource:  "nodes",
		Namespace: p.downstreamClusterID,
	})
	p.Require().NoError(err)
	p.Require().False(allowed, "user should not be allowed to delete nodes")
}

// TestRemovingPRTBRevokesNamespaceAccess tests that removing a user's PRTB from one project revokes
// access to that project's namespaces without affecting access granted by a PRTB in another project.
func (p *RBACTestSuite) TestRemovingPRTBRevokesNamespaceAccess() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Helper function to create a project and add the user as project-member
	createProjectAndAddUser := func() (*management.Project, *management.ProjectRoleTemplateBinding) {
		projectConfig := &management.Project{
			ClusterID: p.downstreamClusterID,
			Name:      namegen.AppendRandomString("test-project-"),
		}

		project, err := client.Management.Project.Create(projectConfig)
		p.Require().NoError(err)

		prtb, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
			UserID:         user.ID,
			RoleTemplateID: "project-member",
			ProjectID:      project.ID,
		})
		p.Require().NoError(err)

		return project, prtb
	}

	// Create two projects and add user to both
	project1, _ := createProjectAndAddUser()
	project2, prtb2 := createProjectAndAddUser()

	// Helper function to add a namespace to a project
	addNamespaceToProject := func(project *management.Project) *corev1.Namespace {
		return p.createNamespace(client, p.projectName(project))
	}

	// Add namespace to first project
	ns1 := addNamespaceToProject(project1)

	// Verify user can access namespace in first project
	p.Require().Eventually(func() bool {
		_, err = extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns1.Name)
		return err == nil
	}, 2*time.Minute, 2*time.Second, "waiting for permissions to be applied to user")

	// Add namespace to second project
	ns2 := addNamespaceToProject(project2)

	// Verify user can access namespace in both projects
	p.Require().Eventually(func() bool {
		_, err1 := extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns1.Name)
		_, err2 := extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns2.Name)
		return err1 == nil && err2 == nil
	}, 2*time.Minute, 2*time.Second, "waiting for permissions to be applied to user")

	// Remove user from second project
	err = client.Management.ProjectRoleTemplateBinding.Delete(prtb2)
	p.Require().NoError(err)

	// Verify user can still access namespace in first project but not in second anymore
	p.Require().NoError(err)
	p.Require().Eventually(func() bool {
		_, err1 := extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns1.Name)
		_, err2 := extnamespaces.GetNamespaceByName(testUser, p.downstreamClusterID, ns2.Name)
		return apierrors.IsForbidden(err2) && err1 == nil
	}, 2*time.Minute, 2*time.Second, "waiting for permissions to be removed from user")
}

// TestDeletingPRTBRemovesClusterAccess tests that deleting a user's only PRTB removes the membership
// ClusterRoleBinding and revokes the user's access to the cluster.
func (p *RBACTestSuite) TestDeletingPRTBRemovesClusterAccess() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Admin creates a PRTB giving user project-member on the suite project.
	prtb, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		UserID:         user.ID,
		RoleTemplateID: "project-member",
		ProjectID:      p.project.ID,
	})
	p.Require().NoError(err)

	// Verify the user can see the cluster.
	p.Require().Eventually(func() bool {
		_, err := testUser.Management.Cluster.ByID(p.downstreamClusterID)
		return err == nil
	}, 2*time.Minute, 2*time.Second, "user could never see the cluster")

	// Derive the label key from the PRTB ID (namespace:name -> namespace_name).
	// The label key is set on the membership CRB; the value varies by RBAC model
	// ("membership-binding-owner" in legacy, "true" with aggregation) so we use
	// a key-exists selector to cover both.
	prtbKey := strings.ReplaceAll(prtb.ID, ":", "_")

	// Wait for the membership ClusterRoleBinding to appear.
	p.Require().Eventually(func() bool {
		crbs, err := extrbac.ListClusterRoleBindings(client, p.downstreamClusterID, metav1.ListOptions{
			LabelSelector: prtbKey,
		})
		return err == nil && len(crbs.Items) == 1
	}, 2*time.Minute, 2*time.Second, fmt.Sprintf("failed waiting for clusterRoleBinding to get created with label %s for prtb %+v", prtbKey, prtb))

	// Deleting the PRTB before its remove-handler finalizer is added orphans its bindings (see rtbFinalizers).
	p.Require().EventuallyWithT(func(c *assert.CollectT) {
		finalizers, err := rtbFinalizers(client, extrbac.ProjectRoleTemplateBindingGroupVersionResource, prtb.ID)
		assert.NoError(c, err)
		assert.Contains(c, finalizers, prtbRemoveFinalizer)
	}, 2*time.Minute, 2*time.Second, "waiting for the PRTB remove-handler finalizer")

	// Delete the PRTB — user should lose access.
	err = client.Management.ProjectRoleTemplateBinding.Delete(prtb)
	p.Require().NoError(err)

	// Wait for the membership ClusterRoleBinding to be deleted.
	p.Require().Eventually(func() bool {
		crbs, err := extrbac.ListClusterRoleBindings(client, p.downstreamClusterID, metav1.ListOptions{
			LabelSelector: prtbKey,
		})
		return err == nil && len(crbs.Items) == 0
	}, 2*time.Minute, 2*time.Second, "failed waiting for clusterRoleBinding to get deleted")

	// Verify the user can no longer see or fetch the cluster.
	p.Require().Eventually(func() bool {
		clusters, err := testUser.Management.Cluster.List(nil)
		return err == nil && len(clusters.Data) == 0
	}, 2*time.Minute, 2*time.Second, "failed revoking cluster access from user")

	_, err = testUser.Management.Cluster.ByID(p.downstreamClusterID)
	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusForbidden, apiErr.StatusCode)
}

// TestDeletingPRTBCleansUpLegacyMembershipLabels tests that deleting a PRTB cleans up the membership
// ClusterRoleBinding labelled with the PRTB's key and revokes the user's access to the cluster.
func (p *RBACTestSuite) TestDeletingPRTBCleansUpLegacyMembershipLabels() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Admin creates a PRTB giving user project-member on the suite project.
	prtb, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		UserID:         user.ID,
		RoleTemplateID: "project-member",
		ProjectID:      p.project.ID,
	})
	p.Require().NoError(err)

	// Verify the user can see the cluster.
	p.Require().Eventually(func() bool {
		_, err := testUser.Management.Cluster.ByID(p.downstreamClusterID)
		return err == nil
	}, 2*time.Minute, 2*time.Second, "user could never see the cluster")

	// The label key is set on the membership CRB; the value varies by RBAC model
	// so we use a key-exists selector to cover both legacy and aggregation.
	prtbKey := strings.ReplaceAll(prtb.ID, ":", "_")

	// Wait for the membership ClusterRoleBinding to appear.
	p.Require().Eventually(func() bool {
		crbs, err := extrbac.ListClusterRoleBindings(client, p.downstreamClusterID, metav1.ListOptions{
			LabelSelector: prtbKey,
		})
		return err == nil && len(crbs.Items) == 1
	}, 2*time.Minute, 2*time.Second, "failed waiting for clusterRoleBinding to get created")

	// Delete the PRTB — user should lose access and the membership CRB should be cleaned up.
	err = client.Management.ProjectRoleTemplateBinding.Delete(prtb)
	p.Require().NoError(err)

	// Wait for the membership ClusterRoleBinding to be gone.
	p.Require().Eventually(func() bool {
		crbs, err := extrbac.ListClusterRoleBindings(client, p.downstreamClusterID, metav1.ListOptions{
			LabelSelector: prtbKey,
		})
		return err == nil && len(crbs.Items) == 0
	}, 2*time.Minute, 2*time.Second, "failed waiting for cluster role bindings to be deleted")

	p.assertClusterAccessRevoked(testUser)
}

// TestCRTBCannotTargetUsersAndGroup tests that creating a CRTB that targets both a user and a group
// is rejected with a 422.
func (p *RBACTestSuite) TestCRTBCannotTargetUsersAndGroup() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	_, err := client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		Name:             namegen.AppendRandomString("crtb-"),
		ClusterID:        p.downstreamClusterID,
		UserID:           user.ID,
		GroupPrincipalID: "someauthprovidergroupid",
		RoleTemplateID:   "clustercatalogs-view",
	})
	p.Require().Error(err)

	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	p.Require().Contains(apiErr.Body, "must target a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]")
}

// TestCRTBMustHaveTarget tests that creating a CRTB with neither a user nor a group target is
// rejected with a 422.
func (p *RBACTestSuite) TestCRTBMustHaveTarget() {
	client := p.newSubSession()

	_, err := client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		Name:           namegen.AppendRandomString("crtb-"),
		ClusterID:      p.downstreamClusterID,
		RoleTemplateID: "clustercatalogs-view",
	})
	p.Require().Error(err)

	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	p.Require().Contains(apiErr.Body, "must target a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]")
}

// TestCRTBCannotUpdateSubjectsOrCluster tests that updates to a CRTB's cluster and subject fields
// are ignored.
func (p *RBACTestSuite) TestCRTBCannotUpdateSubjectsOrCluster() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	oldCRTB, err := client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		Name:           namegen.AppendRandomString("crtb-"),
		ClusterID:      p.downstreamClusterID,
		UserID:         user.ID,
		RoleTemplateID: "clustercatalogs-view",
	})
	p.Require().NoError(err)

	// Wait for userPrincipalId to be populated.
	p.Require().Eventually(func() bool {
		reloaded, err := client.Management.ClusterRoleTemplateBinding.ByID(oldCRTB.ID)
		if err != nil {
			return false
		}
		oldCRTB = reloaded
		return oldCRTB.UserPrincipalID != ""
	}, 2*time.Minute, 2*time.Second, "waiting for userPrincipalId to be populated")

	// Attempt to update immutable fields.
	updatedCRTB, err := client.Management.ClusterRoleTemplateBinding.Update(oldCRTB, map[string]interface{}{
		"clusterId":        "fakecluster",
		"userId":           "",
		"userPrincipalId":  "asdf",
		"groupPrincipalId": "asdf",
		"groupId":          "asdf",
	})
	p.Require().NoError(err)

	p.Require().Equal(oldCRTB.ClusterID, updatedCRTB.ClusterID)
	p.Require().Equal(oldCRTB.UserID, updatedCRTB.UserID)
	p.Require().Equal(oldCRTB.UserPrincipalID, updatedCRTB.UserPrincipalID)
	p.Require().Equal(oldCRTB.GroupPrincipalID, updatedCRTB.GroupPrincipalID)
	p.Require().Equal(oldCRTB.GroupID, updatedCRTB.GroupID)
}
