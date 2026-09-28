package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	extnamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	extrbac "github.com/rancher/rancher/tests/e2e/actions/kubeapi/rbac"
	"github.com/rancher/rancher/tests/e2e/actions/kubeapi/secrets"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	extauthz "github.com/rancher/shepherd/extensions/kubeapi/authorization"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

// TestProjectCreatorGetsOwnerBindings tests that a cluster-member who creates a project is bound
// as its owner and gains owner permissions in the project's namespaces.
func (p *RBACTestSuite) TestProjectCreatorGetsOwnerBindings() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	// Grant user the cluster-member role on the local cluster.
	_, err := client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
		ClusterID:       p.downstreamClusterID,
		UserPrincipalID: user.PrincipalIDs[0],
		RoleTemplateID:  "cluster-member",
	})
	p.Require().NoError(err)

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// User creates a project, retrying until RBAC propagates.
	var project *management.Project
	p.Require().Eventually(func() bool {
		project, err = testUser.Management.Project.Create(&management.Project{
			ClusterID: p.downstreamClusterID,
			Name:      namegen.AppendRandomString("test-proj-"),
		})
		return err == nil
	}, 2*time.Minute, 2*time.Second, "waiting for user to be able to create a project")

	// Wait for project to become active.
	p.Require().Eventually(func() bool {
		proj, err := testUser.Management.Project.ByID(project.ID)
		return err == nil && proj.State == "active"
	}, 2*time.Minute, 2*time.Second, "waiting for project to become active")

	// Wait until user can create namespaces.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:     "create",
			Resource: "namespaces",
			Group:    "",
		},
	})
	p.Require().NoError(err)

	// User creates a namespace in the project.
	ns := p.createNamespace(testUser, p.projectName(project))

	// Verify user can list pods in the namespace (proves basic access). The per-namespace bindings
	// are created asynchronously by the roletemplate controllers, so wait for the permission to
	// propagate rather than checking once.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "list",
			Resource:  "pods",
			Group:     "",
			Namespace: ns.Name,
		},
	})
	p.Require().NoError(err)

	// Verify the user has a project-owner RoleBinding in the namespace. The RoleRef name depends on
	// the RBAC model ("project-owner" in the legacy model, "project-owner-aggregator" when the
	// aggregated-roletemplates feature is enabled), so match by prefix and wait for it to appear.
	p.Require().Eventually(func() bool {
		rbs, err := extrbac.ListRoleBindings(client, p.downstreamClusterID, ns.Name, metav1.ListOptions{})
		if err != nil {
			return false
		}
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if subject.Name == user.ID && strings.HasPrefix(rb.RoleRef.Name, "project-owner") {
					return true
				}
			}
		}
		return false
	}, 2*time.Minute, 2*time.Second, "expected a project-owner role binding for the user")

	// Verify user can create deployments (extensions group) in the namespace.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "create",
			Resource:  "deployments",
			Group:     "extensions",
			Namespace: ns.Name,
		},
	})
	p.Require().NoError(err)

	// Verify user can list pods.metrics.k8s.io in the namespace.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "list",
			Resource:  "pods",
			Group:     "metrics.k8s.io",
			Namespace: ns.Name,
		},
	})
	p.Require().NoError(err)
}

// TestReadOnlyCannotEditSecret tests that a user with the read-only project role can neither create
// nor update secrets in the project's namespaces.
func (p *RBACTestSuite) TestReadOnlyCannotEditSecret() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	// Create a PRTB giving the test user read-only access to the project.
	_, err := client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		UserID:         user.ID,
		RoleTemplateID: "read-only",
		ProjectID:      p.project.ID,
	})
	p.Require().NoError(err)

	// Create a namespace in the project for testing namespaced secrets.
	ns := p.createNamespace(client, p.projectName(p.project))

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Wait until the read-only binding is in effect, so the denials below are caused by the role
	// and not by the binding still propagating.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:      "list",
			Resource:  "pods",
			Namespace: ns.Name,
		},
	})
	p.Require().NoError(err)

	// Read-only user should fail to create a secret.
	_, err = secrets.CreateSecretForCluster(testUser, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-secret-"},
		StringData: map[string]string{"abc": "123"},
	}, p.downstreamClusterID, ns.Name)
	p.Require().Error(err)
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden, got: %v", err)

	// Admin creates a secret so the read-only user can see it but not update it.
	adminSecret, err := secrets.CreateSecretForCluster(client, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-secret-"},
		StringData: map[string]string{"abc": "123"},
	}, p.downstreamClusterID, ns.Name)
	p.Require().NoError(err)

	// Read-only user should fail to update the secret.
	_, err = secrets.PatchSecret(testUser, p.downstreamClusterID, adminSecret.Name, ns.Name,
		k8stypes.JSONPatchType, secrets.ReplacePatchOP, "/data/abc", "ZmdoCg==", metav1.PatchOptions{})
	p.Require().Error(err)
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden, got: %v", err)
}

// TestReadOnlyCannotMoveNamespace tests that a user with the read-only role on two projects cannot
// move a namespace from one project to the other.
func (p *RBACTestSuite) TestReadOnlyCannotMoveNamespace() {
	client := p.newSubSession()

	user := p.createUser(client, "testuser", "user")

	// Create two projects.
	p1, err := client.Management.Project.Create(&management.Project{
		ClusterID: p.downstreamClusterID,
		Name:      namegen.AppendRandomString("test-proj-"),
	})
	p.Require().NoError(err)

	p2, err := client.Management.Project.Create(&management.Project{
		ClusterID: p.downstreamClusterID,
		Name:      namegen.AppendRandomString("test-proj-"),
	})
	p.Require().NoError(err)

	// Wait for project namespaces to exist.
	p1Name := strings.ReplaceAll(p1.ID, ":", "-")
	p2Name := strings.ReplaceAll(p2.ID, ":", "-")

	p.Require().Eventually(func() bool {
		_, err1 := extnamespaces.GetNamespaceByName(client, p.downstreamClusterID, p1Name)
		_, err2 := extnamespaces.GetNamespaceByName(client, p.downstreamClusterID, p2Name)
		return err1 == nil && err2 == nil
	}, 2*time.Minute, 2*time.Second, fmt.Sprintf("waiting for project namespaces %s and %s to exist", p1Name, p2Name))

	// Give the test user read-only access to both projects.
	_, err = client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		UserID:         user.ID,
		RoleTemplateID: "read-only",
		ProjectID:      p1.ID,
	})
	p.Require().NoError(err)

	_, err = client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
		UserID:         user.ID,
		RoleTemplateID: "read-only",
		ProjectID:      p2.ID,
	})
	p.Require().NoError(err)

	// Create a namespace in project 1.
	ns := p.createNamespace(client, p.projectName(p1))

	testUser, err := client.AsUser(user)
	p.Require().NoError(err)

	// Wait until the read-only user can see the namespace.
	err = extauthz.WaitForAllowed(testUser, p.downstreamClusterID, []*authzv1.ResourceAttributes{
		{
			Verb:     "get",
			Resource: "namespaces",
			Name:     ns.Name,
		},
	})
	p.Require().NoError(err)

	// Read-only user should fail to move the namespace to project 2 by updating the projectId annotation.
	dynamicClient, err := testUser.GetDownStreamClusterClient(p.downstreamClusterID)
	p.Require().NoError(err)

	nsGVR := corev1.SchemeGroupVersion.WithResource("namespaces")
	patchPayload := fmt.Sprintf(`{"metadata":{"annotations":{"field.cattle.io/projectId":"%s:%s"}}}`, p.downstreamClusterID, p.projectName(p2))
	_, err = dynamicClient.Resource(nsGVR).Patch(context.TODO(), ns.Name, k8stypes.MergePatchType, []byte(patchPayload), metav1.PatchOptions{})
	p.Require().Error(err)
	p.Require().True(apierrors.IsForbidden(err), "expected forbidden, got: %v", err)
}
