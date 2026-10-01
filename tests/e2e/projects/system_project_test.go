package projects

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rancher/norman/types"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestSystemProjectCannotBeDeleted tests that deleting the System project is rejected with a 405.
func (s *ProjectsTestSuite) TestSystemProjectCannotBeDeleted() {
	client := s.newSubSession()

	projects, err := client.Management.Project.List(&types.ListOpts{
		Filters: map[string]any{
			"clusterId": s.clusterID,
		},
	})
	s.Require().NoError(err)

	var systemProject management.Project
	found := false
	for _, project := range projects.Data {
		if project.Name == "System" {
			systemProject = project
			found = true
			break
		}
	}
	s.Require().True(found, "System project not found")

	// Attempting to delete the System project should return 405.
	err = client.Management.Project.Delete(&systemProject)
	s.Require().Error(err)

	var apiErr *clientbase.APIError
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusMethodNotAllowed, apiErr.StatusCode)
	s.Require().Contains(apiErr.Body, "System Project cannot be deleted")
}

// TestSystemNamespacesDefaultServiceAccount tests that the default service account in every system
// namespace except kube-system has automountServiceAccountToken disabled.
func (s *ProjectsTestSuite) TestSystemNamespacesDefaultServiceAccount() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.ByID("system-namespaces")
	s.Require().NoError(err)

	systemNamespaces := make(map[string]any)
	for ns := range strings.SplitSeq(setting.Value, ",") {
		trimmed := strings.TrimSpace(ns)
		if trimmed != "" {
			systemNamespaces[trimmed] = true
		}
	}

	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)

	saGVR := corev1.SchemeGroupVersion.WithResource("serviceaccounts")

	saList, err := dynamicClient.Resource(saGVR).Namespace("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=default",
	})
	s.Require().NoError(err)

	checked := 0
	for _, sa := range saList.Items {
		ns := sa.GetNamespace()
		if _, ok := systemNamespaces[ns]; !ok || ns == "kube-system" {
			continue
		}
		automount, found, err := unstructured.NestedBool(sa.Object, "automountServiceAccountToken")
		s.Require().NoError(err, "automountServiceAccountToken is not a bool for service account %s in namespace %s", sa.GetName(), ns)
		s.Require().True(found, "automountServiceAccountToken not found for service account %s in namespace %s", sa.GetName(), ns)
		s.Require().False(automount, "automountServiceAccountToken should be false for service account %s in namespace %s", sa.GetName(), ns)
		checked++
	}
	s.Require().NotZero(checked, "no default service accounts found in system namespaces %v", setting.Value)
}
