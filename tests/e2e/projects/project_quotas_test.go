package projects

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	extnamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// createNamespaceWithQuota creates a namespace in the given project with an optional
// resource quota annotation. If quota is nil, no resource quota annotation is set and
// the project's namespaceDefaultResourceQuota will apply.
func (s *ProjectsTestSuite) createNamespaceWithQuota(client *rancher.Client, project *management.Project, quota map[string]string) *corev1.Namespace {
	_, projName, found := strings.Cut(project.ID, ":")
	s.Require().True(found, "invalid project ID %q, expected format <cluster>:<project>", project.ID)

	annotations := map[string]string{}
	if quota != nil {
		q := map[string]any{"limit": quota}
		b, err := json.Marshal(q)
		s.Require().NoError(err)
		annotations["field.cattle.io/resourceQuota"] = string(b)
	}
	ns, err := extnamespaces.CreateNamespace(client, s.clusterID, projName, namegen.AppendRandomString("testns-"), "{}", map[string]string{}, annotations)
	s.Require().NoError(err)
	return ns
}

// resourceQuotaHard returns spec.hard of the ResourceQuota that the Rancher quota controller
// creates in the given namespace (identified by the default-resource-quota label). It returns a
// nil map if the controller hasn't created the ResourceQuota yet (or has deleted it), and an error
// if there is more than one.
func (s *ProjectsTestSuite) resourceQuotaHard(client *rancher.Client, nsName string) (map[string]string, error) {
	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	if err != nil {
		return nil, err
	}

	rqGVR := corev1.SchemeGroupVersion.WithResource("resourcequotas")
	rqList, err := dynamicClient.Resource(rqGVR).Namespace(nsName).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "resourcequota.management.cattle.io/default-resource-quota=true",
	})
	if err != nil || len(rqList.Items) == 0 {
		return nil, err
	}
	if len(rqList.Items) > 1 {
		return nil, fmt.Errorf("expected at most 1 ResourceQuota in namespace %s, got %d", nsName, len(rqList.Items))
	}

	specRaw, found, err := unstructured.NestedMap(rqList.Items[0].Object, "spec", "hard")
	if err != nil || !found {
		return nil, err
	}
	hard := make(map[string]string, len(specRaw))
	for k, v := range specRaw {
		hard[k] = fmt.Sprintf("%v", v)
	}
	return hard, nil
}

// projectUsedLimit returns the project's usedLimit for the given field ("pods" or "services").
// An unset usedLimit is reported as "0".
func (s *ProjectsTestSuite) projectUsedLimit(client *rancher.Client, projectID, field string) (string, error) {
	proj, err := client.Management.Project.ByID(projectID)
	if err != nil {
		return "", err
	}
	if proj.ResourceQuota == nil {
		return "", fmt.Errorf("project %s has no resourceQuota", projectID)
	}
	if proj.ResourceQuota.UsedLimit == nil {
		return "0", nil
	}

	var used string
	switch field {
	case "pods":
		used = proj.ResourceQuota.UsedLimit.Pods
	case "services":
		used = proj.ResourceQuota.UsedLimit.Services
	default:
		return "", fmt.Errorf("unsupported usedLimit field %q", field)
	}
	if used == "" {
		return "0", nil
	}
	return used, nil
}

// TestProjectResourceQuotaFields tests that creating a project with a resource quota
// and namespace default resource quota correctly stores those fields.
func (s *ProjectsTestSuite) TestProjectResourceQuotaFields() {
	client := s.newSubSession()

	pq := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}
	nsq := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}

	project, err := client.Management.Project.Create(&management.Project{
		Name:                          namegen.AppendRandomString("test-"),
		ClusterID:                     s.clusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsq,
	})
	s.Require().NoError(err)

	s.Require().NotNil(project.ResourceQuota)
	s.Require().Equal("100", project.ResourceQuota.Limit.Pods)
	s.Require().NotNil(project.NamespaceDefaultResourceQuota)
	s.Require().Equal("100", project.NamespaceDefaultResourceQuota.Limit.Pods)
}

// TestProjectQuotaAPIValidation tests project-level resource quota API validation:
// - namespaceDefaultResourceQuota must be provided when resourceQuota is set
// - resourceQuota must be provided when namespaceDefaultResourceQuota is set
// - namespace default quota fields must not exceed project quota
// - namespace default quota must have all fields defined on the project quota
func (s *ProjectsTestSuite) TestProjectQuotaAPIValidation() {
	client := s.newSubSession()

	pq := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}
	nsqLarge := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "200"},
	}

	var apiErr *clientbase.APIError

	// resourceQuota without namespaceDefaultResourceQuota should fail (422).
	_, err := client.Management.Project.Create(&management.Project{
		Name:          namegen.AppendRandomString("test-"),
		ClusterID:     s.clusterID,
		ResourceQuota: pq,
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// namespaceDefaultResourceQuota without resourceQuota should fail (422).
	_, err = client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Namespace default quota exceeding project quota should fail (422).
	_, err = client.Management.Project.Create(&management.Project{
		Name:                          namegen.AppendRandomString("test-"),
		ClusterID:                     s.clusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsqLarge,
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Namespace default quota missing fields defined on project quota should fail (422).
	pqMulti := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100", Services: "100"},
	}
	nsqIncomplete := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}

	proj, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
	})
	s.Require().NoError(err)

	_, err = client.Management.Project.Update(proj, map[string]any{
		"resourceQuota":                 pqMulti,
		"namespaceDefaultResourceQuota": nsqIncomplete,
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}

// TestProjectContainerDefaultResourceLimit tests that creating a project with a
// containerDefaultResourceLimit correctly stores the limit, and that it can be cleared.
func (s *ProjectsTestSuite) TestProjectContainerDefaultResourceLimit() {
	client := s.newSubSession()

	pq := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}
	nsq := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}
	lmt := &management.ContainerResourceLimit{
		RequestsCPU:    "1",
		RequestsMemory: "1Gi",
		LimitsCPU:      "2",
		LimitsMemory:   "2Gi",
	}

	project, err := client.Management.Project.Create(&management.Project{
		Name:                          namegen.AppendRandomString("test-"),
		ClusterID:                     s.clusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsq,
		ContainerDefaultResourceLimit: lmt,
	})
	s.Require().NoError(err)
	s.Require().NotNil(project.ResourceQuota)
	s.Require().NotNil(project.ContainerDefaultResourceLimit)

	// Clear the container limit.
	updated, err := client.Management.Project.Update(project, map[string]any{
		"containerDefaultResourceLimit": nil,
	})
	s.Require().NoError(err)
	s.Require().Nil(updated.ContainerDefaultResourceLimit)
}

// TestNamespaceResourceQuotaCreated tests that when a namespace is created in a project
// with an explicit resource quota annotation, the Rancher controller creates a k8s
// ResourceQuota object in the namespace with the requested limits, dropping any limit the
// project quota doesn't define.
func (s *ProjectsTestSuite) TestNamespaceResourceQuotaCreated() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	s.Require().NoError(err)

	// configMaps isn't in the project quota, so it shouldn't reach the namespace's ResourceQuota.
	ns := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "4", "configMaps": "50"})

	var hard map[string]string
	s.Require().Eventually(func() bool {
		h, err := s.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	s.Require().Equal(map[string]string{"pods": "4"}, hard)
}

// TestNamespaceDefaultQuotaApplied tests that when a namespace is created in a project
// without an explicit quota annotation, the project's namespaceDefaultResourceQuota is
// applied by the controller.
func (s *ProjectsTestSuite) TestNamespaceDefaultQuotaApplied() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	s.Require().NoError(err)

	// Create namespace without explicit quota — should get the project default.
	ns := s.createNamespaceWithQuota(client, project, nil)

	var hard map[string]string
	s.Require().Eventually(func() bool {
		h, err := s.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	s.Require().Equal("4", hard["pods"])
}

// TestProjectQuotaUpdateAppliedToNamespace tests that when a project is updated to
// add a resource quota, existing namespaces in the project get a ResourceQuota created.
func (s *ProjectsTestSuite) TestProjectQuotaUpdateAppliedToNamespace() {
	client := s.newSubSession()

	// Create project without quota.
	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
	})
	s.Require().NoError(err)

	// Create a namespace (no quota yet on the project).
	ns := s.createNamespaceWithQuota(client, project, nil)

	// Update the project to add quota.
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	s.Require().NoError(err)

	// The controller should apply the default quota to the existing namespace.
	var hard map[string]string
	s.Require().Eventually(func() bool {
		h, err := s.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	s.Require().Equal("4", hard["pods"])
}

// TestAddQuotaFromProjectWithNamespacePropagation asserts that adding a limit to a project's quotas
// adds it to an existing namespace's ResourceQuota.
func (s *ProjectsTestSuite) TestAddQuotaFromProjectWithNamespacePropagation() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{LimitsCPU: "500m"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{LimitsCPU: "200m"},
		},
	})
	s.Require().NoError(err)

	ns := s.createNamespaceWithQuota(client, project, nil)

	// Precondition: the namespace's quota exists before the project changes, so the new limit has
	// to propagate to an existing quota rather than being part of the initial one.
	wantBefore := map[string]string{"limits.cpu": "200m"}
	s.EventuallyWithT(func(c *assert.CollectT) {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		assert.NoError(c, err)
		assert.Equal(c, wantBefore, hard)
	}, time.Minute, 2*time.Second, "waiting for the namespace default quota in %s", ns.Name)

	project.ResourceQuota.Limit.Secrets = "20"
	project.NamespaceDefaultResourceQuota.Limit.Secrets = "10"
	_, err = client.Management.Project.Replace(project)
	s.Require().NoError(err)

	// The quota controller sometimes gets a conflict updating the namespace annotation and retries.
	wantAfter := map[string]string{"limits.cpu": "200m", "secrets": "10"}
	s.EventuallyWithT(func(c *assert.CollectT) {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		assert.NoError(c, err)
		assert.Equal(c, wantAfter, hard)
	}, time.Minute, 2*time.Second, "waiting for the secrets limit to be added to the quota in %s", ns.Name)
}

// TestRemoveQuotaFromProjectWithNamespacePropagation asserts that removing limits from a project's
// quotas removes them from its namespaces' ResourceQuotas, and removing the last one deletes the
// ResourceQuota.
func (s *ProjectsTestSuite) TestRemoveQuotaFromProjectWithNamespacePropagation() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{LimitsCPU: "500m", ConfigMaps: "10"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{LimitsCPU: "200m", ConfigMaps: "5"},
		},
	})
	s.Require().NoError(err)

	ns := s.createNamespaceWithQuota(client, project, nil)

	// Precondition: the namespace starts with both limits, so their removal below is a change.
	wantBefore := map[string]string{"limits.cpu": "200m", "configmaps": "5"}
	s.EventuallyWithT(func(c *assert.CollectT) {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		assert.NoError(c, err)
		assert.Equal(c, wantBefore, hard)
	}, time.Minute, 2*time.Second, "waiting for the namespace default quota in %s", ns.Name)

	project.ResourceQuota.Limit.LimitsCPU = ""
	project.NamespaceDefaultResourceQuota.Limit.LimitsCPU = ""
	project, err = client.Management.Project.Replace(project)
	s.Require().NoError(err)

	// The quota controller sometimes gets a conflict updating the namespace annotation and retries.
	wantAfter := map[string]string{"configmaps": "5"}
	s.EventuallyWithT(func(c *assert.CollectT) {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		assert.NoError(c, err)
		assert.Equal(c, wantAfter, hard)
	}, time.Minute, 2*time.Second, "waiting for the CPU limit to be removed from the quota in %s", ns.Name)

	// Now remove the last resource limit from the project.
	project.ResourceQuota.Limit.ConfigMaps = ""
	project.NamespaceDefaultResourceQuota.Limit.ConfigMaps = ""
	_, err = client.Management.Project.Replace(project)
	s.Require().NoError(err)

	s.EventuallyWithT(func(c *assert.CollectT) {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		assert.NoError(c, err)
		assert.Nil(c, hard)
	}, time.Minute, 2*time.Second, "waiting for the quota in %s to be deleted", ns.Name)
}

// TestNamespaceQuotaExceedsProjectLimit tests that the controller handles a namespace
// whose requested quota exceeds the project limit by zeroing overused resources in the
// created k8s ResourceQuota, and that the project's usedLimit is not inflated.
func (s *ProjectsTestSuite) TestNamespaceQuotaExceedsProjectLimit() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	s.Require().NoError(err)

	// Create namespace requesting more pods than the project allows.
	ns := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "200"})

	// The controller should still create a ResourceQuota, but with the overused resource zeroed.
	var hard map[string]string
	s.Require().Eventually(func() bool {
		h, err := s.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	s.Require().Equal("0", hard["pods"], "overused pods quota should be zeroed")

	// A namespace whose quota failed validation doesn't count towards the project's usage.
	used, err := s.projectUsedLimit(client, project.ID, "pods")
	s.Require().NoError(err)
	s.Require().Equal("0", used, "project usedLimit should not include the overused namespace")
}

// TestProjectUsedQuotaUpdated tests that the project's usedLimit is updated by the
// controller when namespaces with quotas are created in the project.
func (s *ProjectsTestSuite) TestProjectUsedQuotaUpdated() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	s.Require().NoError(err)

	// Create namespace — default quota of 4 pods should apply.
	ns := s.createNamespaceWithQuota(client, project, nil)
	s.Require().Eventually(func() bool {
		hard, err := s.resourceQuotaHard(client, ns.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)

	s.Require().Eventually(func() bool {
		used, err := s.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "4"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=4")
}

// TestProjectUsedQuotaExactMatch tests that when all of a project's quota is consumed
// by namespaces, the project quota cannot be reduced below the used amount.
func (s *ProjectsTestSuite) TestProjectUsedQuotaExactMatch() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	s.Require().NoError(err)

	// Create two namespaces: 2 + 8 = 10 pods (full quota).
	ns1 := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "2"})
	s.Require().Eventually(func() bool {
		hard, err := s.resourceQuotaHard(client, ns1.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns1.Name)

	ns2 := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "8"})
	s.Require().Eventually(func() bool {
		hard, err := s.resourceQuotaHard(client, ns2.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns2.Name)

	s.Require().Eventually(func() bool {
		used, err := s.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "10"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=10")

	// Try reducing the project quota below the used amount — should fail (422).
	var apiErr *clientbase.APIError
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "8"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "1"},
		},
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}

// TestProjectQuotaAddRemoveFields tests adding and removing quota fields on a project
// and verifying that the usedLimit is updated accordingly.
func (s *ProjectsTestSuite) TestProjectQuotaAddRemoveFields() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	s.Require().NoError(err)

	// Create two namespaces using the default quota of 2 pods each.
	ns1 := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "2"})
	s.Require().Eventually(func() bool {
		hard, err := s.resourceQuotaHard(client, ns1.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns1.Name)
	s.Require().Eventually(func() bool {
		used, err := s.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "2"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=2")

	ns2 := s.createNamespaceWithQuota(client, project, map[string]string{"pods": "2"})
	s.Require().Eventually(func() bool {
		hard, err := s.resourceQuotaHard(client, ns2.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns2.Name)
	s.Require().Eventually(func() bool {
		used, err := s.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "4"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=4")

	// Trying to add services field with a default that exceeds project limit should fail.
	var apiErr *clientbase.APIError
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10", Services: "10"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2", Services: "7"},
		},
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Add services field with a valid default.
	project, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10", Services: "10"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2", Services: "2"},
		},
	})
	s.Require().NoError(err)

	// Controller should propagate services default to existing namespaces.
	s.Require().Eventually(func() bool {
		used, err := s.projectUsedLimit(client, project.ID, "services")
		return err == nil && used == "4"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.services=4")

	// Remove the services field — verify the update succeeds.
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	s.Require().NoError(err)

	// NOTE: We do not assert that usedLimit.services converges to 0 because the
	// reconcile controller (Norman-triggered) may enqueue namespaces before the
	// Wrangler project cache is updated, causing the sync controller to read a
	// stale project default and skip the namespace annotation cleanup. This is a
	// known eventual-consistency gap between the Norman and Wrangler informers.
	//
	// Tracking issue: https://github.com/rancher/rancher/issues/55060
	//
	// After removing services, usedLimit.services should drop to 0.
	// s.Require().Eventually(func() bool {
	// 	used, err := s.projectUsedLimit(client, project.ID, "services")
	// 	return err == nil && used == "0"
	// }, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.services=0")
}

// TestProjectQuotaCannotExceedWithExistingNamespaces tests that setting a project quota
// where default * existing namespace count exceeds the limit is rejected.
func (s *ProjectsTestSuite) TestProjectQuotaCannotExceedWithExistingNamespaces() {
	client := s.newSubSession()

	// Create project without quota.
	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: s.clusterID,
	})
	s.Require().NoError(err)

	// Create 4 namespaces in the project.
	for range 4 {
		s.createNamespaceWithQuota(client, project, nil)
	}

	// Try setting quota where default (2) * 4 namespaces = 8 > limit (5) — should fail.
	var apiErr *clientbase.APIError
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "5"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	s.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	s.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}
