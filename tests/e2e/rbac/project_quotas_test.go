package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	extnamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// createNamespaceWithQuota creates a namespace in the given project with an optional
// resource quota annotation. If quota is nil, no resource quota annotation is set and
// the project's namespaceDefaultResourceQuota will apply.
func (p *RBACTestSuite) createNamespaceWithQuota(client *rancher.Client, projName string, quota map[string]string) *corev1.Namespace {
	annotations := map[string]string{}
	if quota != nil {
		q := map[string]any{"limit": quota}
		b, err := json.Marshal(q)
		p.Require().NoError(err)
		annotations["field.cattle.io/resourceQuota"] = string(b)
	}
	ns, err := extnamespaces.CreateNamespace(client, p.downstreamClusterID, projName, namegen.AppendRandomString("testns-"), "{}", map[string]string{}, annotations)
	p.Require().NoError(err)
	return ns
}

// resourceQuotaHard returns spec.hard of the ResourceQuota that the Rancher quota controller
// creates in the given namespace (identified by the default-resource-quota label). It returns a
// nil map if the controller hasn't created the ResourceQuota yet.
func (p *RBACTestSuite) resourceQuotaHard(client *rancher.Client, nsName string) (map[string]string, error) {
	dynamicClient, err := client.GetDownStreamClusterClient(p.downstreamClusterID)
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
func (p *RBACTestSuite) projectUsedLimit(client *rancher.Client, projectID, field string) (string, error) {
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
func (p *RBACTestSuite) TestProjectResourceQuotaFields() {
	client := p.newSubSession()

	pq := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}
	nsq := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}

	project, err := client.Management.Project.Create(&management.Project{
		Name:                          namegen.AppendRandomString("test-"),
		ClusterID:                     p.downstreamClusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsq,
	})
	p.Require().NoError(err)

	p.Require().NotNil(project.ResourceQuota)
	p.Require().Equal("100", project.ResourceQuota.Limit.Pods)
	p.Require().NotNil(project.NamespaceDefaultResourceQuota)
	p.Require().Equal("100", project.NamespaceDefaultResourceQuota.Limit.Pods)
}

// TestProjectQuotaAPIValidation tests project-level resource quota API validation:
// - namespaceDefaultResourceQuota must be provided when resourceQuota is set
// - resourceQuota must be provided when namespaceDefaultResourceQuota is set
// - namespace default quota fields must not exceed project quota
// - namespace default quota must have all fields defined on the project quota
func (p *RBACTestSuite) TestProjectQuotaAPIValidation() {
	client := p.newSubSession()

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
		ClusterID:     p.downstreamClusterID,
		ResourceQuota: pq,
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// namespaceDefaultResourceQuota without resourceQuota should fail (422).
	_, err = client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Namespace default quota exceeding project quota should fail (422).
	_, err = client.Management.Project.Create(&management.Project{
		Name:                          namegen.AppendRandomString("test-"),
		ClusterID:                     p.downstreamClusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsqLarge,
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Namespace default quota missing fields defined on project quota should fail (422).
	pqMulti := &management.ProjectResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100", Services: "100"},
	}
	nsqIncomplete := &management.NamespaceResourceQuota{
		Limit: &management.ResourceQuotaLimit{Pods: "100"},
	}

	proj, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
	})
	p.Require().NoError(err)

	_, err = client.Management.Project.Update(proj, map[string]any{
		"resourceQuota":                 pqMulti,
		"namespaceDefaultResourceQuota": nsqIncomplete,
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}

// TestProjectContainerDefaultResourceLimit tests that creating a project with a
// containerDefaultResourceLimit correctly stores the limit, and that it can be cleared.
func (p *RBACTestSuite) TestProjectContainerDefaultResourceLimit() {
	client := p.newSubSession()

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
		ClusterID:                     p.downstreamClusterID,
		ResourceQuota:                 pq,
		NamespaceDefaultResourceQuota: nsq,
		ContainerDefaultResourceLimit: lmt,
	})
	p.Require().NoError(err)
	p.Require().NotNil(project.ResourceQuota)
	p.Require().NotNil(project.ContainerDefaultResourceLimit)

	// Clear the container limit.
	updated, err := client.Management.Project.Update(project, map[string]any{
		"containerDefaultResourceLimit": nil,
	})
	p.Require().NoError(err)
	p.Require().Nil(updated.ContainerDefaultResourceLimit)
}

// TestNamespaceResourceQuotaCreated tests that when a namespace is created in a project
// with an explicit resource quota annotation, the Rancher controller creates a k8s
// ResourceQuota object in the namespace with the requested limits.
func (p *RBACTestSuite) TestNamespaceResourceQuotaCreated() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	p.Require().NoError(err)

	ns := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "4"})

	var hard map[string]string
	p.Require().Eventually(func() bool {
		h, err := p.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	p.Require().Equal("4", hard["pods"])
}

// TestNamespaceDefaultQuotaApplied tests that when a namespace is created in a project
// without an explicit quota annotation, the project's namespaceDefaultResourceQuota is
// applied by the controller.
func (p *RBACTestSuite) TestNamespaceDefaultQuotaApplied() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	p.Require().NoError(err)

	// Create namespace without explicit quota — should get the project default.
	ns := p.createNamespaceWithQuota(client, p.projectName(project), nil)

	var hard map[string]string
	p.Require().Eventually(func() bool {
		h, err := p.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	p.Require().Equal("4", hard["pods"])
}

// TestProjectQuotaUpdateAppliedToNamespace tests that when a project is updated to
// add a resource quota, existing namespaces in the project get a ResourceQuota created.
func (p *RBACTestSuite) TestProjectQuotaUpdateAppliedToNamespace() {
	client := p.newSubSession()

	// Create project without quota.
	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
	})
	p.Require().NoError(err)

	// Create a namespace (no quota yet on the project).
	ns := p.createNamespaceWithQuota(client, p.projectName(project), nil)

	// Update the project to add quota.
	_, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	p.Require().NoError(err)

	// The controller should apply the default quota to the existing namespace.
	var hard map[string]string
	p.Require().Eventually(func() bool {
		h, err := p.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	p.Require().Equal("4", hard["pods"])
}

// TestNamespaceQuotaExceedsProjectLimit tests that the controller handles a namespace
// whose requested quota exceeds the project limit by zeroing overused resources in the
// created k8s ResourceQuota, and that the project's usedLimit is not inflated.
func (p *RBACTestSuite) TestNamespaceQuotaExceedsProjectLimit() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
	})
	p.Require().NoError(err)

	// Create namespace requesting more pods than the project allows.
	ns := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "200"})

	// The controller should still create a ResourceQuota, but with the overused resource zeroed.
	var hard map[string]string
	p.Require().Eventually(func() bool {
		h, err := p.resourceQuotaHard(client, ns.Name)
		hard = h
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)
	p.Require().Equal("0", hard["pods"], "overused pods quota should be zeroed")

	// A namespace whose quota failed validation doesn't count towards the project's usage.
	used, err := p.projectUsedLimit(client, project.ID, "pods")
	p.Require().NoError(err)
	p.Require().Equal("0", used, "project usedLimit should not include the overused namespace")
}

// TestProjectUsedQuotaUpdated tests that the project's usedLimit is updated by the
// controller when namespaces with quotas are created in the project.
func (p *RBACTestSuite) TestProjectUsedQuotaUpdated() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "100"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "4"},
		},
	})
	p.Require().NoError(err)

	// Create namespace — default quota of 4 pods should apply.
	ns := p.createNamespaceWithQuota(client, p.projectName(project), nil)
	p.Require().Eventually(func() bool {
		hard, err := p.resourceQuotaHard(client, ns.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns.Name)

	p.Require().Eventually(func() bool {
		used, err := p.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "4"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=4")
}

// TestProjectUsedQuotaExactMatch tests that when all of a project's quota is consumed
// by namespaces, the project quota cannot be reduced below the used amount.
func (p *RBACTestSuite) TestProjectUsedQuotaExactMatch() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	p.Require().NoError(err)

	// Create two namespaces: 2 + 8 = 10 pods (full quota).
	ns1 := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "2"})
	p.Require().Eventually(func() bool {
		hard, err := p.resourceQuotaHard(client, ns1.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns1.Name)

	ns2 := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "8"})
	p.Require().Eventually(func() bool {
		hard, err := p.resourceQuotaHard(client, ns2.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns2.Name)

	p.Require().Eventually(func() bool {
		used, err := p.projectUsedLimit(client, project.ID, "pods")
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
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}

// TestProjectQuotaAddRemoveFields tests adding and removing quota fields on a project
// and verifying that the usedLimit is updated accordingly.
func (p *RBACTestSuite) TestProjectQuotaAddRemoveFields() {
	client := p.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
		ResourceQuota: &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10"},
		},
		NamespaceDefaultResourceQuota: &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2"},
		},
	})
	p.Require().NoError(err)

	// Create two namespaces using the default quota of 2 pods each.
	ns1 := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "2"})
	p.Require().Eventually(func() bool {
		hard, err := p.resourceQuotaHard(client, ns1.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns1.Name)
	p.Require().Eventually(func() bool {
		used, err := p.projectUsedLimit(client, project.ID, "pods")
		return err == nil && used == "2"
	}, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.pods=2")

	ns2 := p.createNamespaceWithQuota(client, p.projectName(project), map[string]string{"pods": "2"})
	p.Require().Eventually(func() bool {
		hard, err := p.resourceQuotaHard(client, ns2.Name)
		return err == nil && len(hard) > 0
	}, 2*time.Minute, 2*time.Second, "waiting for ResourceQuota in namespace %s", ns2.Name)
	p.Require().Eventually(func() bool {
		used, err := p.projectUsedLimit(client, project.ID, "pods")
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
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Add services field with a valid default.
	project, err = client.Management.Project.Update(project, map[string]any{
		"resourceQuota": &management.ProjectResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "10", Services: "10"},
		},
		"namespaceDefaultResourceQuota": &management.NamespaceResourceQuota{
			Limit: &management.ResourceQuotaLimit{Pods: "2", Services: "2"},
		},
	})
	p.Require().NoError(err)

	// Controller should propagate services default to existing namespaces.
	p.Require().Eventually(func() bool {
		used, err := p.projectUsedLimit(client, project.ID, "services")
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
	p.Require().NoError(err)

	// NOTE: We do not assert that usedLimit.services converges to 0 because the
	// reconcile controller (Norman-triggered) may enqueue namespaces before the
	// Wrangler project cache is updated, causing the sync controller to read a
	// stale project default and skip the namespace annotation cleanup. This is a
	// known eventual-consistency gap between the Norman and Wrangler informers.
	//
	// Tracking issue: https://github.com/rancher/rancher/issues/55060
	//
	// After removing services, usedLimit.services should drop to 0.
	// p.Require().Eventually(func() bool {
	// 	used, err := p.projectUsedLimit(client, project.ID, "services")
	// 	return err == nil && used == "0"
	// }, 2*time.Minute, 2*time.Second, "waiting for project usedLimit.services=0")
}

// TestProjectQuotaCannotExceedWithExistingNamespaces tests that setting a project quota
// where default * existing namespace count exceeds the limit is rejected.
func (p *RBACTestSuite) TestProjectQuotaCannotExceedWithExistingNamespaces() {
	client := p.newSubSession()

	// Create project without quota.
	project, err := client.Management.Project.Create(&management.Project{
		Name:      namegen.AppendRandomString("test-"),
		ClusterID: p.downstreamClusterID,
	})
	p.Require().NoError(err)

	// Create 4 namespaces in the project.
	for range 4 {
		p.createNamespaceWithQuota(client, p.projectName(project), nil)
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
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}
