package clusters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rancher/rancher/tests/e2e/actions/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var storageClassGVR = schema.GroupVersionResource{
	Group:    "storage.k8s.io",
	Version:  "v1",
	Resource: "storageclasses",
}

func (s *ClustersTestSuite) storageClassURL() string {
	return fmt.Sprintf("https://%s/v3/cluster/%s/storageClasses",
		s.client.WranglerContext.RESTConfig.Host, s.clusterID)
}

func (s *ClustersTestSuite) pvcURL(projectID string) string {
	return fmt.Sprintf("https://%s/v3/project/%s/persistentVolumeClaims",
		s.client.WranglerContext.RESTConfig.Host, projectID)
}

func (s *ClustersTestSuite) post(httpClient *http.Client, url string, body map[string]any) (map[string]any, int) {
	b, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(b))
	s.Require().NoError(err)
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	var result map[string]any
	s.Require().NoErrorf(json.Unmarshal(respBody, &result), "status %d, body: %s", resp.StatusCode, string(respBody))
	return result, resp.StatusCode
}

// createStorageClassDirect uses the k8s dynamic client to create a StorageClass
// directly, bypassing the Norman API's automatic default-filling of
// storageaccounttype/skuName parameters.
func (s *ClustersTestSuite) createStorageClassDirect(client *rancher.Client, name, provisioner string, params map[string]any) {
	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)

	obj := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "storage.k8s.io/v1",
			"kind":       "StorageClass",
			"metadata": map[string]any{
				"name": name,
			},
			"provisioner": provisioner,
			"parameters":  params,
		},
	}

	// Namespace("") on this cluster-scoped resource is what makes the session track the create: the
	// session's dynamic client only wraps Create on the interface Namespace returns.
	_, err = dynamicClient.Resource(storageClassGVR).Namespace("").Create(s.T().Context(), obj, metav1.CreateOptions{})
	s.Require().NoError(err)
}

// createStorageClassNorman creates a StorageClass via the Norman cluster API. The session doesn't
// track raw Norman creates, so this registers a cleanup that deletes it through the k8s API.
func (s *ClustersTestSuite) createStorageClassNorman(client *rancher.Client, httpClient *http.Client, name, provisioner string, params map[string]any) string {
	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)

	body := map[string]any{
		"name":        name,
		"provisioner": provisioner,
		"parameters":  params,
	}
	result, status := s.post(httpClient, s.storageClassURL(), body)
	s.Require().Truef(status >= 200 && status < 300,
		"unexpected status %d creating StorageClass: %v", status, result)
	scName, ok := result["name"].(string)
	s.Require().Truef(ok, "created StorageClass has no name: %v", result)

	t := s.T()
	t.Cleanup(func() {
		// Not t.Context(): it's canceled before cleanup functions run.
		err := dynamicClient.Resource(storageClassGVR).Delete(context.Background(), scName, metav1.DeleteOptions{})
		if !apierrors.IsNotFound(err) {
			assert.NoError(t, err, "failed to delete StorageClass %s", scName)
		}
	})
	return scName
}

// TestCannotCreateAzureNoAccountStorageType asserts that a PVC referencing a
// StorageClass with the azure-disk provisioner but no storageaccounttype or
// skuName parameter is rejected by the Norman API with a 422.
//
// The StorageClass is created via the k8s dynamic client to bypass Norman's
// automatic default-filling of those parameters.
func (s *ClustersTestSuite) TestCannotCreateAzureNoAccountStorageType() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		ClusterID: s.clusterID,
		Name:      namegen.AppendRandomString("project-"),
	})
	s.Require().NoError(err)

	ns, err := namespaces.CreateNamespace(client, namegen.AppendRandomString("ns-"), "", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)

	scName := namegen.AppendRandomString("sc-")
	// Create the StorageClass directly via k8s API to omit storageaccounttype/skuName.
	s.createStorageClassDirect(client, scName, "kubernetes.io/azure-disk", map[string]any{
		"kind": "shared",
	})

	httpClient := s.httpClient()
	result, status := s.post(httpClient, s.pvcURL(project.ID), map[string]any{
		"name":           namegen.AppendRandomString("pvc-"),
		"storageClassId": scName,
		"namespaceId":    ns.Name,
		"accessModes":    []string{"ReadWriteOnce"},
		"resources": map[string]any{
			"requests": map[string]any{
				"storage": "30Gi",
			},
		},
	})

	s.Require().Equalf(http.StatusUnprocessableEntity, status, "response: %v", result)
	s.Contains(result["message"], "must provide storageaccounttype or skuName")
}

// TestCanCreateAzureAnyAccountStorageType asserts that a PVC referencing a
// StorageClass that has either storageaccounttype or skuName set can be
// successfully created.
func (s *ClustersTestSuite) TestCanCreateAzureAnyAccountStorageType() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		ClusterID: s.clusterID,
		Name:      namegen.AppendRandomString("project-"),
	})
	s.Require().NoError(err)

	// The PVCs are created through the raw Norman API, which the session doesn't track; deleting
	// this namespace at cleanup removes them.
	ns, err := namespaces.CreateNamespace(client, namegen.AppendRandomString("ns-"), "", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)

	httpClient := s.httpClient()

	// Try with storageaccounttype.
	sc1Name := s.createStorageClassNorman(client, httpClient,
		namegen.AppendRandomString("sc-"),
		"kubernetes.io/azure-disk",
		map[string]any{"storageaccounttype": "asdf"},
	)

	result, status := s.post(httpClient, s.pvcURL(project.ID), map[string]any{
		"name":           namegen.AppendRandomString("pvc-"),
		"storageClassId": sc1Name,
		"namespaceId":    ns.Name,
		"accessModes":    []string{"ReadWriteOnce"},
		"resources": map[string]any{
			"requests": map[string]any{"storage": "30Gi"},
		},
	})
	s.Truef(status >= 200 && status < 300,
		"unexpected status %d creating PVC with storageaccounttype: %v", status, result)

	// Try with skuName.
	sc2Name := s.createStorageClassNorman(client, httpClient,
		namegen.AppendRandomString("sc-"),
		"kubernetes.io/azure-disk",
		map[string]any{"skuName": "asdf"},
	)

	result, status = s.post(httpClient, s.pvcURL(project.ID), map[string]any{
		"name":           namegen.AppendRandomString("pvc-"),
		"storageClassId": sc2Name,
		"namespaceId":    ns.Name,
		"accessModes":    []string{"ReadWriteOnce"},
		"resources": map[string]any{
			"requests": map[string]any{"storage": "30Gi"},
		},
	})
	s.Truef(status >= 200 && status < 300,
		"unexpected status %d creating PVC with skuName: %v", status, result)
}

// TestCanCreatePVCNoStorageNoVol asserts that a PVC with no storage class and
// no volume reference can be created and begins in the "pending" state.
func (s *ClustersTestSuite) TestCanCreatePVCNoStorageNoVol() {
	client := s.newSubSession()

	project, err := client.Management.Project.Create(&management.Project{
		ClusterID: s.clusterID,
		Name:      namegen.AppendRandomString("project-"),
	})
	s.Require().NoError(err)

	// The PVC is created through the raw Norman API, which the session doesn't track; deleting
	// this namespace at cleanup removes it.
	ns, err := namespaces.CreateNamespace(client, namegen.AppendRandomString("ns-"), "", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)

	httpClient := s.httpClient()

	result, status := s.post(httpClient, s.pvcURL(project.ID), map[string]any{
		"name":        namegen.AppendRandomString("pvc-"),
		"namespaceId": ns.Name,
		"accessModes": []string{"ReadWriteOnce"},
		"resources": map[string]any{
			"requests": map[string]any{"storage": "30Gi"},
		},
	})

	s.Require().Truef(status >= 200 && status < 300,
		"unexpected status %d creating PVC: %v", status, result)
	s.Equal("pending", result["state"])
}
