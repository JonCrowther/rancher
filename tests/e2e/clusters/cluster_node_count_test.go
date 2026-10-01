package clusters

import (
	"context"
	"time"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	managementNodeGVR = schema.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "nodes"}
	namespaceGVR      = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
)

// TestClusterNodeCount asserts that the cluster node count is updated as
// management nodes are added and removed.
func (s *ClustersTestSuite) TestClusterNodeCount() {
	client := s.newSubSession()

	cluster, err := client.Management.Cluster.Create(&management.Cluster{
		Name: namegen.AppendRandomString("cluster-"),
	})
	s.Require().NoError(err)

	s.Require().Eventually(func() bool {
		c, err := client.Management.Cluster.ByID(cluster.ID)
		if err != nil {
			return false
		}
		return c.NodeCount == 0
	}, 30*time.Second, 2*time.Second, "cluster %s node count did not reach 0", cluster.ID)

	// Wait for the cluster's management namespace to be created on the local cluster.
	localDynamic, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)

	err = wait.PollUntilContextTimeout(s.T().Context(), 2*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := localDynamic.Resource(namespaceGVR).Get(ctx, cluster.ID, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return err == nil, err
	})
	s.Require().NoError(err, "timed out waiting for cluster namespace %s to be created", cluster.ID)

	// Nodes must be created manually via the management k8s API because the cluster
	// is in a pending/not-ready state and the normal provisioning flow is not running.
	node1 := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "management.cattle.io/v3",
			"kind":       "Node",
			"metadata": map[string]any{
				"name":      namegen.AppendRandomString("node-"),
				"namespace": cluster.ID,
			},
		},
	}
	_, err = localDynamic.Resource(managementNodeGVR).Namespace(cluster.ID).Create(s.T().Context(), node1, metav1.CreateOptions{})
	s.Require().NoError(err)

	s.Require().Eventually(func() bool {
		c, err := client.Management.Cluster.ByID(cluster.ID)
		if err != nil {
			return false
		}
		return c.NodeCount == 1
	}, 30*time.Second, 2*time.Second, "cluster %s node count did not reach 1", cluster.ID)

	node2 := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "management.cattle.io/v3",
			"kind":       "Node",
			"metadata": map[string]any{
				"name":      namegen.AppendRandomString("node-"),
				"namespace": cluster.ID,
			},
		},
	}
	node2, err = localDynamic.Resource(managementNodeGVR).Namespace(cluster.ID).Create(s.T().Context(), node2, metav1.CreateOptions{})
	s.Require().NoError(err)

	s.Require().Eventually(func() bool {
		c, err := client.Management.Cluster.ByID(cluster.ID)
		if err != nil {
			return false
		}
		return c.NodeCount == 2
	}, 30*time.Second, 2*time.Second, "cluster %s node count did not reach 2", cluster.ID)

	// Delete node2 and verify the count drops back to 1.
	err = localDynamic.Resource(managementNodeGVR).Namespace(cluster.ID).Delete(s.T().Context(), node2.GetName(), metav1.DeleteOptions{})
	s.Require().NoError(err)

	s.Require().Eventually(func() bool {
		c, err := client.Management.Cluster.ByID(cluster.ID)
		if err != nil {
			return false
		}
		return c.NodeCount == 1
	}, 30*time.Second, 2*time.Second, "cluster %s node count did not drop back to 1 after node deletion", cluster.ID)
}
