package clusters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"
)

// findDownstreamClusterID polls the management API until an active downstream cluster
// with a Ready condition is found, then returns its ID. Returns an error if no such
// cluster is found within the timeout.
func (s *ClustersTestSuite) findDownstreamClusterID() (string, error) {
	var clusterID string
	err := wait.PollUntilContextTimeout(s.T().Context(), 5*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
		clusterList, err := s.client.Management.Cluster.ListAll(nil)
		if err != nil {
			return false, err
		}
		for _, cluster := range clusterList.Data {
			if cluster.ID == "local" || cluster.State != "active" {
				continue
			}
			for _, condition := range cluster.Conditions {
				if condition.Type == "Ready" && condition.Status == "True" {
					clusterID = cluster.ID
					return true, nil
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return "", fmt.Errorf("no ready downstream cluster found within timeout: %w", err)
	}
	return clusterID, nil
}

// TestK8sProxyFetchesNamespacesFromLocalCluster asserts that listing namespaces through the local
// cluster's k8s proxy returns a NamespaceList.
func (s *ClustersTestSuite) TestK8sProxyFetchesNamespacesFromLocalCluster() {
	url := fmt.Sprintf("https://%s/k8s/proxy/%s/api/v1/namespaces", s.client.WranglerContext.RESTConfig.Host, s.clusterID)

	httpClient := s.httpClient()
	resp, err := httpClient.Get(url)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusOK, resp.StatusCode)

	var payload map[string]any
	s.Require().NoError(json.NewDecoder(resp.Body).Decode(&payload))
	s.Require().Equal("NamespaceList", payload["kind"])
	_, ok := payload["items"]
	s.Require().True(ok)
}

// TestK8sProxyFetchesNamespacesFromDownstreamCluster asserts that listing namespaces through a
// ready downstream cluster's k8s proxy returns a NamespaceList.
func (s *ClustersTestSuite) TestK8sProxyFetchesNamespacesFromDownstreamCluster() {
	downstreamClusterID, err := s.findDownstreamClusterID()
	s.Require().NoError(err)

	url := fmt.Sprintf("https://%s/k8s/proxy/%s/api/v1/namespaces", s.client.WranglerContext.RESTConfig.Host, downstreamClusterID)
	httpClient := s.httpClient()

	// Wrap in Eventually to handle transient proxy unavailability against a downstream cluster.
	var payload map[string]any
	s.Require().Eventually(func() bool {
		resp, err := httpClient.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return false
		}

		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return false
		}
		return true
	}, 2*time.Minute, 5*time.Second, "timed out waiting for downstream cluster proxy to return a successful response")

	s.Require().Equal("NamespaceList", payload["kind"])
	_, ok := payload["items"]
	s.Require().True(ok)
}

// TestProxyK8sV1PathReturnsNotFound asserts that a ready downstream cluster's k8s proxy returns 404
// for the /v1 path, which is Steve's API rather than a Kubernetes one.
func (s *ClustersTestSuite) TestProxyK8sV1PathReturnsNotFound() {
	downstreamClusterID, err := s.findDownstreamClusterID()
	s.Require().NoError(err)

	proxyURL := fmt.Sprintf("https://%s/k8s/proxy/%s", s.client.WranglerContext.RESTConfig.Host, downstreamClusterID)
	httpClient := s.httpClient()

	// A 404 would also come back if the proxy didn't know the cluster, so first make sure it serves
	// a Kubernetes path for it.
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		resp, err := httpClient.Get(proxyURL + "/api/v1/namespaces")
		if !assert.NoError(c, err) {
			return
		}
		resp.Body.Close()
		assert.Equal(c, http.StatusOK, resp.StatusCode)
	}, 2*time.Minute, 5*time.Second, "waiting for the downstream cluster proxy to serve /api/v1/namespaces")

	resp, err := httpClient.Get(proxyURL + "/v1")
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusNotFound, resp.StatusCode)
}
