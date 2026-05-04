package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	"k8s.io/client-go/rest"
)

type K8sProxyTestSuite struct {
	suite.Suite
	client              *rancher.Client
	session             *session.Session
	downstreamClusterID string
}

func (s *K8sProxyTestSuite) SetupSuite() {
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client

	s.downstreamClusterID = s.findDownstreamClusterID()
}

func (s *K8sProxyTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// findDownstreamClusterID lists management clusters and returns the ID of the first
// active downstream cluster that has a Ready condition with status True. Returns an
// empty string if none is found.
func (s *K8sProxyTestSuite) findDownstreamClusterID() string {
	clusterList, err := s.client.Management.Cluster.ListAll(nil)
	s.Require().NoError(err)

	for _, cluster := range clusterList.Data {
		if cluster.ID == "local" || cluster.State != "active" {
			continue
		}
		for _, condition := range cluster.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				return cluster.ID
			}
		}
	}
	return ""
}

func (s *K8sProxyTestSuite) httpClient() *http.Client {
	httpClient, err := rest.HTTPClientFor(s.client.WranglerContext.RESTConfig)
	s.Require().NoError(err)
	return httpClient
}

func (s *K8sProxyTestSuite) TestK8sProxyFetchesNamespacesFromLocalCluster() {
	url := fmt.Sprintf("https://%s/k8s/proxy/local/api/v1/namespaces", s.client.RancherConfig.Host)

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

func (s *K8sProxyTestSuite) TestK8sProxyFetchesNamespacesFromDownstreamCluster() {
	if s.downstreamClusterID == "" {
		s.T().Skip("no ready downstream cluster available for this test")
	}

	url := fmt.Sprintf("https://%s/k8s/proxy/%s/api/v1/namespaces", s.client.RancherConfig.Host, s.downstreamClusterID)
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

func (s *K8sProxyTestSuite) TestProxyK8sV1PathReturnsNotFound() {
	if s.downstreamClusterID == "" {
		s.T().Skip("no ready downstream cluster available for this test")
	}

	url := fmt.Sprintf("https://%s/k8s/proxy/%s/v1", s.client.RancherConfig.Host, s.downstreamClusterID)
	httpClient := s.httpClient()

	resp, err := httpClient.Get(url)
	s.Require().NoError(err)
	defer resp.Body.Close()

	s.Require().Equal(http.StatusNotFound, resp.StatusCode)
}

func TestK8sProxy(t *testing.T) {
	suite.Run(t, new(K8sProxyTestSuite))
}
