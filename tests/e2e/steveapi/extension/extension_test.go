package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/shepherd/clients/rancher"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// newExtensionAPIRestConfig returns a REST config for the extension API server of the given cluster,
// authenticated with bearerToken (none if empty).
func newExtensionAPIRestConfig(rancherConfig *rancher.Config, clusterID string, bearerToken string) *rest.Config {
	host := fmt.Sprintf("https://%s/ext", rancherConfig.Host)
	if clusterID != "" {
		host = fmt.Sprintf("https://%s/k8s/clusters/%s/ext", rancherConfig.Host, clusterID)
	}
	return &rest.Config{
		Host:        host,
		BearerToken: bearerToken,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: *rancherConfig.Insecure,
			CAFile:   rancherConfig.CAFile,
		},
	}
}

// do sends a request with an optional JSON body to path on Rancher's Steve API and returns the
// response status code and body. It doesn't assert, so it's safe to call from a cleanup.
func (s *ExtensionAPITestSuite) do(client *http.Client, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", s.client.WranglerContext.RESTConfig.Host, path), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

// createKubeconfig creates a kubeconfig for the local cluster through Steve's ext.cattle.io.kubeconfig
// endpoint. It returns the response status code and body, and the kubeconfig if it was created (201),
// in which case it also registers a cleanup that deletes it. Rancher generates the name. Raw HTTP
// isn't tracked by the session, hence the manual cleanup.
func (s *ExtensionAPITestSuite) createKubeconfig(client *http.Client) (int, []byte, *extv1.Kubeconfig) {
	status, body, err := s.do(client, http.MethodPost, "/v1/ext.cattle.io.kubeconfig", []byte(`{
		"apiVersion": "ext.cattle.io/v1",
		"kind": "kubeconfig",
		"spec": {
			"clusters": ["local"],
			"currentContext": "local",
			"description": "kubeconfig for testing new kubeconfigs",
			"ttl": 100
		}
	}`))
	s.Require().NoError(err)
	if status != http.StatusCreated {
		return status, body, nil
	}

	kubeconfig := &extv1.Kubeconfig{}
	s.Require().NoError(json.Unmarshal(body, kubeconfig))

	t := s.T()
	t.Cleanup(func() {
		deleteStatus, deleteBody, err := s.do(client, http.MethodDelete, "/v1/ext.cattle.io.kubeconfig/"+kubeconfig.Name, nil)
		if !assert.NoError(t, err, "failed to delete kubeconfig %s", kubeconfig.Name) {
			return
		}
		assert.Containsf(t, []int{http.StatusNoContent, http.StatusNotFound}, deleteStatus,
			"failed to delete kubeconfig %s: %s", kubeconfig.Name, deleteBody)
	})
	return status, body, kubeconfig
}

// TestExtensionAPIServer verifies that discovery and the OpenAPI v2 and v3 documents are served under
// /ext to an authenticated client, and forbidden without authentication.
func (s *ExtensionAPITestSuite) TestExtensionAPIServer() {
	restConfig := newExtensionAPIRestConfig(s.client.RancherConfig, s.clusterID, s.client.RancherConfig.AdminToken)
	discClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	s.Require().NoError(err)

	groups, err := discClient.ServerGroups()
	s.Require().NoError(err)
	groupNames := make([]string, 0, len(groups.Groups))
	for _, group := range groups.Groups {
		groupNames = append(groupNames, group.Name)
	}
	s.Contains(groupNames, extv1.SchemeGroupVersion.Group)

	v2Document, err := discClient.OpenAPISchema()
	s.Require().NoError(err)
	s.NotNil(v2Document)

	paths, err := discClient.OpenAPIV3().Paths()
	s.Require().NoError(err)
	s.NotEmpty(paths)

	// No auth
	unauthRestConfig := newExtensionAPIRestConfig(s.client.RancherConfig, s.clusterID, "")
	unauthDiscClient, err := discovery.NewDiscoveryClientForConfig(unauthRestConfig)
	s.Require().NoError(err)

	_, err = unauthDiscClient.ServerGroups()
	s.Truef(apierrors.IsForbidden(err), "expected Forbidden listing groups without auth, got: %v", err)

	_, err = unauthDiscClient.OpenAPISchema()
	s.Truef(apierrors.IsForbidden(err), "expected Forbidden getting OpenAPI v2 without auth, got: %v", err)

	_, err = unauthDiscClient.OpenAPIV3().Paths()
	s.Truef(apierrors.IsForbidden(err), "expected Forbidden getting OpenAPI v3 without auth, got: %v", err)
}

// TestExtensionAPIServerAuthorization verifies which /ext endpoints an authenticated admin can reach:
// the OpenAPI documents are allowed, and metrics, health and version endpoints are forbidden.
func (s *ExtensionAPITestSuite) TestExtensionAPIServerAuthorization() {
	restConfig := newExtensionAPIRestConfig(s.client.RancherConfig, s.clusterID, s.client.RancherConfig.AdminToken)
	client, err := rest.HTTPClientFor(restConfig)
	s.Require().NoError(err)

	tests := []struct {
		path               string
		expectedStatusCode int
	}{
		{
			path:               "/openapi/v2",
			expectedStatusCode: http.StatusOK,
		},
		{
			path:               "/openapi/v3",
			expectedStatusCode: http.StatusOK,
		},
		{
			path:               "/openapi/v3/version",
			expectedStatusCode: http.StatusOK,
		},
		{
			path:               "/metrics",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			path:               "/healthz",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			path:               "/readyz",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			path:               "/livez",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			path:               "/version",
			expectedStatusCode: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		s.Run(strings.ReplaceAll(test.path, "/", "_"), func() {
			resp, err := client.Get(restConfig.Host + test.path)
			s.Require().NoError(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			s.Require().NoError(err)
			s.Equalf(test.expectedStatusCode, resp.StatusCode, "body: %s", body)
		})
	}
}

// TestExtensionAPIServerCreateRequests verifies that a kubeconfig and a selfuser can be created
// through Steve's ext.cattle.io endpoints.
func (s *ExtensionAPITestSuite) TestExtensionAPIServerCreateRequests() {
	client, err := rest.HTTPClientFor(s.client.WranglerContext.RESTConfig)
	s.Require().NoError(err)

	s.Run("create kubeconfig", func() {
		status, body, kubeconfig := s.createKubeconfig(client)
		s.Require().Equalf(http.StatusCreated, status, "body: %s", body)
		s.NotEmpty(kubeconfig.Name)
		s.Equal([]string{"local"}, kubeconfig.Spec.Clusters)
		s.Equal("local", kubeconfig.Spec.CurrentContext)
	})

	// A selfuser isn't stored: creating one returns the caller's user ID, so there's nothing to clean up.
	s.Run("create self user", func() {
		status, body, err := s.do(client, http.MethodPost, "/v1/ext.cattle.io.selfusers", []byte(`{
			"apiVersion": "ext.cattle.io/v1",
			"kind": "selfuser"
		}`))
		s.Require().NoError(err)
		s.Require().Equalf(http.StatusCreated, status, "body: %s", body)
		selfUser := &extv1.SelfUser{}
		s.Require().NoError(json.Unmarshal(body, selfUser))
		s.NotEmpty(selfUser.Status.UserID)
	})
}

// TestExtensionAPIServerUpdateRequests verifies that an existing kubeconfig can be updated through
// Steve, and that updating a missing one returns 404.
func (s *ExtensionAPITestSuite) TestExtensionAPIServerUpdateRequests() {
	client, err := rest.HTTPClientFor(s.client.WranglerContext.RESTConfig)
	s.Require().NoError(err)

	status, body, kubeconfig := s.createKubeconfig(client)
	s.Require().Equalf(http.StatusCreated, status, "body: %s", body)

	updated := extv1.Kubeconfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:            kubeconfig.Name,
			ResourceVersion: kubeconfig.ResourceVersion,
		},
		Spec: extv1.KubeconfigSpec{
			Clusters:       kubeconfig.Spec.Clusters,
			CurrentContext: kubeconfig.Spec.CurrentContext,
			Description:    "kubeconfig updated",
			TTL:            kubeconfig.Spec.TTL,
		},
	}
	data, err := json.Marshal(updated)
	s.Require().NoError(err)

	status, body, err = s.do(client, http.MethodPut, "/v1/ext.cattle.io.kubeconfig/"+kubeconfig.Name, data)
	s.Require().NoError(err)
	s.Require().Equalf(http.StatusOK, status, "body: %s", body)
	result := &extv1.Kubeconfig{}
	s.Require().NoError(json.Unmarshal(body, result))
	s.Equal("kubeconfig updated", result.Spec.Description)

	updated.Name = "does-not-exist"
	updated.ResourceVersion = ""
	data, err = json.Marshal(updated)
	s.Require().NoError(err)

	status, body, err = s.do(client, http.MethodPut, "/v1/ext.cattle.io.kubeconfig/does-not-exist", data)
	s.Require().NoError(err)
	s.Equalf(http.StatusNotFound, status, "body: %s", body)
	s.Contains(string(body), "not found")
}

// TestExtensionAPIServerDeleteRequests verifies that an existing kubeconfig can be deleted through
// Steve, and that deleting a missing one returns 404.
func (s *ExtensionAPITestSuite) TestExtensionAPIServerDeleteRequests() {
	client, err := rest.HTTPClientFor(s.client.WranglerContext.RESTConfig)
	s.Require().NoError(err)

	status, body, kubeconfig := s.createKubeconfig(client)
	s.Require().Equalf(http.StatusCreated, status, "body: %s", body)

	status, body, err = s.do(client, http.MethodDelete, "/v1/ext.cattle.io.kubeconfig/"+kubeconfig.Name, nil)
	s.Require().NoError(err)
	s.Equalf(http.StatusNoContent, status, "body: %s", body)

	status, body, err = s.do(client, http.MethodDelete, "/v1/ext.cattle.io.kubeconfig/does-not-exist", nil)
	s.Require().NoError(err)
	s.Equalf(http.StatusNotFound, status, "body: %s", body)
	s.Contains(string(body), "not found")
}
