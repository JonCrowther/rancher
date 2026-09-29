package workloads

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/rancher/rancher/tests/e2e/actions/namespaces"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	"k8s.io/client-go/rest"
)

// WorkloadsTestSuite covers Rancher's Norman project API for workloads and the resources around
// them: dnsRecords, ingresses, project-scoped and namespaced secrets, and HPAs. Its tests live in
// the topic files in this package; this file holds only the shared setup and helpers.
//
// Every Norman project API call here is raw HTTP, which the session doesn't track. Objects created
// that way live in a namespace or project the test created through its sub-session, so they're
// deleted along with it.
type WorkloadsTestSuite struct {
	suite.Suite
	client     *rancher.Client
	session    *session.Session
	httpClient *http.Client // authenticates as the suite's admin user
	clusterID  string       // cluster under test; "local" is Rancher's own cluster, not a downstream
}

func (s *WorkloadsTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client

	httpClient, err := rest.HTTPClientFor(client.WranglerContext.RESTConfig)
	s.Require().NoError(err)
	s.httpClient = httpClient
}

func (s *WorkloadsTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession returns a client whose creates are cleaned up when the calling test ends.
func (s *WorkloadsTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

// createProject creates a project in the cluster under test.
func (s *WorkloadsTestSuite) createProject(client *rancher.Client) *management.Project {
	project, err := client.Management.Project.Create(&management.Project{
		ClusterID: s.clusterID,
		Name:      namegen.AppendRandomString("project-"),
	})
	s.Require().NoError(err)
	return project
}

// createNamespace creates a namespace in project and returns its name.
func (s *WorkloadsTestSuite) createNamespace(client *rancher.Client, project *management.Project) string {
	ns, err := namespaces.CreateNamespace(client, namegen.AppendRandomString("ns-"), "", map[string]string{}, map[string]string{}, project)
	s.Require().NoError(err)
	return ns.Name
}

// projectURL returns the Norman project API URL for path (a collection such as "workloads", or
// "schemas/<type>") in project.
func (s *WorkloadsTestSuite) projectURL(project *management.Project, path string) string {
	return fmt.Sprintf("https://%s/v3/project/%s/%s", s.client.WranglerContext.RESTConfig.Host, project.ID, path)
}

// do sends a request with an optional JSON body and returns the status code and response body.
// It doesn't assert anything, so tests use it wherever a non-2xx status is the expected result.
func do(httpClient *http.Client, method, url string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

// send sends a request as the suite's admin, requires a 2xx response, and returns the decoded body.
// It's the raw-HTTP equivalent of a typed client call followed by Require().NoError(err).
func (s *WorkloadsTestSuite) send(method, url string, body any) map[string]any {
	status, respBody, err := do(s.httpClient, method, url, body)
	s.Require().NoError(err)
	s.Require().Truef(status >= 200 && status < 300, "%s %s: unexpected status %d: %s", method, url, status, respBody)
	var result map[string]any
	if len(respBody) > 0 {
		s.Require().NoError(json.Unmarshal(respBody, &result))
	}
	return result
}

// list returns the objects in the Norman collection at url.
func (s *WorkloadsTestSuite) list(url string) ([]map[string]any, error) {
	status, body, err := do(s.httpClient, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d: %s", url, status, body)
	}
	var collection struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &collection); err != nil {
		return nil, err
	}
	return collection.Data, nil
}

// listIDs returns the IDs of the objects in the Norman collection at url.
func (s *WorkloadsTestSuite) listIDs(url string) ([]string, error) {
	objects, err := s.list(url)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(objects))
	for _, obj := range objects {
		id, _ := obj["id"].(string)
		ids = append(ids, id)
	}
	return ids, nil
}

// normanSchema is the part of a Norman schema the schema tests check.
type normanSchema struct {
	CollectionMethods []string               `json:"collectionMethods"`
	ResourceMethods   []string               `json:"resourceMethods"`
	ResourceFields    map[string]fieldAccess `json:"resourceFields"`
}

// fieldAccess is whether a schema field can be set on create and on update.
type fieldAccess struct {
	Create bool `json:"create"`
	Update bool `json:"update"`
}

// getSchema returns the Norman schema for typeName in project.
func (s *WorkloadsTestSuite) getSchema(project *management.Project, typeName string) (normanSchema, error) {
	var schema normanSchema
	url := s.projectURL(project, "schemas/"+typeName)
	status, body, err := do(s.httpClient, http.MethodGet, url, nil)
	if err != nil {
		return schema, err
	}
	if status != http.StatusOK {
		return schema, fmt.Errorf("GET %s: unexpected status %d: %s", url, status, body)
	}
	err = json.Unmarshal(body, &schema)
	return schema, err
}

// nginxWorkload returns the body of a Norman workload with one nginx container in namespace nsName.
// Tests add or override fields before sending it.
func nginxWorkload(nsName string) map[string]any {
	return map[string]any{
		"name":        namegen.AppendRandomString("workload-"),
		"namespaceId": nsName,
		"scale":       1,
		"containers":  []any{map[string]any{"name": "one", "image": "nginx"}},
	}
}

// toStringSlice converts a []any from JSON unmarshalling to []string.
func toStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(raw))
	for i, item := range raw {
		out[i], _ = item.(string)
	}
	return out
}

func TestWorkloadsTestSuite(t *testing.T) {
	suite.Run(t, new(WorkloadsTestSuite))
}
