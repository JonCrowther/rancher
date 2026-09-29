package workloads

import (
	"net/http"
	"time"

	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestDNSFields verifies that the dnsRecord Norman schema exposes full CRUD
// access and that the expected resource fields are present with the correct
// create/update permissions.
func (s *WorkloadsTestSuite) TestDNSFields() {
	client := s.newSubSession()
	project := s.createProject(client)

	schema, err := s.getSchema(project, "dnsRecord")
	s.Require().NoError(err)

	s.ElementsMatch([]string{"GET", "POST"}, schema.CollectionMethods)
	s.ElementsMatch([]string{"GET", "PUT", "DELETE"}, schema.ResourceMethods)

	expected := map[string]fieldAccess{
		"allocateLoadBalancerNodePorts": {Create: true, Update: true},
		"clusterIp":                     {Create: false, Update: false},
		"clusterIPs":                    {Create: true, Update: true},
		"hostname":                      {Create: true, Update: true},
		"ipAddresses":                   {Create: true, Update: true},
		"ipFamilies":                    {Create: true, Update: true},
		"ipFamilyPolicy":                {Create: true, Update: true},
		"namespaceId":                   {Create: true, Update: false},
		"ports":                         {Create: false, Update: false},
		"projectId":                     {Create: true, Update: false},
		"publicEndpoints":               {Create: false, Update: false},
		"selector":                      {Create: true, Update: true},
		"targetDnsRecordIds":            {Create: true, Update: true},
		"targetWorkloadIds":             {Create: true, Update: true},
		"trafficDistribution":           {Create: true, Update: true},
		"workloadId":                    {Create: false, Update: false},
	}
	for fieldName, want := range expected {
		field, ok := schema.ResourceFields[fieldName]
		if s.Truef(ok, "expected resourceField %q to be present in dnsRecord schema", fieldName) {
			s.Equalf(want, field, "field %q: unexpected create/update permissions", fieldName)
		}
	}
}

// TestDNSHostname asserts that a dnsRecord can be created with a hostname,
// updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestDNSHostname() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "dnsRecords")

	name := namegen.AppendRandomString("dns-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"hostname":    "target",
		"namespaceId": nsName,
	})
	s.Equal("dnsRecord", created["baseType"])
	s.Equal("dnsRecord", created["type"])
	s.Equal(name, created["name"])
	s.Equal("target", created["hostname"])
	s.Nil(created["clusterIp"])
	s.Equal(nsName, created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	recordID := created["id"].(string)
	recordURL := url + "/" + recordID

	s.send(http.MethodPut, recordURL, map[string]any{"hostname": "target2"})

	reloaded := s.send(http.MethodGet, recordURL, nil)
	s.Equal("dnsRecord", reloaded["baseType"])
	s.Equal("dnsRecord", reloaded["type"])
	s.Equal(name, reloaded["name"])
	s.Equal("target2", reloaded["hostname"])
	s.Nil(reloaded["clusterIp"])
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, recordID)

	s.send(http.MethodDelete, recordURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, recordURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "dnsRecord %s still readable after delete", recordID)
}

// TestDNSIPs asserts that a dnsRecord can be created with IP addresses, that
// the IPs can be updated, and that creating a dnsRecord with a loopback IP is
// rejected with 422.
func (s *WorkloadsTestSuite) TestDNSIPs() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "dnsRecords")

	name := namegen.AppendRandomString("dns-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"ipAddresses": []string{"1.1.1.1", "2.2.2.2"},
		"namespaceId": nsName,
	})
	s.Equal("dnsRecord", created["baseType"])
	s.Equal("dnsRecord", created["type"])
	s.Equal(name, created["name"])
	s.NotContains(created, "hostname")
	s.Equal([]string{"1.1.1.1", "2.2.2.2"}, toStringSlice(created["ipAddresses"]))
	s.Nil(created["clusterIp"])
	s.Equal(nsName, created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	recordID := created["id"].(string)
	recordURL := url + "/" + recordID

	s.send(http.MethodPut, recordURL, map[string]any{"ipAddresses": []string{"1.1.1.2", "2.2.2.1"}})

	reloaded := s.send(http.MethodGet, recordURL, nil)
	s.Equal("dnsRecord", reloaded["baseType"])
	s.Equal("dnsRecord", reloaded["type"])
	s.Equal(name, reloaded["name"])
	s.NotContains(reloaded, "hostname")
	s.Equal([]string{"1.1.1.2", "2.2.2.1"}, toStringSlice(reloaded["ipAddresses"]))
	s.Nil(reloaded["clusterIp"])
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	// The valid create above is the positive precondition: the same request with a loopback IP
	// fails only because of the IP.
	status, body, err := do(s.httpClient, http.MethodPost, url, map[string]any{
		"name":        namegen.AppendRandomString("dns-"),
		"ipAddresses": []string{"127.0.0.2"},
		"namespaceId": nsName,
	})
	s.Require().NoError(err)
	s.Equal(http.StatusUnprocessableEntity, status)
	s.Contains(string(body), "may not be in the loopback range")

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, recordID)

	s.send(http.MethodDelete, recordURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, recordURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "dnsRecord %s still readable after delete", recordID)
}
