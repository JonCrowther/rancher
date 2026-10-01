package workloads

import (
	"net/http"
	"time"

	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestNamespacedSecrets asserts that an Opaque namespaced secret can be created,
// updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestNamespacedSecrets() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "namespacedSecrets")

	name := namegen.AppendRandomString("secret-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"namespaceId": nsName,
		"stringData":  map[string]any{"foo": "bar"},
	})
	s.Equal("namespacedSecret", created["baseType"])
	s.Equal("namespacedSecret", created["type"])
	s.Equal("Opaque", created["kind"])
	s.Equal(name, created["name"])
	data := created["data"].(map[string]any)
	s.Equal("YmFy", data["foo"])

	id := created["id"].(string)
	secretURL := url + "/" + id

	// Update: add a new key to data.
	s.send(http.MethodPut, secretURL, map[string]any{
		"data": map[string]any{"foo": "YmFy", "baz": "YmFy"},
	})

	reloaded := s.send(http.MethodGet, secretURL, nil)
	s.Equal("namespacedSecret", reloaded["baseType"])
	s.Equal("namespacedSecret", reloaded["type"])
	s.Equal("Opaque", reloaded["kind"])
	s.Equal(name, reloaded["name"])
	reloadedData := reloaded["data"].(map[string]any)
	s.Equal("YmFy", reloadedData["foo"])
	s.Equal("YmFy", reloadedData["baz"])
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, secretURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, secretURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "namespacedSecret %s still readable after delete", id)
}

// TestNamespacedCertificates asserts that a namespaced TLS certificate secret
// can be created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestNamespacedCertificates() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "namespacedCertificates")

	name := namegen.AppendRandomString("cert-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"namespaceId": nsName,
		"certs":       certPEM,
		"key":         keyPEM,
	})
	s.Equal("namespacedSecret", created["baseType"])
	s.Equal("namespacedCertificate", created["type"])
	s.Equal(name, created["name"])
	s.Equal(certPEM, created["certs"])
	s.Equal(nsName, created["namespaceId"])
	s.Equal(project.ID, created["projectId"])
	s.NotContains(created, "namespace")

	id := created["id"].(string)
	certURL := url + "/" + id

	updated := s.send(http.MethodPut, certURL, map[string]any{"certs": updatedCertPEM})
	s.Equal(nsName, updated["namespaceId"])
	s.Equal(project.ID, updated["projectId"])

	reloaded := s.send(http.MethodGet, certURL, nil)
	s.Equal("namespacedSecret", reloaded["baseType"])
	s.Equal("namespacedCertificate", reloaded["type"])
	s.Equal(name, reloaded["name"])
	s.Equal(updatedCertPEM, reloaded["certs"])
	s.Equal(nsName, reloaded["namespaceId"])
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, certURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, certURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "namespacedCertificate %s still readable after delete", id)
}

// TestNamespacedDockerCredential asserts that a namespaced docker credential
// can be created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestNamespacedDockerCredential() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "namespacedDockerCredentials")

	name := namegen.AppendRandomString("dockercred-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"namespaceId": nsName,
		"registries": map[string]any{
			"index.docker.io": map[string]any{
				"username": "foo",
				"password": "bar",
			},
		},
	})
	s.Equal("namespacedSecret", created["baseType"])
	s.Equal("namespacedDockerCredential", created["type"])
	s.Equal(name, created["name"])
	regs := created["registries"].(map[string]any)
	dockerIO := regs["index.docker.io"].(map[string]any)
	s.Equal("foo", dockerIO["username"])
	s.Contains(dockerIO, "password")
	s.Equal(nsName, created["namespaceId"])
	s.Equal(project.ID, created["projectId"])

	id := created["id"].(string)
	credURL := url + "/" + id

	// Update: add a second registry.
	s.send(http.MethodPut, credURL, map[string]any{
		"registries": map[string]any{
			"index.docker.io": map[string]any{
				"username": "foo",
				"password": "bar",
			},
			"two": map[string]any{
				"username": "blah",
			},
		},
	})

	reloaded := s.send(http.MethodGet, credURL, nil)
	s.Equal("namespacedSecret", reloaded["baseType"])
	s.Equal("namespacedDockerCredential", reloaded["type"])
	s.Equal(name, reloaded["name"])
	reloadedRegs := reloaded["registries"].(map[string]any)
	reloadedDockerIO := reloadedRegs["index.docker.io"].(map[string]any)
	s.Equal("foo", reloadedDockerIO["username"])
	reloadedTwo := reloadedRegs["two"].(map[string]any)
	s.Equal("blah", reloadedTwo["username"])
	// Password is write-only; should not be present after reload.
	s.NotContains(reloadedDockerIO, "password")
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, credURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, credURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "namespacedDockerCredential %s still readable after delete", id)
}

// TestNamespacedBasicAuth asserts that a namespaced basic-auth secret can be
// created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestNamespacedBasicAuth() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "namespacedBasicAuths")

	name := namegen.AppendRandomString("basicauth-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"namespaceId": nsName,
		"username":    "foo",
		"password":    "bar",
	})
	s.Equal("namespacedSecret", created["baseType"])
	s.Equal("namespacedBasicAuth", created["type"])
	s.Equal(name, created["name"])
	s.Equal("foo", created["username"])
	s.Contains(created, "password")
	s.Equal(nsName, created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	id := created["id"].(string)
	authURL := url + "/" + id

	s.send(http.MethodPut, authURL, map[string]any{"username": "foo2"})

	reloaded := s.send(http.MethodGet, authURL, nil)
	s.Equal("namespacedSecret", reloaded["baseType"])
	s.Equal("namespacedBasicAuth", reloaded["type"])
	s.Equal(name, reloaded["name"])
	s.Equal("foo2", reloaded["username"])
	// Password is write-only; should not be present after reload.
	s.NotContains(reloaded, "password")
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, authURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, authURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "namespacedBasicAuth %s still readable after delete", id)
}

// TestNamespacedSSHAuth asserts that a namespaced SSH auth secret can be
// created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestNamespacedSSHAuth() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	url := s.projectURL(project, "namespacedSshAuths")

	name := namegen.AppendRandomString("sshauth-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":        name,
		"namespaceId": nsName,
		"privateKey":  "foo",
	})
	s.Equal("namespacedSecret", created["baseType"])
	s.Equal("namespacedSshAuth", created["type"])
	s.Equal(name, created["name"])
	s.Contains(created, "privateKey")
	s.Equal(nsName, created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	id := created["id"].(string)
	authURL := url + "/" + id

	s.send(http.MethodPut, authURL, map[string]any{"privateKey": "foo2"})

	reloaded := s.send(http.MethodGet, authURL, nil)
	s.Equal("namespacedSecret", reloaded["baseType"])
	s.Equal("namespacedSshAuth", reloaded["type"])
	s.Equal(name, reloaded["name"])
	// privateKey is write-only; should not be present after reload.
	s.NotContains(reloaded, "privateKey")
	s.Equal(nsName, reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, authURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, authURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "namespacedSshAuth %s still readable after delete", id)
}
