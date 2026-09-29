package workloads

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rancher/rancher/tests/e2e/actions/kubeapi/secrets"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSecrets asserts that a project-scoped Opaque secret can be created,
// updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestSecrets() {
	client := s.newSubSession()
	project := s.createProject(client)
	url := s.projectURL(project, "secrets")

	name := namegen.AppendRandomString("secret-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":       name,
		"stringData": map[string]any{"foo": "bar"},
	})
	s.Equal("secret", created["type"])
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
	s.Equal("secret", reloaded["baseType"])
	s.Equal("secret", reloaded["type"])
	s.Equal("Opaque", reloaded["kind"])
	s.Equal(name, reloaded["name"])
	reloadedData := reloaded["data"].(map[string]any)
	s.Equal("YmFy", reloadedData["foo"])
	s.Equal("YmFy", reloadedData["baz"])
	s.Nil(reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, secretURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, secretURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "secret %s still readable after delete", id)
}

// TestCertificates asserts that a project-scoped certificate can be created,
// listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestCertificates() {
	client := s.newSubSession()
	project := s.createProject(client)
	url := s.projectURL(project, "certificates")

	name := namegen.AppendRandomString("cert-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":  name,
		"key":   keyPEM,
		"certs": certPEM,
	})
	s.Equal("secret", created["baseType"])
	s.Equal("2026-06-28T01:13:32Z", created["expiresAt"])
	s.Equal("certificate", created["type"])
	s.Equal(name, created["name"])
	s.Equal(certPEM, created["certs"])
	s.Nil(created["namespaceId"])
	s.NotContains(created, "namespace")

	id := created["id"].(string)
	certURL := url + "/" + id

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, certURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, certURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "certificate %s still readable after delete", id)
}

// TestDockerCredential asserts that a project-scoped docker credential can be
// created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestDockerCredential() {
	client := s.newSubSession()
	project := s.createProject(client)
	url := s.projectURL(project, "dockerCredentials")

	name := namegen.AppendRandomString("dockercred-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name": name,
		"registries": map[string]any{
			"index.docker.io": map[string]any{
				"username": "foo",
				"password": "bar",
			},
		},
	})
	s.Equal("secret", created["baseType"])
	s.Equal("dockerCredential", created["type"])
	s.Equal(name, created["name"])
	regs := created["registries"].(map[string]any)
	dockerIO := regs["index.docker.io"].(map[string]any)
	s.Equal("foo", dockerIO["username"])
	s.Contains(dockerIO, "password")
	s.Contains(dockerIO, "auth")
	s.Nil(created["namespaceId"])
	s.NotContains(created, "namespace")
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
	s.Equal("secret", reloaded["baseType"])
	s.Equal("dockerCredential", reloaded["type"])
	s.Equal(name, reloaded["name"])
	reloadedRegs := reloaded["registries"].(map[string]any)
	reloadedDockerIO := reloadedRegs["index.docker.io"].(map[string]any)
	s.Equal("foo", reloadedDockerIO["username"])
	reloadedTwo := reloadedRegs["two"].(map[string]any)
	s.Equal("blah", reloadedTwo["username"])
	// Password is write-only; should not be present after reload.
	s.NotContains(reloadedDockerIO, "password")
	s.Nil(reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, credURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, credURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "dockerCredential %s still readable after delete", id)
}

// TestBasicAuth asserts that a project-scoped basic-auth secret can be
// created, updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestBasicAuth() {
	client := s.newSubSession()
	project := s.createProject(client)
	url := s.projectURL(project, "basicAuths")

	name := namegen.AppendRandomString("basicauth-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":     name,
		"username": "foo",
		"password": "bar",
	})
	s.Equal("secret", created["baseType"])
	s.Equal("basicAuth", created["type"])
	s.Equal(name, created["name"])
	s.Equal("foo", created["username"])
	s.Contains(created, "password")
	s.Nil(created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	id := created["id"].(string)
	authURL := url + "/" + id

	s.send(http.MethodPut, authURL, map[string]any{"username": "foo2"})

	reloaded := s.send(http.MethodGet, authURL, nil)
	s.Equal("secret", reloaded["baseType"])
	s.Equal("basicAuth", reloaded["type"])
	s.Equal(name, reloaded["name"])
	s.Equal("foo2", reloaded["username"])
	// Password is write-only; should not be present after reload.
	s.NotContains(reloaded, "password")
	s.Nil(reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, authURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, authURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "basicAuth %s still readable after delete", id)
}

// TestSSHAuth asserts that a project-scoped SSH auth secret can be created,
// updated, listed, and deleted via the Norman project API.
func (s *WorkloadsTestSuite) TestSSHAuth() {
	client := s.newSubSession()
	project := s.createProject(client)
	url := s.projectURL(project, "sshAuths")

	name := namegen.AppendRandomString("sshauth-")
	created := s.send(http.MethodPost, url, map[string]any{
		"name":       name,
		"privateKey": "foo",
	})
	s.Equal("secret", created["baseType"])
	s.Equal("sshAuth", created["type"])
	s.Equal(name, created["name"])
	s.Contains(created, "privateKey")
	s.Nil(created["namespaceId"])
	s.NotContains(created, "namespace")
	s.Equal(project.ID, created["projectId"])

	id := created["id"].(string)
	authURL := url + "/" + id

	s.send(http.MethodPut, authURL, map[string]any{"privateKey": "foo2"})

	reloaded := s.send(http.MethodGet, authURL, nil)
	s.Equal("secret", reloaded["baseType"])
	s.Equal("sshAuth", reloaded["type"])
	s.Equal(name, reloaded["name"])
	// privateKey is write-only; should not be present after reload.
	s.NotContains(reloaded, "privateKey")
	s.Nil(reloaded["namespaceId"])
	s.NotContains(reloaded, "namespace")
	s.Equal(project.ID, reloaded["projectId"])

	ids, err := s.listIDs(url)
	s.Require().NoError(err)
	s.Contains(ids, id)

	s.send(http.MethodDelete, authURL, nil)
	s.Eventually(func() bool {
		status, _, err := do(s.httpClient, http.MethodGet, authURL, nil)
		return err == nil && status == http.StatusNotFound
	}, 30*time.Second, time.Second, "sshAuth %s still readable after delete", id)
}

// TestSecretCreationKubectl asserts that a TLS secret created directly via the
// Kubernetes API is accessible as a namespacedCertificate through the Rancher
// project API, with an RSA algorithm and valid certificate metadata.
func (s *WorkloadsTestSuite) TestSecretCreationKubectl() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	secretName := namegen.AppendRandomString("tlssecret-")
	_, err := secrets.CreateSecretForCluster(client, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: nsName},
		StringData: map[string]string{
			"tls.key": keyPEM,
			"tls.crt": certPEM,
		},
		Type: corev1.SecretTypeTLS,
	}, s.clusterID, nsName)
	s.Require().NoError(err)

	certID := fmt.Sprintf("%s:%s", nsName, secretName)
	certURL := s.projectURL(project, "namespacedCertificates/"+certID)
	var cert map[string]any
	s.Require().Eventually(func() bool {
		status, body, err := do(s.httpClient, http.MethodGet, certURL, nil)
		return err == nil && status == http.StatusOK && json.Unmarshal(body, &cert) == nil
	}, 30*time.Second, time.Second, "namespacedCertificate %s never became readable", certID)

	algorithm, _ := cert["algorithm"].(string)
	s.Contains(algorithm, "RSA")
	s.NotNil(cert["expiresAt"])
	s.NotNil(cert["issuedAt"])
}

// TestMalformedSecretParse asserts that a TLS secret with a malformed
// certificate created directly via the Kubernetes API can still be retrieved
// as a namespacedCertificate through the Rancher project API.
func (s *WorkloadsTestSuite) TestMalformedSecretParse() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	secretName := namegen.AppendRandomString("malformedcert-")
	_, err := secrets.CreateSecretForCluster(client, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: nsName},
		StringData: map[string]string{
			"tls.key": keyPEM,
			"tls.crt": malformedCertPEM,
		},
		Type: corev1.SecretTypeTLS,
	}, s.clusterID, nsName)
	s.Require().NoError(err)

	certID := fmt.Sprintf("%s:%s", nsName, secretName)
	certURL := s.projectURL(project, "namespacedCertificates/"+certID)
	var cert map[string]any
	s.Require().Eventually(func() bool {
		status, body, err := do(s.httpClient, http.MethodGet, certURL, nil)
		return err == nil && status == http.StatusOK && json.Unmarshal(body, &cert) == nil
	}, 30*time.Second, time.Second, "namespacedCertificate %s never became readable", certID)

	s.Equal(certID, cert["id"])
	s.Equal(secretName, cert["name"])
}
