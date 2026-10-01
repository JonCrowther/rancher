package secrets

import (
	"fmt"
	"net/http"

	stevesecrets "github.com/rancher/rancher/tests/e2e/actions/secrets"
	"github.com/rancher/shepherd/pkg/clientbase"
	"github.com/rancher/shepherd/pkg/namegenerator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestLinks verifies the id and the links Steve returns for a secret.
func (s *SecretsTestSuite) TestLinks() {
	client, err := s.newSubSession().Steve.ProxyDownstream(s.clusterID)
	s.Require().NoError(err)

	secretClient := client.SteveType(stevesecrets.SecretSteveType)

	secretObj, err := secretClient.Create(corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      namegenerator.AppendRandomString("steve-secret-squirrel"),
			Namespace: namespaceMap["test-ns-1"],
		},
		Data: map[string][]byte{"foo": []byte("bar")},
	})
	s.Require().NoError(err)

	readObj, err := secretClient.ByID(secretObj.ID)
	s.Require().NoError(err)

	host := s.client.RancherConfig.Host
	expectedID := secretObj.Namespace + "/" + secretObj.Name
	s.Equal(expectedID, readObj.JSONResp["id"])
	s.Equal(map[string]any{
		"patch":  fmt.Sprintf("https://%s/v1/secrets/%s", host, expectedID),
		"remove": fmt.Sprintf("https://%s/v1/secrets/%s", host, expectedID),
		"update": fmt.Sprintf("https://%s/v1/secrets/%s", host, expectedID),
		"self":   fmt.Sprintf("https://%s/v1/secrets/%s", host, expectedID),
		"view":   fmt.Sprintf("https://%s/api/v1/namespaces/%s/secrets/%s", host, secretObj.Namespace, secretObj.Name),
	}, readObj.JSONResp["links"])
}

// TestCRUD verifies that a secret can be created, read, updated and deleted through Steve, both via
// the global /v1/secrets endpoint and via the namespaced /v1/secrets/<namespace> endpoint.
func (s *SecretsTestSuite) TestCRUD() {
	client, err := s.newSubSession().Steve.ProxyDownstream(s.clusterID)
	s.Require().NoError(err)

	s.Run("global", func() {
		secretClient := client.SteveType(stevesecrets.SecretSteveType)

		// create
		secretObj, err := secretClient.Create(corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      namegenerator.AppendRandomString("steve-secret-garden"),
				Namespace: namespaceMap["test-ns-1"], // need to specify the namespace for a namespaced resource if using a global endpoint ("/v1/secrets")
			},
			Data: map[string][]byte{"foo": []byte("bar")},
		})
		s.Require().NoError(err)

		// read
		readObj, err := secretClient.ByID(secretObj.ID)
		s.Require().NoError(err)
		s.Contains(readObj.JSONResp["data"], "foo")

		// update
		updatedSecret := secretObj.JSONResp
		updatedSecret["data"] = map[string][]byte{"lorem": []byte("ipsum")}
		secretObj, err = secretClient.Update(secretObj, &updatedSecret)
		s.Require().NoError(err)

		// read again
		readObj, err = secretClient.ByID(secretObj.ID)
		s.Require().NoError(err)
		s.Contains(readObj.JSONResp["data"], "lorem")
		s.NotContains(readObj.JSONResp["data"], "foo")

		// delete
		s.Require().NoError(secretClient.Delete(readObj))

		// read again
		_, err = secretClient.ByID(secretObj.ID)
		var apiErr *clientbase.APIError
		s.Require().ErrorAs(err, &apiErr)
		s.Equal(http.StatusNotFound, apiErr.StatusCode)
	})

	s.Run("namespaced", func() {
		secretClient := client.SteveType(stevesecrets.SecretSteveType).NamespacedSteveClient(namespaceMap["test-ns-1"])

		// create
		secretObj, err := secretClient.Create(corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: namegenerator.AppendRandomString("steve-secret-six"),
				// no need to provide a namespace since using a namespaced endpoint ("/v1/secrets/test-ns-1")
			},
			Data: map[string][]byte{"foo": []byte("bar")},
		})
		s.Require().NoError(err)

		// read
		readObj, err := secretClient.ByID(secretObj.ID)
		s.Require().NoError(err)
		s.Contains(readObj.JSONResp["data"], "foo")

		// update
		updatedSecret := secretObj.JSONResp
		updatedSecret["data"] = map[string][]byte{"lorem": []byte("ipsum")}
		secretObj, err = secretClient.Update(secretObj, &updatedSecret)
		s.Require().NoError(err)

		// read again
		readObj, err = secretClient.ByID(secretObj.ID)
		s.Require().NoError(err)
		s.Contains(readObj.JSONResp["data"], "lorem")
		s.NotContains(readObj.JSONResp["data"], "foo")

		// delete
		s.Require().NoError(secretClient.Delete(readObj))

		// read again
		_, err = secretClient.ByID(secretObj.ID)
		var apiErr *clientbase.APIError
		s.Require().ErrorAs(err, &apiErr)
		s.Equal(http.StatusNotFound, apiErr.StatusCode)
	})
}
