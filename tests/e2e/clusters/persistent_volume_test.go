package clusters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
)

func (s *ClustersTestSuite) pvURL() string {
	return fmt.Sprintf("https://%s/v3/cluster/%s/persistentVolumes",
		s.client.WranglerContext.RESTConfig.Host, s.clusterID)
}

func (s *ClustersTestSuite) postPV(httpClient *http.Client, body map[string]any) map[string]any {
	b, err := json.Marshal(body)
	s.Require().NoError(err)
	resp, err := httpClient.Post(s.pvURL(), "application/json", bytes.NewReader(b))
	s.Require().NoError(err)
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	s.Require().Truef(resp.StatusCode >= 200 && resp.StatusCode < 300,
		"unexpected status %d creating PV: %s", resp.StatusCode, string(respBody))
	var result map[string]any
	s.Require().NoError(json.Unmarshal(respBody, &result))
	return result
}

func (s *ClustersTestSuite) putPV(httpClient *http.Client, id string, body map[string]any) map[string]any {
	b, err := json.Marshal(body)
	s.Require().NoError(err)
	url := fmt.Sprintf("%s/%s", s.pvURL(), id)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(b))
	s.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	s.Require().NoError(err)
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	s.Require().Truef(resp.StatusCode >= 200 && resp.StatusCode < 300,
		"unexpected status %d updating PV: %s", resp.StatusCode, string(respBody))
	var result map[string]any
	s.Require().NoError(json.Unmarshal(respBody, &result))
	return result
}

// TestPersistentVolumeUpdate asserts that read-only fields within a
// persistentVolumeSource cannot be mutated after creation, and that the
// persistentVolumeSource type itself cannot be changed once set.
func (s *ClustersTestSuite) TestPersistentVolumeUpdate() {
	httpClient := s.httpClient()

	name := namegen.AppendRandomString("pv-")
	pv := s.postPV(httpClient, map[string]any{
		"clusterId":   s.clusterID,
		"name":        name,
		"accessModes": []string{"ReadWriteOnce"},
		"capacity":    map[string]any{"storage": "10Gi"},
		"cinder": map[string]any{
			"readOnly": "false",
			"secretRef": map[string]any{
				"name":      "fss",
				"namespace": "fsf",
			},
			"volumeID": "fss",
			"fsType":   "fss",
		},
	})
	s.Require().NotNil(pv)

	id, ok := pv["id"].(string)
	s.Require().Truef(ok, "created PV has no id: %v", pv)
	// The PV is created through the raw Norman API, which the session doesn't track.
	t := s.T()
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/%s", s.pvURL(), id), nil)
		if !assert.NoError(t, err) {
			return
		}
		resp, err := httpClient.Do(req)
		if !assert.NoError(t, err, "failed to delete PV %s", id) {
			return
		}
		resp.Body.Close()
		assert.Truef(t, resp.StatusCode < 300 || resp.StatusCode == http.StatusNotFound,
			"unexpected status %d deleting PV %s", resp.StatusCode, id)
	})

	// Fields within the persistentVolumeSource should not be updated.
	updated := s.putPV(httpClient, id, map[string]any{
		"cinder": map[string]any{"readOnly": "true"},
	})
	cinder, ok := updated["cinder"].(map[string]any)
	s.Require().Truef(ok, "updated PV has no cinder source: %v", updated)
	// readOnly must remain false — it is not updatable.
	s.Equal(false, cinder["readOnly"], "cinder.readOnly should not have been updated")

	// The persistentVolumeSource type cannot be changed from cinder to azureFile.
	updated = s.putPV(httpClient, id, map[string]any{
		"azureFile": map[string]any{
			"readOnly":  "true",
			"shareName": "abc",
		},
		"cinder": map[string]any{},
	})
	_, hasAzureFile := updated["azureFile"]
	s.False(hasAzureFile, "azureFile should not be present after attempting to change PV source type")
}
