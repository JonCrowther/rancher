package workloads

import (
	"net/http"

	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestHPA asserts that a HorizontalPodAutoscaler can be created via the Norman
// project API with multiple metric types (Resource, Pods, External, Object),
// and that it appears in the HPA list with the expected state.
func (s *WorkloadsTestSuite) TestHPA() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	body := nginxWorkload(nsName)
	body["containers"] = []any{map[string]any{
		"name":      "one",
		"image":     "nginx",
		"resources": map[string]any{"requests": "100m"},
	}}
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)
	workloadID, _ := wl["id"].(string)
	s.Require().NotEmpty(workloadID)

	hpaURL := s.projectURL(project, "horizontalPodAutoscalers")
	s.send(http.MethodPost, hpaURL, map[string]any{
		"name":        namegen.AppendRandomString("hpa-"),
		"namespaceId": nsName,
		"maxReplicas": 10,
		"workloadId":  workloadID,
		"metrics": []any{
			map[string]any{
				"name": "cpu",
				"type": "Resource",
				"target": map[string]any{
					"type":        "Utilization",
					"utilization": "50",
				},
			},
			map[string]any{
				"name": "pods-test",
				"type": "Pods",
				"target": map[string]any{
					"type":         "AverageValue",
					"averageValue": "50",
				},
			},
			map[string]any{
				"name": "pods-external",
				"type": "External",
				"target": map[string]any{
					"type":  "Value",
					"value": "50",
				},
			},
			map[string]any{
				"describedObject": map[string]any{
					"apiVersion": "extensions/v1beta1",
					"kind":       "Ingress",
					"name":       "test",
				},
				"name": "object-test",
				"type": "Object",
				"target": map[string]any{
					"type":  "Value",
					"value": "50",
				},
			},
		},
	})

	// The namespace is new, so the HPA just created is the only one in it.
	hpas, err := s.list(hpaURL + "?namespaceId=" + nsName)
	s.Require().NoError(err)
	s.Require().Len(hpas, 1)
	s.Equal("initializing", hpas[0]["state"])
}
