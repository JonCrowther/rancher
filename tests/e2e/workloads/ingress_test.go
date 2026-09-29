package workloads

import (
	"net/http"

	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestIngressFields verifies that the Norman schema for ingress, ingressBackend,
// ingressRule, and httpIngressPath exposes the expected methods and fields with
// the correct create/update permissions.
func (s *WorkloadsTestSuite) TestIngressFields() {
	client := s.newSubSession()
	project := s.createProject(client)

	cru := fieldAccess{Create: true, Update: true}
	cr := fieldAccess{Create: true, Update: false}
	r := fieldAccess{Create: false, Update: false}

	tests := []struct {
		typeName          string
		collectionMethods []string
		resourceMethods   []string
		fields            map[string]fieldAccess
	}{
		{
			typeName:          "ingress",
			collectionMethods: []string{"GET", "POST"},
			resourceMethods:   []string{"GET", "PUT", "DELETE"},
			fields: map[string]fieldAccess{
				"namespaceId":      cr,
				"projectId":        cr,
				"rules":            cru,
				"tls":              cru,
				"ingressClassName": cru,
				"backend":          cru,
				"defaultBackend":   cru,
				"publicEndpoints":  r,
				"status":           r,
			},
		},
		{
			// The embedded types have no API methods of their own.
			typeName: "ingressBackend",
			fields: map[string]fieldAccess{
				"serviceId":   cru,
				"service":     cru,
				"targetPort":  cru,
				"resource":    cru,
				"workloadIds": cru,
			},
		},
		{
			typeName: "ingressRule",
			fields: map[string]fieldAccess{
				"host":  cru,
				"paths": cru,
			},
		},
		{
			typeName: "httpIngressPath",
			fields: map[string]fieldAccess{
				"resource":    cru,
				"pathType":    cru,
				"path":        cru,
				"serviceId":   cru,
				"service":     cru,
				"targetPort":  cru,
				"workloadIds": cru,
			},
		},
	}

	for _, tt := range tests {
		schema, err := s.getSchema(project, tt.typeName)
		if !s.NoErrorf(err, "schema %s", tt.typeName) {
			continue
		}
		s.ElementsMatchf(tt.collectionMethods, schema.CollectionMethods, "schema %s: collectionMethods", tt.typeName)
		s.ElementsMatchf(tt.resourceMethods, schema.ResourceMethods, "schema %s: resourceMethods", tt.typeName)
		for fieldName, want := range tt.fields {
			field, ok := schema.ResourceFields[fieldName]
			if s.Truef(ok, "schema %s: expected field %q to be present", tt.typeName, fieldName) {
				s.Equalf(want, field, "schema %s field %q: unexpected create/update permissions", tt.typeName, fieldName)
			}
		}
	}
}

// TestIngress asserts that an ingress can be created with a single rule via the
// Norman project API and that the rule's host, path, targetPort, workloadIds,
// and serviceId are stored correctly.
func (s *WorkloadsTestSuite) TestIngress() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	workload := s.send(http.MethodPost, s.projectURL(project, "workloads"), nginxWorkload(nsName))
	workloadID := workload["id"].(string)

	ingress := s.send(http.MethodPost, s.projectURL(project, "ingresses"), map[string]any{
		"name":        namegen.AppendRandomString("ing-") + "." + namegen.AppendRandomString("suf-"),
		"namespaceId": nsName,
		"rules": []any{
			map[string]any{
				"host": "foo.com",
				"paths": []any{
					map[string]any{
						"path":        "/",
						"targetPort":  80,
						"workloadIds": []string{workloadID},
					},
				},
			},
		},
	})

	rules := ingress["rules"].([]any)
	s.Require().Len(rules, 1)
	rule := rules[0].(map[string]any)
	s.Equal("foo.com", rule["host"])

	paths := rule["paths"].([]any)
	s.Require().Len(paths, 1)
	path := paths[0].(map[string]any)
	s.Equal("/", path["path"])
	s.EqualValues(80, path["targetPort"])
	s.Equal([]string{workloadID}, toStringSlice(path["workloadIds"]))
	s.Nil(path["serviceId"])
}

// TestIngressRulesSameHostPortPath asserts that when two ingress rules share the
// same host and path, the Norman API merges them into a single rule whose path
// entry contains workload IDs from both original rules.
func (s *WorkloadsTestSuite) TestIngressRulesSameHostPortPath() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	workloadsURL := s.projectURL(project, "workloads")
	workload1ID := s.send(http.MethodPost, workloadsURL, nginxWorkload(nsName))["id"].(string)
	workload2ID := s.send(http.MethodPost, workloadsURL, nginxWorkload(nsName))["id"].(string)

	rule := func(workloadID string) map[string]any {
		return map[string]any{
			"host": "foo.com",
			"paths": []any{
				map[string]any{
					"path":        "/",
					"targetPort":  80,
					"workloadIds": []string{workloadID},
				},
			},
		}
	}
	ingress := s.send(http.MethodPost, s.projectURL(project, "ingresses"), map[string]any{
		"name":        namegen.AppendRandomString("ing-"),
		"namespaceId": nsName,
		"rules":       []any{rule(workload1ID), rule(workload2ID)},
	})

	// The two rules with the same host+path should be merged into one.
	rules := ingress["rules"].([]any)
	s.Require().Len(rules, 1)
	merged := rules[0].(map[string]any)
	s.Equal("foo.com", merged["host"])

	paths := merged["paths"].([]any)
	s.Require().Len(paths, 1)
	path := paths[0].(map[string]any)
	s.Equal("/", path["path"])
	s.EqualValues(80, path["targetPort"])
	s.ElementsMatch([]string{workload1ID, workload2ID}, toStringSlice(path["workloadIds"]))
	s.Nil(path["serviceId"])
}
