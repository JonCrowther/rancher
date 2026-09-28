package clusters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type nodeSchema struct {
	CollectionMethods []string `json:"collectionMethods"`
	ResourceMethods   []string `json:"resourceMethods"`
	ResourceFields    map[string]struct {
		Create bool `json:"create"`
		Update bool `json:"update"`
	} `json:"resourceFields"`
}

func (s *ClustersTestSuite) schemaURL(typeName string) string {
	return fmt.Sprintf("https://%s/v3/schemas/%s",
		s.client.WranglerContext.RESTConfig.Host, typeName)
}

// fetchSchema retrieves and unmarshals a Norman schema by type name.
func (s *ClustersTestSuite) fetchSchema(typeName string) nodeSchema {
	resp, err := s.httpClient().Get(s.schemaURL(typeName))
	s.Require().NoError(err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	s.Require().NoError(err)
	s.Require().Equalf(http.StatusOK, resp.StatusCode, "schema %q not found", typeName)

	var sc nodeSchema
	s.Require().NoError(json.Unmarshal(body, &sc))
	return sc
}

// TestNodeFields verifies that the Norman management schema for the node type
// exposes full CRUD access and that every explicitly named field has the
// expected create/update permissions. Fields whose names end with "Config"
// are expected to be create-only (cr), except customConfig which is (cru).
func (s *ClustersTestSuite) TestNodeFields() {
	sc := s.fetchSchema("node")

	// Verify CRUD methods.
	s.Contains(sc.CollectionMethods, "GET")
	s.Contains(sc.CollectionMethods, "POST")
	s.Contains(sc.ResourceMethods, "GET")
	s.Contains(sc.ResourceMethods, "PUT")
	s.Contains(sc.ResourceMethods, "DELETE")

	type perm struct{ create, update bool }
	cr := perm{true, false}
	cru := perm{true, true}
	ru := perm{false, true}
	r := perm{false, false}

	explicit := map[string]perm{
		"allocatable":        r,
		"annotations":        cru,
		"appliedNodeVersion": r,
		"capacity":           r,
		"clusterId":          cr,
		"conditions":         r,
		"controlPlane":       cr,
		"declaredFeatures":   r,
		"dockerInfo":         r,
		"etcd":               cr,
		"externalIpAddress":  r,
		"features":           r,
		"hostname":           r,
		"imported":           cru,
		"info":               r,
		"ipAddress":          r,
		"labels":             cru,
		"limits":             r,
		"name":               cru,
		"namespaceId":        cr,
		"nodeName":           r,
		"nodeTaints":         r,
		"podCidr":            r,
		"podCidrs":           r,
		"providerId":         r,
		"publicEndpoints":    r,
		"requested":          r,
		"requestedHostname":  cr,
		"runtimeHandlers":    r,
		"scaledownTime":      cru,
		"taints":             ru,
		"unschedulable":      r,
		"volumesAttached":    r,
		"volumesInUse":       r,
		"worker":             cr,
	}

	// Check explicit fields.
	for fieldName, want := range explicit {
		field, ok := sc.ResourceFields[fieldName]
		s.Truef(ok, "expected field %q in node schema", fieldName)
		if !ok {
			continue
		}
		s.Equalf(want.create, field.Create, "field %q: unexpected create permission", fieldName)
		s.Equalf(want.update, field.Update, "field %q: unexpected update permission", fieldName)
	}

	// Fields ending in "Config" should be cr, except customConfig which is cru.
	s.Contains(sc.ResourceFields, "customConfig", "expected field \"customConfig\" in node schema")
	for fieldName, field := range sc.ResourceFields {
		if !strings.HasSuffix(fieldName, "Config") {
			continue
		}
		if fieldName == "customConfig" {
			s.Truef(field.Create && field.Update,
				"field %q: expected cru (create=true, update=true)", fieldName)
		} else {
			s.Truef(field.Create && !field.Update,
				"field %q: expected cr (create=true, update=false)", fieldName)
		}
	}
}

// TestNodeDriverSchema asserts that the amazonec2config, digitaloceanconfig, and
// azureconfig schemas do not expose sensitive path fields that could allow
// local filesystem access.
func (s *ClustersTestSuite) TestNodeDriverSchema() {
	drivers := []string{"amazonec2config", "digitaloceanconfig", "azureconfig"}
	badFields := []string{"sshKeypath", "sshKeyPath", "existingKeyPath"}

	for _, driver := range drivers {
		sc := s.fetchSchema(driver)
		// A schema with no fields would pass the checks below without testing anything.
		s.Require().NotEmptyf(sc.ResourceFields, "schema %s has no resource fields", driver)
		for _, field := range badFields {
			_, present := sc.ResourceFields[field]
			s.Falsef(present, "driver %s should not expose field %q", driver, field)
		}
	}
}

// TestAmazonNodeDriverSchema asserts that the amazonec2config schema includes
// AWS-specific fields required for EBS volume encryption support.
func (s *ClustersTestSuite) TestAmazonNodeDriverSchema() {
	sc := s.fetchSchema("amazonec2config")

	requiredFields := []string{"encryptEbsVolume"}
	for _, field := range requiredFields {
		_, present := sc.ResourceFields[field]
		s.Truef(present, "amazonec2config schema is missing required field %q", field)
	}
}
