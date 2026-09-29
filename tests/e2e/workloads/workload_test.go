package workloads

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	extdeployments "github.com/rancher/rancher/tests/e2e/actions/kubeapi/deployments"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// portEntry mirrors the Rancher Norman port representation for workload containers.
type portEntry struct {
	Kind          string `json:"kind"`
	SourcePort    int    `json:"sourcePort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
}

// TestDeploymentCreationKubectl asserts that a Deployment created directly
// via the Kubernetes API appears in the Norman workload API with the correct
// port mapping (hostPort translated to sourcePort + kind=HostPort).
func (s *WorkloadsTestSuite) TestDeploymentCreationKubectl() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	deploymentName := namegen.AppendRandomString("dep-")
	template := corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.7.9",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 80,
							HostPort:      8099,
						},
					},
				},
			},
		},
	}
	_, err := extdeployments.CreateDeployment(client, s.clusterID, deploymentName, nsName, template, 1)
	s.Require().NoError(err)

	// Poll the Norman workload API until the deployment appears and the port
	// mapping has been translated from hostPort to sourcePort + kind.
	listURL := s.projectURL(project, "workloads") + "?namespaceId=" + nsName
	var port map[string]any
	s.Require().Eventually(func() bool {
		workloads, err := s.list(listURL)
		if err != nil {
			return false
		}
		for _, wl := range workloads {
			if wl["name"] != deploymentName {
				continue
			}
			containers, _ := wl["containers"].([]any)
			if len(containers) == 0 {
				return false
			}
			container, _ := containers[0].(map[string]any)
			ports, _ := container["ports"].([]any)
			if len(ports) == 0 {
				return false
			}
			port, _ = ports[0].(map[string]any)
			return port != nil
		}
		return false
	}, 30*time.Second, 2*time.Second, "workload %s not found in Norman API for project %s", deploymentName, project.ID)

	s.Equal("HostPort", port["kind"])
	s.EqualValues(8099, port["sourcePort"])
	s.EqualValues(80, port["containerPort"])
}

// TestWorkloadPortKinds asserts that workloads created via the Norman project
// API correctly store the port kind and sourcePort for each port type
// (HostPort, NodePort, LoadBalancer, ClusterIP).
func (s *WorkloadsTestSuite) TestWorkloadPortKinds() {
	client := s.newSubSession()
	project := s.createProject(client)
	workloadsURL := s.projectURL(project, "workloads")

	portTests := []portEntry{
		{SourcePort: 776, ContainerPort: 80, Kind: "HostPort", Protocol: "TCP"},
		{SourcePort: 777, ContainerPort: 80, Kind: "NodePort", Protocol: "TCP"},
		{SourcePort: 778, ContainerPort: 80, Kind: "LoadBalancer", Protocol: "TCP"},
		{SourcePort: 779, ContainerPort: 80, Kind: "ClusterIP", Protocol: "TCP"},
	}
	for _, port := range portTests {
		body := nginxWorkload(s.createNamespace(client, project))
		body["containers"] = []any{map[string]any{"name": "one", "image": "nginx", "ports": []any{port}}}
		wl := s.send(http.MethodPost, workloadsURL, body)

		containers, _ := wl["containers"].([]any)
		s.Require().NotEmptyf(containers, "expected containers in workload response for kind %s", port.Kind)
		container, _ := containers[0].(map[string]any)
		ports, _ := container["ports"].([]any)
		s.Require().NotEmptyf(ports, "expected ports in container for kind %s", port.Kind)
		got, _ := ports[0].(map[string]any)

		s.Equalf(port.Kind, got["kind"], "port kind mismatch")
		s.EqualValuesf(port.ContainerPort, got["containerPort"], "containerPort mismatch for kind %s", port.Kind)
		s.EqualValuesf(port.SourcePort, got["sourcePort"], "sourcePort mismatch for kind %s", port.Kind)
	}
}

// TestWorkloadImageChangePrivateRegistry asserts that when a workload image is
// updated to reference a different registry, the correct docker credential is
// automatically selected as the imagePullSecret.
func (s *WorkloadsTestSuite) TestWorkloadImageChangePrivateRegistry() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	credsURL := s.projectURL(project, "dockerCredentials")

	registry := func(host string) map[string]any {
		return s.send(http.MethodPost, credsURL, map[string]any{
			"name": namegen.AppendRandomString("reg-"),
			"registries": map[string]any{
				host: map[string]any{"username": "testuser", "password": "foobarbaz"},
			},
		})
	}
	registry1 := registry("index.docker.io")
	registry2 := registry("quay.io")
	registry1ID := registry1["id"].(string)
	registry2ID := registry2["id"].(string)

	// The workload store picks pull secrets from this same dockerCredential list, so wait for both
	// credentials to be listed before creating the workload.
	s.Require().Eventually(func() bool {
		ids, err := s.listIDs(credsURL)
		return err == nil && slices.Contains(ids, registry1ID) && slices.Contains(ids, registry2ID)
	}, 30*time.Second, time.Second, "docker credentials %s and %s never listed", registry1ID, registry2ID)

	// A docker.io image should get registry1 as its pull secret.
	body := nginxWorkload(nsName)
	body["containers"] = []any{map[string]any{"name": "one", "image": "testuser/testimage"}}
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)
	pullSecrets, ok := wl["imagePullSecrets"].([]any)
	s.Require().True(ok)
	s.Require().Len(pullSecrets, 1)
	s.Equal(registry1["name"], pullSecrets[0].(map[string]any)["name"])

	// Updating to a quay.io image should switch the pull secret to registry2.
	wlURL := s.projectURL(project, "workloads/"+wl["id"].(string))
	updated := s.send(http.MethodPut, wlURL, map[string]any{
		"containers": []any{
			map[string]any{"name": "one", "image": "quay.io/testuser/testimage"},
		},
	})
	containers, ok := updated["containers"].([]any)
	s.Require().True(ok)
	s.Require().NotEmpty(containers)
	s.Equal("quay.io/testuser/testimage", containers[0].(map[string]any)["image"])

	pullSecrets, ok = updated["imagePullSecrets"].([]any)
	s.Require().True(ok)
	s.Require().Len(pullSecrets, 1)
	s.Equal(registry2["name"], pullSecrets[0].(map[string]any)["name"])
}

// TestWorkloadPortsChange asserts that changing container ports on a workload
// correctly updates the backing ClusterIP service's cluster IP field.
func (s *WorkloadsTestSuite) TestWorkloadPortsChange() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	// Create workload with no ports — expect a headless service (no cluster IP).
	body := nginxWorkload(nsName)
	workloadName := body["name"].(string)
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)
	wlURL := s.projectURL(project, "workloads/"+wl["id"].(string))

	svcListURL := fmt.Sprintf("%s?name=%s&kind=ClusterIP", s.projectURL(project, "services"), workloadName)
	clusterIP := func() (string, error) {
		services, err := s.list(svcListURL)
		if err != nil {
			return "", err
		}
		if len(services) == 0 {
			return "", errors.New("service not found")
		}
		ip, _ := services[0]["clusterIp"].(string)
		return ip, nil
	}

	s.Eventually(func() bool {
		ip, err := clusterIP()
		return err == nil && ip == ""
	}, 30*time.Second, time.Second, "headless service for %s never appeared without a cluster IP", workloadName)

	// Adding a ClusterIP port should assign a cluster IP.
	s.send(http.MethodPut, wlURL, map[string]any{
		"namespaceId": nsName,
		"scale":       1,
		"containers": []any{map[string]any{
			"name":  "one",
			"image": "nginx",
			"ports": []any{map[string]any{
				"sourcePort":    "0",
				"containerPort": "80",
				"kind":          "ClusterIP",
				"protocol":      "TCP",
			}},
		}},
	})
	s.Eventually(func() bool {
		ip, err := clusterIP()
		return err == nil && ip != ""
	}, 30*time.Second, time.Second, "service for %s never got a cluster IP", workloadName)

	// Removing the ports should reset the cluster IP.
	s.send(http.MethodPut, wlURL, map[string]any{
		"namespaceId": nsName,
		"scale":       1,
		"containers": []any{map[string]any{
			"name":  "one",
			"image": "nginx",
			"ports": []any{},
		}},
	})
	s.Eventually(func() bool {
		ip, err := clusterIP()
		return err == nil && ip == ""
	}, 30*time.Second, time.Second, "service for %s kept its cluster IP after the ports were removed", workloadName)
}

// TestWorkloadProbes asserts that liveness and readiness probes on a workload
// container are persisted and can be updated via the Norman project API.
func (s *WorkloadsTestSuite) TestWorkloadProbes() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	container := map[string]any{
		"name":  "one",
		"image": "nginx",
		"livenessProbe": map[string]any{
			"failureThreshold":    3,
			"initialDelaySeconds": 10,
			"periodSeconds":       2,
			"successThreshold":    1,
			"tcp":                 false,
			"timeoutSeconds":      2,
			"host":                "localhost",
			"path":                "/healthcheck",
			"port":                80,
			"scheme":              "HTTP",
		},
		"readinessProbe": map[string]any{
			"failureThreshold":    3,
			"initialDelaySeconds": 10,
			"periodSeconds":       2,
			"successThreshold":    1,
			"timeoutSeconds":      2,
			"tcp":                 true,
			"host":                "localhost",
			"port":                80,
		},
	}
	body := nginxWorkload(nsName)
	body["containers"] = []any{container}
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)

	probeHost := func(wl map[string]any, probe string) any {
		containers, _ := wl["containers"].([]any)
		if len(containers) == 0 {
			return nil
		}
		c, _ := containers[0].(map[string]any)
		p, _ := c[probe].(map[string]any)
		return p["host"]
	}
	s.Equal("localhost", probeHost(wl, "livenessProbe"))
	s.Equal("localhost", probeHost(wl, "readinessProbe"))

	container["livenessProbe"].(map[string]any)["host"] = "updatedhost"
	container["readinessProbe"].(map[string]any)["host"] = "updatedhost"
	updated := s.send(http.MethodPut, s.projectURL(project, "workloads/"+wl["id"].(string)), map[string]any{
		"namespaceId": nsName,
		"scale":       1,
		"containers":  []any{container},
	})
	s.Equal("updatedhost", probeHost(updated, "livenessProbe"))
	s.Equal("updatedhost", probeHost(updated, "readinessProbe"))
}

// TestWorkloadScheduling asserts that the scheduler field on a workload is
// persisted and can be updated via the Norman project API.
func (s *WorkloadsTestSuite) TestWorkloadScheduling() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	body := nginxWorkload(nsName)
	body["scheduling"] = map[string]any{"scheduler": "some-scheduler"}
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)

	scheduler := func(wl map[string]any) any {
		scheduling, _ := wl["scheduling"].(map[string]any)
		return scheduling["scheduler"]
	}
	s.Equal("some-scheduler", scheduler(wl))

	updated := s.send(http.MethodPut, s.projectURL(project, "workloads/"+wl["id"].(string)), map[string]any{
		"namespaceId": nsName,
		"scale":       1,
		"scheduling":  map[string]any{"scheduler": "test-scheduler"},
		"containers":  []any{map[string]any{"name": "one", "image": "nginx"}},
	})
	s.Equal("test-scheduler", scheduler(updated))
}

// TestStatefulSetWorkloadVolumeMountSubpath asserts that the Norman project API
// accepts a StatefulSet with a relative volumeMount subPath and rejects creates
// and updates where the subPath is absolute or contains "..".
func (s *WorkloadsTestSuite) TestStatefulSetWorkloadVolumeMountSubpath() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)
	workloadsURL := s.projectURL(project, "workloads")

	// statefulSet returns a workload body that the API routes to the statefulSet schema, whose
	// store is the one that validates subPath.
	statefulSet := func(subPath string) map[string]any {
		return map[string]any{
			"name":        namegen.AppendRandomString("wl-"),
			"namespaceId": nsName,
			"scale":       1,
			"containers": []any{map[string]any{
				"name":  "mystatefulset",
				"image": "ubuntu:xenial",
				"volumeMounts": []any{map[string]any{
					"name":      "vol1",
					"mountPath": "var/lib/mysql",
					"subPath":   subPath,
				}},
			}},
			"statefulSetConfig": map[string]any{
				"podManagementPolicy":  "OrderedReady",
				"revisionHistoryLimit": 10,
				"strategy":             "RollingUpdate",
				"type":                 "statefulSetConfig",
			},
			"volumes": []any{map[string]any{
				"name": "vol1",
				"persistentVolumeClaim": map[string]any{
					"persistentVolumeClaimId": nsName + ":myvolume",
					"readOnly":                false,
					"type":                    "persistentVolumeClaimVolumeSource",
				},
				"type": "volume",
			}},
		}
	}

	// The valid create is the positive precondition: the invalid requests below differ from it
	// only in subPath.
	wl := s.send(http.MethodPost, workloadsURL, statefulSet("mysql"))
	s.Require().Equal("statefulSet", wl["type"])
	wlURL := workloadsURL + "/" + wl["id"].(string)

	invalid := []struct {
		subPath string
		message string
	}{
		{subPath: "/mysql", message: "must be a relative path"},
		{subPath: "../mysql", message: "must not contain '..'"},
	}
	for _, tt := range invalid {
		status, body, err := do(s.httpClient, http.MethodPost, workloadsURL, statefulSet(tt.subPath))
		s.Require().NoError(err)
		s.Equalf(http.StatusUnprocessableEntity, status, "create with subPath %q: %s", tt.subPath, body)
		s.Containsf(string(body), tt.message, "create with subPath %q", tt.subPath)

		update := statefulSet(tt.subPath)
		delete(update, "name")
		status, body, err = do(s.httpClient, http.MethodPut, wlURL, update)
		s.Require().NoError(err)
		s.Equalf(http.StatusUnprocessableEntity, status, "update with subPath %q: %s", tt.subPath, body)
		s.Containsf(string(body), tt.message, "update with subPath %q", tt.subPath)
	}
}

// TestWorkloadRedeploy asserts that the redeploy action sets the
// cattle.io/timestamp annotation on the workload.
func (s *WorkloadsTestSuite) TestWorkloadRedeploy() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), nginxWorkload(nsName))
	annotations, _ := wl["annotations"].(map[string]any)
	s.Require().NotContains(annotations, "cattle.io/timestamp", "a new workload already has a redeploy timestamp")
	wlURL := s.projectURL(project, "workloads/"+wl["id"].(string))

	s.send(http.MethodPost, wlURL+"?action=redeploy", map[string]any{})

	s.Eventually(func() bool {
		status, body, err := do(s.httpClient, http.MethodGet, wlURL, nil)
		if err != nil || status != http.StatusOK {
			return false
		}
		var got struct {
			Annotations map[string]string `json:"annotations"`
		}
		return json.Unmarshal(body, &got) == nil && got.Annotations["cattle.io/timestamp"] != ""
	}, 30*time.Second, time.Second, "timed out waiting for cattle.io/timestamp annotation after redeploy")
}

// TestWorkloadActionReadOnly asserts that a read-only project member receives a
// 404 when attempting the rollback action, while a project-member succeeds.
func (s *WorkloadsTestSuite) TestWorkloadActionReadOnly() {
	client := s.newSubSession()
	project := s.createProject(client)
	nsName := s.createNamespace(client, project)

	// userHTTPClient creates a standard user bound to project with roleTemplateID and returns
	// an HTTP client that authenticates as them.
	userHTTPClient := func(prefix, roleTemplateID string) *http.Client {
		enabled := true
		pw := password.GenerateUserPassword("testpass-")
		user, err := users.CreateUserWithRole(client, &management.User{
			Username: namegen.AppendRandomString(prefix),
			Password: pw,
			Name:     prefix,
			Enabled:  &enabled,
		}, "user")
		s.Require().NoError(err)
		user.Password = pw

		_, err = client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
			UserID:         user.ID,
			RoleTemplateID: roleTemplateID,
			ProjectID:      project.ID,
		})
		s.Require().NoError(err)

		userClient, err := client.AsUser(user)
		s.Require().NoError(err)
		httpClient, err := rest.HTTPClientFor(userClient.WranglerContext.RESTConfig)
		s.Require().NoError(err)
		return httpClient
	}
	roHTTP := userHTTPClient("rouser-", "read-only")
	memberHTTP := userHTTPClient("memberuser-", "project-member")

	// Admin creates the workload, then updates it once to produce a revision that can be
	// rolled back.
	body := nginxWorkload(nsName)
	body["containers"] = []any{map[string]any{
		"name":  "foo",
		"image": "rancher/mirrored-library-nginx:1.21.1-alpine",
		"env":   []any{map[string]any{"name": "FOO_KEY", "value": "FOO_VALUE"}},
	}}
	wl := s.send(http.MethodPost, s.projectURL(project, "workloads"), body)
	wlURL := s.projectURL(project, "workloads/"+wl["id"].(string))
	s.send(http.MethodPut, wlURL, map[string]any{
		"namespaceId": nsName,
		"scale":       1,
		"containers": []any{map[string]any{
			"name":  "foo",
			"image": "rancher/mirrored-library-nginx:1.21.1-alpine",
			"env":   []any{map[string]any{"name": "BAR_KEY", "value": "BAR_VALUE"}},
		}},
	})

	var replicaSetID string
	s.Require().Eventually(func() bool {
		revisions, err := s.list(wlURL + "/revisions")
		if err != nil || len(revisions) == 0 {
			return false
		}
		replicaSetID, _ = revisions[0]["id"].(string)
		return replicaSetID != ""
	}, 30*time.Second, time.Second, "timed out waiting for workload revision to appear")

	rollbackURL := wlURL + "?action=rollback"
	rollbackBody := map[string]any{"replicaSetId": replicaSetID}

	// The rollback handler answers 404 when the caller can't update the workload, which is also
	// what an unpropagated binding gets. Wait until read-only can read the workload so the 404
	// below comes from the update check.
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		status, body, err := do(roHTTP, http.MethodGet, wlURL, nil)
		if assert.NoError(c, err) {
			assert.Equalf(c, http.StatusOK, status, "read-only GET workload: %s", body)
		}
	}, 2*time.Minute, 2*time.Second)

	status, respBody, err := do(roHTTP, http.MethodPost, rollbackURL, rollbackBody)
	s.Require().NoError(err)
	s.Equalf(http.StatusNotFound, status, "read-only rollback: %s", respBody)

	s.EventuallyWithT(func(c *assert.CollectT) {
		status, body, err := do(memberHTTP, http.MethodPost, rollbackURL, rollbackBody)
		if assert.NoError(c, err) {
			assert.Truef(c, status >= 200 && status < 300, "project-member rollback: status %d: %s", status, body)
		}
	}, 2*time.Minute, 2*time.Second)
}
