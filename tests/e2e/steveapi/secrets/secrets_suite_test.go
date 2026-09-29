package secrets

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	kubenamespaces "github.com/rancher/rancher/tests/e2e/actions/kubeapi/namespaces"
	"github.com/rancher/rancher/tests/e2e/actions/kubeapi/rbac"
	kubesecrets "github.com/rancher/rancher/tests/e2e/actions/kubeapi/secrets"
	"github.com/rancher/rancher/tests/e2e/actions/namespaces"
	"github.com/rancher/rancher/tests/e2e/actions/serviceaccounts"
	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/unstructured"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	"github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	labelKey          = "test-label"
	labelGTEKey       = "test-label-gte"
	steveAPITestLabel = "test.cattle.io/steveapi"
)

var (
	testID                     = namegenerator.RandStringLower(5)
	userEnabled                = true
	impersonationNamespace     = "cattle-impersonation-system"
	impersonationSABase        = "cattle-impersonation-"
	namespaceSecretManagerRole = rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-secret-manager",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"get",
					"list",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
			},
		},
	}
	mixedSecretUserRole = rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mixed-secret-user",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs: []string{
					"get",
					"list",
				},
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"secrets",
				},
				ResourceNames: []string{
					"test1",
					"test2",
				},
			},
		},
	}
	testUsers = map[string][]any{
		"user-a": {
			management.ProjectRoleTemplateBinding{
				RoleTemplateID: "project-owner",
				ProjectID:      "test-prj-1",
			},
		},
		"user-b": {
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "namespace-secret-manager",
					Namespace: "test-ns-1",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "namespace-secret-manager",
				},
			},
		},
		"user-c": {
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mixed-secret-user",
					Namespace: "test-ns-1",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "mixed-secret-user",
				},
			},
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mixed-secret-user",
					Namespace: "test-ns-2",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "mixed-secret-user",
				},
			},
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mixed-secret-user",
					Namespace: "test-ns-3",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "mixed-secret-user",
				},
			},
		},
		"user-d": {
			management.ProjectRoleTemplateBinding{
				RoleTemplateID: "project-owner",
				ProjectID:      "test-prj-1",
			},
			management.ProjectRoleTemplateBinding{
				RoleTemplateID: "project-owner",
				ProjectID:      "test-prj-2",
			},
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "namespace-secret-manager",
					Namespace: "test-ns-8",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "namespace-secret-manager",
				},
			},
			rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "namespace-secret-manager",
					Namespace: "test-ns-9",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: rbacv1.SchemeGroupVersion.Group,
					Kind:     "Role",
					Name:     "namespace-secret-manager",
				},
			},
		},
		"user-e": {
			management.ClusterRoleTemplateBinding{
				RoleTemplateID: "cluster-owner",
			},
		},
	}
	namespaceMap = map[string]string{
		"test-ns-1": "",
		"test-ns-2": "",
		"test-ns-3": "",
		"test-ns-4": "",
		"test-ns-5": "",
		"test-ns-6": "",
		"test-ns-7": "",
		"test-ns-8": "",
		"test-ns-9": "",
	}
	projectMap = map[string]*management.Project{
		"test-prj-1": nil,
		"test-prj-2": nil,
	}
	projectNamespaceMap = map[string]string{
		"test-ns-1": "test-prj-1",
		"test-ns-2": "test-prj-1",
		"test-ns-3": "test-prj-1",
		"test-ns-4": "test-prj-1",
		"test-ns-5": "test-prj-1",
		"test-ns-6": "test-prj-2",
		"test-ns-7": "test-prj-2",
		"test-ns-8": "",
		"test-ns-9": "",
	}
)

// SecretsTestSuite covers Steve's secrets API on the local cluster: listing with filters, sorting,
// pagination, summaries and project/namespace scoping as seen by users with different access, plus
// CRUD and resource links. SetupSuite builds the shared fixture (2 projects, 9 namespaces, labelled
// secrets and 5 users bound at project, cluster or namespace level); the tests live in the topic
// files in this package.
type SecretsTestSuite struct {
	suite.Suite
	client            *rancher.Client
	session           *session.Session
	clusterID         string // cluster under test; "local" is Rancher's own cluster, not a downstream
	userClients       map[string]*rancher.Client
	lastContinueToken string
	lastRevision      string
}

func (s *SecretsTestSuite) SetupSuite() {
	s.clusterID = "local"
	testSession := session.NewSession()
	s.session = testSession

	client, err := rancher.NewClient("", testSession)
	s.Require().NoError(err)
	s.client = client

	s.userClients = make(map[string]*rancher.Client)

	// create projects; the test cases refer to them by their projectMap key, not their display name
	for p := range projectMap {
		project, err := s.client.Management.Project.Create(&management.Project{
			ClusterID: s.clusterID,
			Name:      namegenerator.AppendRandomString(p),
		})
		s.Require().NoError(err)
		projectMap[p] = project
	}

	userID, err := users.GetUserIDByName(client, "admin")
	s.Require().NoError(err)

	impersonationSA := impersonationSABase + userID
	err = serviceaccounts.IsServiceAccountReady(client, s.clusterID, impersonationNamespace, impersonationSA)
	s.Require().NoError(err)

	// create project namespaces
	for n := range namespaceMap {
		if projectMap[projectNamespaceMap[n]] == nil {
			continue
		}
		name := namegenerator.AppendRandomString(n)
		_, err := namespaces.CreateNamespace(client, name, "", nil, nil, projectMap[projectNamespaceMap[n]])
		s.Require().NoError(err)
		namespaceMap[n] = name
	}
	// create non project namespaces. namespaces.CreateNamespace needs a project, so these go through
	// the dynamic client; Namespace("") is what makes the session track the create.
	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)
	for n := range namespaceMap {
		if projectMap[projectNamespaceMap[n]] != nil {
			continue
		}
		name := namegenerator.AppendRandomString(n)
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
		_, err := dynamicClient.Resource(kubenamespaces.NamespaceGroupVersionResource).Namespace("").Create(context.Background(), unstructured.MustToUnstructured(ns), metav1.CreateOptions{})
		s.Require().NoError(err)
		s.Require().Eventually(func() bool {
			ns, err := kubenamespaces.GetNamespaceByName(s.client, s.clusterID, name)
			return err == nil && ns != nil
		}, time.Minute, time.Second, "namespace %s never became readable", name)
		namespaceMap[n] = name
	}

	// create resources in all namespaces
	for name, n := range namespaceMap {
		for i := 1; i <= 5; i++ {
			if i > 2 && (projectNamespaceMap[name] == "test-prj-2" || projectNamespaceMap[name] == "") {
				break
			}
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test%d", i),
				},
			}
			// Test sorting secrets on metadata.fields[2] (# of secret keys)
			if name == "test-ns-1" {
				numKeys := 0
				if i == 1 {
					numKeys = 15
				} else if i == 2 {
					numKeys = 23
				} else if i == 3 {
					numKeys = 7
				}
				if numKeys > 0 {
					obj := map[string][]byte{}
					for j := 1; j <= numKeys; j++ {
						obj[fmt.Sprintf("k%d-%d", i, j)] = []byte("whatever")
					}
					secret.Data = obj
				}
			}
			labels := map[string]string{steveAPITestLabel: testID}
			if i == 2 {
				labels[labelKey] = "2"
			}
			if i >= 3 {
				labels[labelGTEKey] = "3"
			}
			secret.ObjectMeta.SetLabels(labels)
			if i == 4 && name == "test-ns-2" {
				// test4 in namespace test-ns-2 has this annotation
				annotations := map[string]string{"management.cattle.io/project-scoped-secret-copy": "spuds"}
				secret.ObjectMeta.SetAnnotations(annotations)
			}
			err := retryRequest(func() error {
				_, err := kubesecrets.CreateSecretForCluster(s.client, secret, s.clusterID, n)
				if apierrors.IsAlreadyExists(err) {
					return nil
				}
				return err
			})
			s.Require().NoError(err)
		}
	}

	// create test roles in all namespaces
	for _, n := range namespaceMap {
		role := namespaceSecretManagerRole
		role.Namespace = n
		err := retryRequest(func() error {
			_, err = rbac.CreateRole(s.client, s.clusterID, &role)
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return err
		})
		s.Require().NoError(err)
		role = mixedSecretUserRole
		role.Namespace = n
		err = retryRequest(func() error {
			_, err = rbac.CreateRole(s.client, s.clusterID, &role)
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return err
		})
		s.Require().NoError(err)
	}

	// create users and assign access
	for user, access := range testUsers {
		username := namegenerator.AppendRandomString(user)
		password := password.GenerateUserPassword("testpass")
		userObj := &management.User{
			Username: username,
			Password: password,
			Name:     username,
			Enabled:  &userEnabled,
		}
		userObj, err := s.client.Management.User.Create(userObj)
		s.Require().NoError(err)
		userObj.Password = password

		// a namespace RoleBinding only works for a user who can reach the cluster, so give those users
		// cluster-member once
		hasRoleBinding := slices.ContainsFunc(access, func(binding any) bool {
			_, ok := binding.(rbacv1.RoleBinding)
			return ok
		})
		if hasRoleBinding {
			_, err = client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
				ClusterID:       s.clusterID,
				UserPrincipalID: userObj.PrincipalIDs[0],
				RoleTemplateID:  "cluster-member",
			})
			s.Require().NoError(err)
		}

		// users either have access to a whole project or to select namespaces or resources in a project
		for _, binding := range access {
			switch b := binding.(type) {
			case management.ClusterRoleTemplateBinding:
				_, err = client.Management.ClusterRoleTemplateBinding.Create(&management.ClusterRoleTemplateBinding{
					ClusterID:       s.clusterID,
					UserPrincipalID: userObj.PrincipalIDs[0],
					RoleTemplateID:  b.RoleTemplateID,
				})
				s.Require().NoError(err)
			case management.ProjectRoleTemplateBinding:
				_, err = client.Management.ProjectRoleTemplateBinding.Create(&management.ProjectRoleTemplateBinding{
					ProjectID:       projectMap[b.ProjectID].ID,
					UserPrincipalID: userObj.PrincipalIDs[0],
					RoleTemplateID:  b.RoleTemplateID,
				})
				s.Require().NoError(err)
			case rbacv1.RoleBinding:
				subject := rbacv1.Subject{
					Kind: "User",
					Name: userObj.ID,
				}
				err := retryRequest(func() error {
					_, err = rbac.CreateRoleBinding(s.client, s.clusterID, namegenerator.AppendRandomString(b.Name), namespaceMap[b.Namespace], b.RoleRef.Name, subject)
					if apierrors.IsAlreadyExists(err) {
						return nil
					}
					return err
				})
				s.Require().NoError(err)
			}
		}

		userClient, err := s.client.AsUser(userObj)
		s.Require().NoError(err)
		s.Require().Eventually(func() bool {
			_, err := userClient.Management.Cluster.ByID(s.clusterID)
			return err == nil
		}, 2*time.Minute, 2*time.Second, "user %s never gained cluster access", user)
		s.userClients[user] = userClient
	}
}

func (s *SecretsTestSuite) TearDownSuite() {
	s.session.Cleanup()
}

// newSubSession returns a client whose creates are cleaned up when the calling test ends.
func (s *SecretsTestSuite) newSubSession() *rancher.Client {
	subSession := s.session.NewSession()
	client, err := s.client.WithSession(subSession)
	s.Require().NoError(err)
	s.T().Cleanup(subSession.Cleanup)
	return client
}

// retryRequest retries fn while it fails with a "tunnel disconnect" error.
func retryRequest(fn func() error) error {
	retriable := func(err error) bool { return strings.Contains(err.Error(), "tunnel disconnect") }
	return retry.OnError(retry.DefaultBackoff, retriable, fn)
}

func TestSecretsTestSuite(t *testing.T) {
	suite.Run(t, new(SecretsTestSuite))
}
