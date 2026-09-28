package authconfigs

import (
	"context"
	"errors"
	"net/http"
	"time"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// authProviderCleanupAnnotation is set to "unlocked" by the auth config controller once it has seen
// a provider enabled; only then does disabling the provider reset its config and delete its secrets.
const authProviderCleanupAnnotation = "management.cattle.io/auth-provider-cleanup"

// TestAuthConfigsExistAndCannotBeDeleted verifies that the expected set of auth
// config types are returned by the API, and that attempting to delete any of
// them returns 405 Method Not Allowed.
func (s *AuthConfigTestSuite) TestAuthConfigsExistAndCannotBeDeleted() {
	client := s.newSubSession()

	configs, err := client.Management.AuthConfig.List(nil)
	s.Require().NoError(err)

	expectedTypes := map[string]bool{
		"activeDirectoryConfig": false,
		"adfsConfig":            false,
		"azureADConfig":         false,
		"cognitoConfig":         false,
		"freeIpaConfig":         false,
		"genericOIDCConfig":     false,
		"genericSAMLConfig":     false,
		"githubAppConfig":       false,
		"githubConfig":          false,
		"googleOauthConfig":     false,
		"keyCloakConfig":        false,
		"keyCloakOIDCConfig":    false,
		"localConfig":           false,
		"oidcConfig":            false,
		"oktaConfig":            false,
		"openLdapConfig":        false,
		"pingConfig":            false,
		"shibbolethConfig":      false,
	}

	for _, config := range configs.Data {
		if _, ok := expectedTypes[config.Type]; ok {
			expectedTypes[config.Type] = true
		} else {
			s.Failf("unexpected auth config type %q found in API response", config.Type)
		}
	}

	// Assert every expected auth config type was found.
	for configType, found := range expectedTypes {
		s.Require().True(found, "expected auth config type %q not found in API response", configType)
	}

	// Verify that deleting any auth config returns 405.
	for _, config := range configs.Data {
		c := config
		err := client.Management.AuthConfig.Delete(&c)
		s.Require().Error(err, "expected error deleting auth config %s", c.Type)

		var apiErr *clientbase.APIError
		s.Require().True(errors.As(err, &apiErr), "expected APIError for %s, got: %v", c.Type, err)
		s.Require().Equal(http.StatusMethodNotAllowed, apiErr.StatusCode, "expected 405 for %s", c.Type)
	}
}

// TestAuthConfigActions verifies that each auth config type exposes the
// expected set of actions (testAndApply, configureTest, testAndEnable).
func (s *AuthConfigTestSuite) TestAuthConfigActions() {
	client := s.newSubSession()

	configs, err := client.Management.AuthConfig.List(nil)
	s.Require().NoError(err)

	configMap := map[string]management.AuthConfig{}
	for _, config := range configs.Data {
		configMap[config.Type] = config
	}

	// Configs that should have testAndApply action.
	testAndApplyConfigs := []string{
		"activeDirectoryConfig",
		"azureADConfig",
		"cognitoConfig",
		"freeIpaConfig",
		"genericOIDCConfig",
		"githubAppConfig",
		"githubConfig",
		"googleOauthConfig",
		"oidcConfig",
		"openLdapConfig",
	}
	for _, configType := range testAndApplyConfigs {
		c, ok := configMap[configType]
		s.Require().True(ok, "auth config %q not found", configType)
		_, hasAction := c.Actions["testAndApply"]
		s.Require().True(hasAction, "%s should have testAndApply action", configType)
	}

	// Configs that should have configureTest action.
	configureTestConfigs := []string{
		"azureADConfig",
		"cognitoConfig",
		"genericOIDCConfig",
		"githubAppConfig",
		"githubConfig",
		"googleOauthConfig",
		"oidcConfig",
	}
	for _, configType := range configureTestConfigs {
		c, ok := configMap[configType]
		s.Require().True(ok, "auth config %q not found", configType)
		_, hasAction := c.Actions["configureTest"]
		s.Require().True(hasAction, "%s should have configureTest action", configType)
	}

	// Configs that should have testAndEnable action.
	testAndEnableConfigs := []string{
		"adfsConfig",
		"genericSAMLConfig",
		"keyCloakConfig",
		"oktaConfig",
		"pingConfig",
		"shibbolethConfig",
	}
	for _, configType := range testAndEnableConfigs {
		c, ok := configMap[configType]
		s.Require().True(ok, "auth config %q not found", configType)
		_, hasAction := c.Actions["testAndEnable"]
		s.Require().True(hasAction, "%s should have testAndEnable action", configType)
	}
}

// TestAuthConfigSecrets verifies that updating a SAML auth config's spKey
// causes the corresponding secret to be created in the cattle-global-data
// namespace, and that secrets for other unconfigured SAML providers are not
// created.
func (s *AuthConfigTestSuite) TestAuthConfigSecrets() {
	client := s.newSubSession()

	pingConfig, err := client.Management.AuthConfig.ByID("ping")
	s.Require().NoError(err)
	if pingConfig.Enabled {
		s.T().Skip("ping auth is enabled in this environment; this test would overwrite its config and then reset it")
	}

	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)
	secrets := dynamicClient.Resource(corev1.SchemeGroupVersion.WithResource("secrets")).Namespace("cattle-global-data")

	// Enable the config and set the spKey — the API stores the spKey in a
	// secret named "pingconfig-spkey" in the cattle-global-data namespace.
	_, err = client.Management.AuthConfig.Update(pingConfig, map[string]any{
		"spKey":   "-----BEGIN PRIVATE KEY-----",
		"enabled": true,
	})
	s.Require().NoError(err)

	// The session can't undo an update, and the secret is created indirectly. Disabling an
	// unlocked provider makes Rancher reset its config (clearing spKey) and delete its secrets.
	t := s.T()
	s.T().Cleanup(func() {
		current, err := client.Management.AuthConfig.ByID("ping")
		if !assert.NoError(t, err) {
			return
		}
		_, err = client.Management.AuthConfig.Update(current, map[string]any{
			"enabled": false,
		})
		assert.NoError(t, err)
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			_, err := secrets.Get(context.TODO(), "pingconfig-spkey", metav1.GetOptions{})
			assert.Truef(c, apierrors.IsNotFound(err), "expected not found, got: %v", err)
		}, 2*time.Minute, 2*time.Second, "waiting for Rancher to delete the pingconfig-spkey secret")
	})

	// Rancher only resets a provider on disable once its controller has seen it enabled and unlocked
	// it. Disabling before then leaves the spKey and its secret behind, so wait for the unlock.
	s.Require().EventuallyWithT(func(c *assert.CollectT) {
		current, err := client.Management.AuthConfig.ByID("ping")
		if !assert.NoError(c, err) {
			return
		}
		assert.Equal(c, "unlocked", current.Annotations[authProviderCleanupAnnotation])
	}, 2*time.Minute, 2*time.Second, "waiting for the ping auth config to be unlocked for cleanup")

	_, err = secrets.Get(context.TODO(), "pingconfig-spkey", metav1.GetOptions{})
	s.Require().NoError(err, "expected the pingconfig-spkey secret to exist")

	// Verify that secrets for other unconfigured SAML providers are NOT created.
	notExpected := []string{"adfsconfig-spkey", "oktaconfig-spkey", "keycloakconfig-spkey"}
	for _, name := range notExpected {
		_, err := secrets.Get(context.TODO(), name, metav1.GetOptions{})
		s.Require().Truef(apierrors.IsNotFound(err), "expected secret %s to not exist, got: %v", name, err)
	}
}
