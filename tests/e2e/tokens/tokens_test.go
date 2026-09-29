package tokens

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rancher/norman/types"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	stevev1 "github.com/rancher/shepherd/clients/rancher/v1"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// TestCurrentToken verifies that listing tokens returns exactly one token
// marked as current: the token the client authenticates with, owned by the
// client's user.
func (s *TokensTestSuite) TestCurrentToken() {
	client := s.newSubSession()

	// A bearer token is "<token name>:<secret>".
	tokenName, _, found := strings.Cut(client.WranglerContext.RESTConfig.BearerToken, ":")
	s.Require().True(found, "bearer token is not in <name>:<secret> form")

	me, err := client.Management.User.List(&types.ListOpts{Filters: map[string]any{"me": true}})
	s.Require().NoError(err)
	s.Require().Len(me.Data, 1, "expected exactly one user for me=true")

	tokens, err := client.Management.Token.ListAll(nil)
	s.Require().NoError(err)
	var current []management.Token
	for _, t := range tokens.Data {
		if t.Current {
			current = append(current, t)
		}
	}
	s.Require().Len(current, 1, "expected exactly one current token")
	s.Equal(tokenName, current[0].ID)
	s.Equal(me.Data[0].ID, current[0].UserID)
}

// TestWebsocket verifies that requests with websocket-like upgrade headers and a
// foreign Origin are rejected with 403 Forbidden.
func (s *TokensTestSuite) TestWebsocket() {
	client := s.newSubSession()

	httpClient, err := rest.HTTPClientFor(client.WranglerContext.RESTConfig)
	s.Require().NoError(err)
	getClusters := func(headers map[string]string) int {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/v3/clusters", client.WranglerContext.RESTConfig.Host), nil)
		s.Require().NoError(err)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		s.Require().NoError(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// The same request without the websocket headers succeeds, so the 403 below is caused by
	// those headers and not by the URL or credentials.
	s.Require().Equal(http.StatusOK, getClusters(nil))

	s.Equal(http.StatusForbidden, getClusters(map[string]string{
		"Connection": "upgrade",
		"Upgrade":    "websocket",
		"Origin":     "badStuff",
		"User-Agent": "Mozilla",
	}))
}

// TestAPITokenTTL verifies that a token created with ttl=0 is capped to the
// max TTL configured in the auth-token-max-ttl-minutes setting.
func (s *TokensTestSuite) TestAPITokenTTL() {
	client := s.newSubSession()

	maxTTLSetting, err := client.Management.Setting.ByID("auth-token-max-ttl-minutes")
	s.Require().NoError(err)
	maxTTLMins, err := strconv.ParseInt(maxTTLSetting.Value, 10, 64)
	s.Require().NoError(err)

	created, err := client.Management.Token.Create(&management.Token{
		TTLMillis: 0,
	})
	s.Require().NoError(err)

	// TTLMillis is in milliseconds; convert to minutes.
	tokenTTLMins := created.TTLMillis / 60000
	s.Equal(maxTTLMins, tokenTTLMins)
}

// TestKubeconfigTokenTTL verifies that logging in with responseType=kubeconfig,
// through both the /v3-public and /v1-public endpoints, returns a new token with
// the TTL from the kubeconfig-default-token-ttl-minutes setting, which works
// until it expires.
func (s *TokensTestSuite) TestKubeconfigTokenTTL() {
	client := s.newSubSession()

	password := client.RancherConfig.AdminPassword
	if password == "" {
		s.T().Skip("rancher.adminPassword is not set in the test config; it's needed to log in as admin")
	}

	// Set a short TTL (0.1 min = 6s): long enough to prove each token works before it expires.
	// Read and write the setting through Steve, since Norman reports the default in place of an
	// empty stored value and restoring that would pin the default.
	const ttlSetting = "kubeconfig-default-token-ttl-minutes"
	settings := client.Steve.SteveType("management.cattle.io.setting")
	setTTL := func(value string) (string, error) {
		existing, err := settings.ByID(ttlSetting)
		if err != nil {
			return "", err
		}
		var setting v3.Setting
		if err := stevev1.ConvertToK8sType(existing.JSONResp, &setting); err != nil {
			return "", err
		}
		previous := setting.Value
		setting.Value = value
		_, err = settings.Update(existing, setting)
		return previous, err
	}
	origTTL, err := setTTL("0.1")
	s.Require().NoError(err)
	t := s.T()
	t.Cleanup(func() {
		_, err := setTTL(origTTL)
		assert.NoError(t, err, "failed to restore setting %s to %q", ttlSetting, origTTL)
	})

	// The login endpoints are public, so use an unauthenticated client with the configured TLS settings.
	httpClient, err := rest.HTTPClientFor(rest.AnonymousClientConfig(client.WranglerContext.RESTConfig))
	s.Require().NoError(err)
	host := client.WranglerContext.RESTConfig.Host

	login := func(url string, body map[string]any) map[string]any {
		reqBody, err := json.Marshal(body)
		s.Require().NoError(err)
		resp, err := httpClient.Post(url, "application/json", bytes.NewReader(reqBody))
		s.Require().NoError(err)
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		s.Require().NoError(err)
		s.Require().Equalf(http.StatusCreated, resp.StatusCode, "login failed: %s", respBody)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(respBody, &result))
		return result
	}
	getV3 := func(bearerToken string) (int, error) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/v3", host), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	endpoints := []struct {
		name string
		url  string
		body map[string]any
	}{
		{
			name: "v3-public",
			url:  fmt.Sprintf("https://%s/v3-public/localProviders/local?action=login", host),
			body: map[string]any{"username": "admin", "password": password, "responseType": "kubeconfig"},
		},
		{
			name: "v1-public",
			url:  fmt.Sprintf("https://%s/v1-public/login", host),
			body: map[string]any{"type": "localProvider", "username": "admin", "password": password, "responseType": "kubeconfig"},
		},
	}
	for _, e := range endpoints {
		s.Run(e.name, func() {
			result := login(e.url, e.body)

			// Each kubeconfig login creates a new Token that the session doesn't know about.
			tokenName, _ := result["id"].(string)
			s.Require().NotEmpty(tokenName, "login response has no id")
			t := s.T()
			t.Cleanup(func() {
				err := client.WranglerContext.Mgmt.Token().Delete(tokenName, &metav1.DeleteOptions{})
				if !apierrors.IsNotFound(err) {
					assert.NoError(t, err, "failed to delete token %s", tokenName)
				}
			})

			bearerToken, _ := result["token"].(string)
			s.True(strings.HasPrefix(bearerToken, tokenName+":"), "token %q should be <id>:<secret>", bearerToken)
			s.NotEmpty(result["expiresAt"])
			s.Equal("token", result["type"])
			s.Equal("token", result["baseType"])

			token, err := client.WranglerContext.Mgmt.Token().Get(tokenName, metav1.GetOptions{})
			s.Require().NoError(err)
			s.Equal(int64(6000), token.TTLMillis, "token TTL should come from %s", ttlSetting)

			// The token works now, and is rejected once its TTL has passed.
			status, err := getV3(bearerToken)
			s.Require().NoError(err)
			s.Require().Equal(http.StatusOK, status, "new token should authenticate before it expires")
			s.EventuallyWithT(func(c *assert.CollectT) {
				status, err := getV3(bearerToken)
				assert.NoError(c, err)
				assert.Equal(c, http.StatusUnauthorized, status)
			}, 30*time.Second, 500*time.Millisecond, "token should be rejected after it expires")
		})
	}
}
