package uiplugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"time"

	"github.com/rancher/rancher/pkg/controllers/dashboard/plugin"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// uiPluginsGet sends a GET for path under Rancher's /v1/uiplugins endpoint, as the admin user if authenticated.
func (w *UIPluginTestSuite) uiPluginsGet(path string, authenticated bool) (*http.Response, error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/v1/uiplugins%s", w.client.RancherConfig.Host, path), nil)
	if err != nil {
		return nil, err
	}
	if authenticated {
		req.AddCookie(&http.Cookie{
			Name:  "R_SESS",
			Value: w.client.RancherConfig.AdminToken,
		})
	}
	return client.Do(req)
}

// setHomepageEndpoints points the homepage UIPlugin at the given endpoints and registers a cleanup
// that restores the originals and waits for the plugin to be ready again, so later tests see it unchanged.
func (w *UIPluginTestSuite) setHomepageEndpoints(endpoint, compressedEndpoint string) {
	ctx := context.Background()
	uiplugin, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(ctx, "homepage", metav1.GetOptions{})
	w.Require().NoError(err)
	origEndpoint, origCompressedEndpoint := uiplugin.Spec.Plugin.Endpoint, uiplugin.Spec.Plugin.CompressedEndpoint

	w.Require().NoError(w.updateHomepageEndpoints(ctx, endpoint, compressedEndpoint))
	t := w.T()
	t.Cleanup(func() {
		assert.NoError(t, w.updateHomepageEndpoints(context.Background(), origEndpoint, origCompressedEndpoint), "failed to restore the homepage UIPlugin endpoints")
		assert.Eventually(t, func() bool {
			p, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(context.Background(), "homepage", metav1.GetOptions{})
			return err == nil && p.Status.ObservedGeneration == p.Generation && p.Status.Ready
		}, 2*time.Minute, PollInterval, "waiting for the homepage UIPlugin to be ready after restoring its endpoints")
	})
}

func (w *UIPluginTestSuite) updateHomepageEndpoints(ctx context.Context, endpoint, compressedEndpoint string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		uiplugin, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(ctx, "homepage", metav1.GetOptions{})
		if err != nil {
			return err
		}
		uiplugin.Spec.Plugin.Endpoint = endpoint
		uiplugin.Spec.Plugin.CompressedEndpoint = compressedEndpoint
		_, err = w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Update(ctx, uiplugin, metav1.UpdateOptions{})
		return err
	})
}

// TestGetIndexAuthenticated Tests if all extensions are returned in the index if the user is authenticated
func (w *UIPluginTestSuite) TestGetIndexAuthenticated() {
	res, err := w.uiPluginsGet("", true)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusOK, res.StatusCode)

	var index plugin.SafeIndex
	w.Require().NoError(json.NewDecoder(res.Body).Decode(&index))
	for _, name := range []string{"uk-locale", "clock", "top-level-product", "homepage"} {
		w.Assert().Contains(index.Entries, name)
	}
}

// TestGetIndexUnauthenticated Tests if the unauthenticated extensions (and only them) are present
// in the anonymous index and that it is returned if the user is not authenticated
func (w *UIPluginTestSuite) TestGetIndexUnauthenticated() {
	res, err := w.uiPluginsGet("", false)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusOK, res.StatusCode)

	var index plugin.SafeIndex
	w.Require().NoError(json.NewDecoder(res.Body).Decode(&index))
	w.Assert().Contains(index.Entries, "uk-locale")
	for _, name := range []string{"clock", "top-level-product", "homepage"} {
		w.Assert().NotContains(index.Entries, name, "%s requires authentication but is in the anonymous index", name)
	}
}

// TestCorrectContentType Tests that the requests returns the correct Content-Type header
func (w *UIPluginTestSuite) TestCorrectContentType() {
	file := "/top-level-product-0.1.0.umd.min.1.js"
	res, err := w.uiPluginsGet("/top-level-product/0.1.0/plugin"+file, true)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusOK, res.StatusCode)
	w.Require().Equal(mime.TypeByExtension(filepath.Ext(file)), res.Header.Get("Content-Type"))
}

// TestGetSingleExtensionAuthenticated Tests that the requests succeeds if the user is authenticated
func (w *UIPluginTestSuite) TestGetSingleExtensionAuthenticated() {
	res, err := w.uiPluginsGet("/clock/0.2.0/plugin/clock-0.2.0.umd.min.js", true)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusOK, res.StatusCode)
}

// TestGetSingleExtensionUnauthenticated Tests that the requests succeeds if
// the user is unauthenticated when the requested extension does not require authentication
func (w *UIPluginTestSuite) TestGetSingleExtensionUnauthenticated() {
	res, err := w.uiPluginsGet("/uk-locale/0.1.1/plugin/uk-locale-0.1.1.umd.min.js", false)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusOK, res.StatusCode)
}

// TestGetSingleUnauthorizedExtension Tests that the requests fails and returns 404 if the
// extension requires authentication and the user is not authenticated
func (w *UIPluginTestSuite) TestGetSingleUnauthorizedExtension() {
	res, err := w.uiPluginsGet("/clock/0.2.0/plugin/clock-0.2.0.umd.min.js", false)
	w.Require().NoError(err)
	defer res.Body.Close()
	w.Require().Equal(http.StatusNotFound, res.StatusCode)
}

func (w *UIPluginTestSuite) TestCompressedEndpoint() {
	ts, err := StartUIPluginTgzServer()
	w.Require().NoError(err)
	w.T().Cleanup(ts.Close)
	w.setHomepageEndpoints("", ts.URL)

	res, err := w.uiPluginsGet("/homepage/0.4.1/plugin/main.js", true)
	w.Require().NoError(err)
	res.Body.Close()
	w.Require().True(res.StatusCode == http.StatusOK || res.StatusCode == http.StatusTooEarly, "unexpected status %d", res.StatusCode)

	w.Require().Eventually(func() bool {
		uiplugin, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(context.Background(), "homepage", metav1.GetOptions{})
		return err == nil && uiplugin.Status.ObservedGeneration == uiplugin.Generation && uiplugin.Status.Ready
	}, 6*time.Minute, PollInterval, "waiting for the homepage UIPlugin to be ready from its compressed endpoint")
}

func (w *UIPluginTestSuite) TestExponentialBackoff() {
	ts, err := StartUIPluginServerWithBackoff()
	w.Require().NoError(err)
	w.T().Cleanup(ts.Close)
	w.setHomepageEndpoints(ts.URL, "")

	// The server fails its first two requests, so the controller should retry twice, staying
	// not ready while it retries, then become ready with its retry count reset to 0.
	maxRetry := 0
	readyWhileRetrying := false
	w.Require().Eventually(func() bool {
		uiplugin, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(context.Background(), "homepage", metav1.GetOptions{})
		if err != nil || uiplugin.Status.ObservedGeneration != uiplugin.Generation {
			return false
		}
		if uiplugin.Status.RetryNumber > 0 {
			maxRetry = max(maxRetry, uiplugin.Status.RetryNumber)
			readyWhileRetrying = readyWhileRetrying || uiplugin.Status.Ready
			return false
		}
		return maxRetry > 0 && uiplugin.Status.Ready
	}, 6*time.Minute, 200*time.Millisecond, "waiting for the homepage UIPlugin to retry and then become ready")
	w.Require().Equal(2, maxRetry)
	w.Require().False(readyWhileRetrying, "homepage UIPlugin was ready while still retrying")
}

func (w *UIPluginTestSuite) TestUnreachableCompressedEndpoint() {
	ts, err := StartUIPluginServer()
	w.Require().NoError(err)
	w.T().Cleanup(ts.Close)
	w.setHomepageEndpoints(ts.URL, "https://some-unreachable.location.tgz")

	w.Require().Eventually(func() bool {
		uiplugin, err := w.catalogClient.UIPlugins(namespace.UIPluginNamespace).Get(context.Background(), "homepage", metav1.GetOptions{})
		return err == nil && uiplugin.Status.ObservedGeneration == uiplugin.Generation && uiplugin.Status.Ready
	}, 6*time.Minute, PollInterval, "waiting for the homepage UIPlugin to fall back to its uncompressed endpoint and be ready")
}

func StartUIPluginTgzServer() (*httptest.Server, error) {
	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "../../../testdata/uiext/0.4.1.tgz")
	})

	ts := httptest.NewUnstartedServer(customHandler)

	ip := getOutboundIP()
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

func StartUIPluginServer() (*httptest.Server, error) {
	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../../../testdata/uiext")).ServeHTTP(w, r)
	})

	ts := httptest.NewUnstartedServer(customHandler)

	ip := getOutboundIP()
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

func StartUIPluginServerWithBackoff() (*httptest.Server, error) {
	reqCount := 1

	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reqCount <= 2 {
			reqCount++
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		} else {
			http.FileServer(http.Dir("../../../testdata/uiext")).ServeHTTP(w, r)
		}
	})

	ts := httptest.NewUnstartedServer(customHandler)

	ip := getOutboundIP()
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
	if err != nil {
		return nil, err
	}
	ts.Listener = listener
	ts.Start()

	return ts, nil
}

// Get preferred outbound ip of this machine
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		logrus.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
