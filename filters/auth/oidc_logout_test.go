package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/auth"
	"github.com/zalando/skipper/proxy/proxytest"
	"github.com/zalando/skipper/net/dnstest"
)

const (
	testOIDCClientID     = "test-client"
	testOIDCClientSecret = "test-secret"
	testOIDCAccessToken  = "test-access-token"
	testOIDCRefreshToken = "test-refresh-token"
	testOIDCCookieName   = "test-oidc-cookie"
)

type testOIDCTokenContainer struct {
	OAuth2Token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	} `json:"oauth2token"`
}

func newOIDCLogoutTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/revoke" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		expectedCredentials := base64.StdEncoding.EncodeToString([]byte(testOIDCClientID + ":" + testOIDCClientSecret))
		expectedAuthorization := "Basic " + expectedCredentials
		if expectedAuthorization != r.Header.Get("Authorization") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		token := r.Form.Get("token")

		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if token == testOIDCAccessToken || token == testOIDCRefreshToken {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func createOIDCCookie(t *testing.T, accessToken, refreshToken string) *http.Cookie {
	t.Helper()
	container := testOIDCTokenContainer{}
	container.OAuth2Token.AccessToken = accessToken
	container.OAuth2Token.RefreshToken = refreshToken

	cookieValue, err := json.Marshal(container)
	if err != nil {
		t.Fatalf("Failed to marshal token container: %v", err)
	}

	return &http.Cookie{
		Name:  testOIDCCookieName,
		Value: base64.StdEncoding.EncodeToString(cookieValue),
	}
}

func TestOIDCLogout(t *testing.T) {
	const (
		applicationDomain = "foo.skipper.test"
		redirectURL       = "https://example.com/post-logout"
	)

	dnstest.LoopbackNames(t, applicationDomain)

	provider := newOIDCLogoutTestServer()
	defer provider.Close()

	spec := auth.NewOidcLogout()
	fr := make(filters.Registry)
	fr.Register(spec)

	routes := eskip.MustParse(
		`Path("/logout") -> oidcLogout("` + testOIDCClientID + `", "` + testOIDCClientSecret + `", "` + provider.URL + `/revoke", "` + redirectURL + `", "` + testOIDCCookieName + `") -> <shunt>`,
	)

	proxy := proxytest.New(fr, routes...)
	defer proxy.Close()

	t.Run("logout with both tokens", func(t *testing.T) {
		cookie := createOIDCCookie(t, testOIDCAccessToken, testOIDCRefreshToken)
		req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()

		if rsp.StatusCode != http.StatusFound {
			t.Errorf("unexpected status code: %d", rsp.StatusCode)
		}

		location := rsp.Header.Get("Location")
		if location != redirectURL {
			t.Errorf("unexpected redirect URL: %s", location)
		}

		checkDeletedCookie(t, rsp, testOIDCCookieName, "")
	})

	t.Run("logout with only access token", func(t *testing.T) {
		cookie := createOIDCCookie(t, testOIDCAccessToken, "")
		req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()

		if rsp.StatusCode != http.StatusFound {
			t.Errorf("unexpected status code: %d", rsp.StatusCode)
		}

		checkDeletedCookie(t, rsp, testOIDCCookieName, "")
	})

	t.Run("logout with no tokens", func(t *testing.T) {
		cookie := createOIDCCookie(t, "", "")
		req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()

		if rsp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unexpected status code: %d", rsp.StatusCode)
		}
	})

	t.Run("logout with no cookie", func(t *testing.T) {
		req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
		if err != nil {
			t.Fatal(err)
		}

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()

		if rsp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unexpected status code: %d", rsp.StatusCode)
		}
	})

	t.Run("logout with invalid tokens", func(t *testing.T) {
		cookie := createOIDCCookie(t, "invalid-access-token", "invalid-refresh-token")
		req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)

		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer rsp.Body.Close()

		if rsp.StatusCode != http.StatusInternalServerError {
			t.Errorf("unexpected status code: %d", rsp.StatusCode)
		}
	})
}

func TestOIDCLogoutInvalidConfig(t *testing.T) {
	spec := auth.NewOidcLogout()
	fr := make(filters.Registry)
	fr.Register(spec)

	routes := eskip.MustParse(
		`Path("/logout") -> oidcLogout("client", "secret", "invalid-url", "https://example.com", "cookie-name") -> <shunt>`,
	)

	proxy := proxytest.New(fr, routes...)
	defer proxy.Close()

	req, err := http.NewRequest("GET", proxy.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusInternalServerError {
		t.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
}