package auth

import (
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/filters"
)

const (
	OidcLogoutName = "oauthOidcLogout"
)

type (
	oidcLogoutSpec struct{}

	oidcLogoutFilter struct {
		cookieName   string
		redirectPath string
	}
)

// NewOidcLogout creates a new oidc logout filter spec
func NewOidcLogout() filters.Spec {
	return &oidcLogoutSpec{}
}

func (s *oidcLogoutSpec) Name() string {
	return OidcLogoutName
}

// CreateFilter creates an oidc logout filter
func (s *oidcLogoutSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) != 2 {
		return nil, filters.ErrInvalidFilterParameters
	}

	cookieName, ok := args[0].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	redirectPath, ok := args[1].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &oidcLogoutFilter{
		cookieName:   cookieName,
		redirectPath: redirectPath,
	}, nil
}

func (f *oidcLogoutFilter) Request(ctx filters.FilterContext) {
	req := ctx.Request()

	// Remove the OIDC cookie
	cookie := &http.Cookie{
		Name:     f.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(ctx.ResponseWriter(), cookie)

	// Redirect to the specified path
	redirectURL, err := url.Parse(f.redirectPath)
	if err != nil {
		log.Errorf("Failed to parse redirect URL: %v", err)
		ctx.Serve(&http.Response{StatusCode: http.StatusInternalServerError})
		return
	}

	if redirectURL.IsAbs() {
		ctx.Serve(&http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {redirectURL.String()}},
		})
	} else {
		// If it's a relative path, use the current request's scheme and host
		redirectURL.Scheme = req.URL.Scheme
		redirectURL.Host = req.Host
		ctx.Serve(&http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": {redirectURL.String()}},
		})
	}
}

func (f *oidcLogoutFilter) Response(ctx filters.FilterContext) {}