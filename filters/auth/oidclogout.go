package auth

import (
	"net/http"
	"strings"

	"github.com/zalando/skipper/filters"
	log "github.com/sirupsen/logrus"
)

const (
	OidcLogoutName = "oidcLogout"
)

type (
	oidcLogoutSpec struct{}

	oidcLogoutFilter struct {
		redirectURL string
	}
)

// NewOidcLogout creates a new oidcLogout filter specification
func NewOidcLogout() filters.Spec {
	return &oidcLogoutSpec{}
}

func (*oidcLogoutSpec) Name() string { return OidcLogoutName }

func (s *oidcLogoutSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) != 1 {
		return nil, filters.ErrInvalidFilterParameters
	}

	redirectURL, ok := args[0].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &oidcLogoutFilter{
		redirectURL: redirectURL,
	}, nil
}

func (f *oidcLogoutFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	// Clear all OIDC cookies
	var clearedCookies []string
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, oauthOidcCookieName) {
			deleteCookie := &http.Cookie{
				Name:     cookie.Name,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
			}
			clearedCookies = append(clearedCookies, deleteCookie.String())
		}
	}

	// Redirect to the specified URL
	rsp := &http.Response{
		StatusCode: http.StatusFound,
		Header: http.Header{
			"Location":   []string{f.redirectURL},
			"Set-Cookie": clearedCookies,
		},
	}

	ctx.Serve(rsp)
}

func (f *oidcLogoutFilter) Response(ctx filters.FilterContext) {
	// No action needed in the response phase
}