package auth

import (
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zalando/skipper/filters"
	log "github.com/sirupsen/logrus"
)

const (
	OidcLogoutName = "oidcLogout"

	logoutParamClientID int = iota
	logoutParamClientSecret
	logoutParamRevokeURL
	logoutParamRedirectURL
	logoutParamCookieName
)

type (
	oidcLogoutSpec struct{}

	oidcLogoutFilter struct {
		clientID     string
		clientSecret string
		revokeURL    string
		redirectURL  string
		cookieName   string
	}
)

func NewOidcLogout() filters.Spec {
	return &oidcLogoutSpec{}
}

func (*oidcLogoutSpec) Name() string {
	return OidcLogoutName
}

func (s *oidcLogoutSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) != 5 {
		return nil, filters.ErrInvalidFilterParameters
	}

	clientID, ok := args[logoutParamClientID].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	clientSecret, ok := args[logoutParamClientSecret].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	revokeURL, ok := args[logoutParamRevokeURL].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	redirectURL, ok := args[logoutParamRedirectURL].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	cookieName, ok := args[logoutParamCookieName].(string)
	if !ok {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &oidcLogoutFilter{
		clientID:     clientID,
		clientSecret: clientSecret,
		revokeURL:    revokeURL,
		redirectURL:  redirectURL,
		cookieName:   cookieName,
	}, nil
}

func (f *oidcLogoutFilter) Request(ctx filters.FilterContext) {
	req := ctx.Request()

	cookie, err := req.Cookie(f.cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			log.Debugf("No cookie found with name: %s", f.cookieName)
			return
		}
		log.Errorf("Error reading cookie: %v", err)
		ctx.Serve(&http.Response{StatusCode: http.StatusInternalServerError})
		return
	}

	tokenContainer, err := f.parseTokenContainer(cookie.Value)
	if err != nil {
		log.Errorf("Error parsing token container: %v", err)
		ctx.Serve(&http.Response{StatusCode: http.StatusInternalServerError})
		return
	}

	if err := f.revokeToken(tokenContainer.OAuth2Token.AccessToken); err != nil {
		log.Errorf("Error revoking access token: %v", err)
		ctx.Serve(&http.Response{StatusCode: http.StatusInternalServerError})
		return
	}

	if tokenContainer.OAuth2Token.RefreshToken != "" {
		if err := f.revokeToken(tokenContainer.OAuth2Token.RefreshToken); err != nil {
			log.Errorf("Error revoking refresh token: %v", err)
			ctx.Serve(&http.Response{StatusCode: http.StatusInternalServerError})
			return
		}
	}
}

func (f *oidcLogoutFilter) Response(ctx filters.FilterContext) {
	f.clearCookie(ctx)
	f.redirect(ctx)
}

func (f *oidcLogoutFilter) parseTokenContainer(cookieValue string) (*tokenContainer, error) {
	decodedCookie, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cookie value: %v", err)
	}

	var container tokenContainer
	if err := json.Unmarshal(decodedCookie, &container); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token container: %v", err)
	}

	return &container, nil
}

func (f *oidcLogoutFilter) revokeToken(token string) error {
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", f.clientID)
	data.Set("client_secret", f.clientSecret)

	req, err := http.NewRequest("POST", f.revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %v", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send revoke request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (f *oidcLogoutFilter) clearCookie(ctx filters.FilterContext) {
	cookie := &http.Cookie{
		Name:     f.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	}
	ctx.Response().Header.Add("Set-Cookie", cookie.String())
}

func (f *oidcLogoutFilter) redirect(ctx filters.FilterContext) {
	ctx.Response().StatusCode = http.StatusFound
	ctx.Response().Header.Set("Location", f.redirectURL)
}