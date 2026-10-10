package oidcauth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// Session keeps provider tokens on the server. It never persists mapped roles
// to the user database or exposes provider credentials to the browser.
type Session struct {
	mu       sync.Mutex
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	mapping  *RoleMapping
	subject  string
	token    oauth2.Token
	expires  time.Time
	role     int
	closed   bool
}

// NewSession accepts only a signed, unexpired access token with the configured
// resource audience and the same subject as the verified login ID token.
func NewSession(ctx context.Context, config *oauth2.Config, verifier *oidc.IDTokenVerifier, mapping *RoleMapping, subject string, token *oauth2.Token) (*Session, error) {
	if subject == "" || config == nil || verifier == nil || token == nil || mapping == nil {
		return nil, ErrUnauthorized
	}
	s := &Session{config: *config, verifier: verifier, mapping: mapping, subject: subject, token: *token}
	if err := s.verify(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) verify(ctx context.Context) error {
	verified, err := s.verifier.Verify(ctx, s.token.AccessToken)
	if err != nil || verified.Subject != s.subject || !verified.Expiry.After(time.Now()) {
		return ErrUnauthorized
	}
	var claims map[string]interface{}
	if err := verified.Claims(&claims); err != nil {
		return ErrUnauthorized
	}
	// Unlike ID tokens, JWT access tokens may contain nbf. The OIDC verifier
	// does not validate it, so check it before accepting permissions.
	if nbf, ok := claims["nbf"]; ok {
		timestamp, ok := nbf.(float64)
		if !ok || float64(time.Now().Unix()) < timestamp {
			return ErrUnauthorized
		}
	}
	role, err := s.mapping.Role(ctx, claims)
	if err != nil {
		return err
	}
	s.expires, s.role = verified.Expiry, role
	// OAuth2's expires_in can be shorter than the JWT expiry. Never extend
	// authorization beyond either expiry.
	if !s.token.Expiry.IsZero() && s.token.Expiry.Before(s.expires) {
		s.expires = s.token.Expiry
	}
	return nil
}

// Role refreshes only when the current access token expires. The lock prevents
// concurrent requests from redeeming a rotating refresh token more than once.
func (s *Session) Role(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrUnauthorized
	}
	if time.Now().Before(s.expires) {
		return s.role, nil
	}
	if s.token.RefreshToken == "" {
		s.close()
		return 0, ErrUnauthorized
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: resourceTransport{base: http.DefaultTransport, endpoint: s.config.Endpoint.TokenURL, resource: s.mapping.Resource}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	expired := s.token
	expired.Expiry = time.Now().Add(-time.Hour)
	token, err := s.config.TokenSource(ctx, &expired).Token()
	if err != nil {
		s.close()
		return 0, ErrUnauthorized
	}
	// Preserve refresh-token rotation even if the new access token denies
	// authorization. Never fall back to the expired token's privileges.
	if token.RefreshToken == "" {
		token.RefreshToken = s.token.RefreshToken
	}
	s.token = *token
	s.expires = time.Time{}
	if err := s.verify(ctx); err != nil {
		s.close()
		return 0, err
	}
	return s.role, nil
}

// oauth2.Config.TokenSource has no option for RFC 8707 resource indicators.
// Add the indicator only to this provider's token endpoint, including refresh.
type resourceTransport struct {
	base               http.RoundTripper
	endpoint, resource string
}

func (t resourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.String() != t.endpoint {
		return t.base.RoundTrip(req)
	}
	data, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	values, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, err
	}
	values.Set("resource", t.resource)
	body := values.Encode()
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(strings.NewReader(body))
	clone.ContentLength = int64(len(body))
	clone.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(body)), nil }
	return t.base.RoundTrip(clone)
}

// Close makes logout terminal even for requests already holding this session.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
}

func (s *Session) close() {
	s.closed = true
	s.token = oauth2.Token{}
	s.expires = time.Time{}
}
