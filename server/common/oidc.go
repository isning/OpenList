package common

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/oidcauth"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/go-cache"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
)

const OIDCSessionContextKey = "openlist_oidc_session"
const OIDCSessionOwnerContextKey = "openlist_oidc_owner"

var oidcPolicyCache struct {
	sync.Mutex
	key    string
	policy *oidcauth.RoleMapping
	err    error
}

// OIDCPolicy caches only the current configuration, rather than accumulating
// every edited expression. Existing sessions retain their immutable policy.
func OIDCPolicy() (*oidcauth.RoleMapping, string, error) {
	expression := setting.GetStr(conf.SSOOIDCRoleMapping)
	if strings.TrimSpace(expression) == "" {
		return nil, "", nil
	}
	resource := setting.GetStr(conf.SSOOIDCResource)
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(setting.GetStr(conf.SSOEndpointName)+"\x00"+resource+"\x00"+expression)))
	oidcPolicyCache.Lock()
	defer oidcPolicyCache.Unlock()
	if oidcPolicyCache.key != key {
		oidcPolicyCache.policy, oidcPolicyCache.err = oidcauth.NewRoleMapping(resource, expression)
		oidcPolicyCache.key = key
	}
	return oidcPolicyCache.policy, key, oidcPolicyCache.err
}

// RequiresOIDC prevents a managed account from escaping its identity binding
// through a password, WebAuthn, LDAP, or file-protocol login.
func RequiresOIDC(user *model.User) bool {
	return user != nil && oidcauth.ManagedIdentity(user.SsoID)
}

type oidcSession struct {
	userID        uint
	identity      string
	policyKey     string
	authorization *oidcauth.Session
}

var oidcSessions = cache.NewMemCache[*oidcSession](cache.WithExpiredCallback[*oidcSession](func(_ string, session *oidcSession) error {
	session.authorization.Close()
	return nil
}))

// AccessTokenVerifier uses a background key-set context because authorization
// must outlive the callback request. Requests still have a bounded HTTP client.
func AccessTokenVerifier(provider *oidc.Provider, issuer, resource string) (*oidc.IDTokenVerifier, error) {
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil || metadata.JWKSURL == "" {
		return nil, errors.New("OIDC provider has no JWKS endpoint")
	}
	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 15 * time.Second})
	keys := oidc.NewRemoteKeySet(ctx, metadata.JWKSURL)
	return oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: resource, SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}}), nil
}

func GenerateOIDCToken(user *model.User, authorization *oidcauth.Session, policyKey string) (string, error) {
	if user.Disabled || authorization == nil || !RequiresOIDC(user) {
		return "", oidcauth.ErrUnauthorized
	}
	id := uuid.NewString()
	token, err := generateToken(user, id)
	if err != nil {
		return "", err
	}
	oidcSessions.Set(id, &oidcSession{userID: user.ID, identity: user.SsoID, policyKey: policyKey, authorization: authorization}, cache.WithEx[*oidcSession](time.Duration(conf.Conf.TokenExpiresIn)*time.Hour))
	return token, nil
}

// AuthorizeOIDC preserves the real account as the session owner, even when the
// request runs with the built-in guest's effective permissions and metadata ID.
func AuthorizeOIDC(ctx context.Context, user *model.User, claims *UserClaims) (*model.User, error) {
	if claims.OIDCSessionID == "" {
		if RequiresOIDC(user) {
			return nil, oidcauth.ErrUnauthorized
		}
		return user, nil
	}
	session, ok := oidcSessions.Get(claims.OIDCSessionID)
	if !ok || session.userID != user.ID || session.identity != user.SsoID {
		return nil, oidcauth.ErrUnauthorized
	}
	_, key, err := OIDCPolicy()
	if err != nil || key != session.policyKey || !setting.GetBool(conf.SSOLoginEnabled) || setting.GetStr(conf.SSOLoginPlatform) != "OIDC" {
		return nil, oidcauth.ErrUnauthorized
	}
	role, err := session.authorization.Role(ctx)
	if err != nil {
		return nil, err
	}
	if role == model.GUEST {
		// Read current guest configuration, including changes made since login.
		guest, err := op.GetUserByRole(model.GUEST)
		if err != nil || guest.Disabled {
			return nil, oidcauth.ErrUnauthorized
		}
		return guest, nil
	}
	return user.WithSessionRole(role), nil
}

func closeOIDCSession(id string) {
	if session, ok := oidcSessions.Get(id); ok {
		session.authorization.Close()
	}
	oidcSessions.Del(id)
}
