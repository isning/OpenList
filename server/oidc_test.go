package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/OpenListTeam/OpenList/v4/drivers/local"
	"github.com/OpenListTeam/OpenList/v4/internal/bootstrap/data"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/oidcauth"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	jose "gopkg.in/go-jose/go-jose.v2"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testOIDCPolicy = "has(claims.roles) && 'base:admin' in claims.roles ? 'admin' : (has(claims.roles) && 'base:reader' in claims.roles ? 'general' : 'guest')"
const testOIDCResource = "https://openlist.example/api"

type testGrant struct {
	subject, name, nonce, challenge, mode string
	roles                                 []string
	expiresIn                             int
	omitRefresh, noRefresh                bool
}

type testOIDCProvider struct {
	mu             sync.Mutex
	server         *httptest.Server
	key            *ecdsa.PrivateKey
	kid            string
	codes          map[string]testGrant
	grants         map[string]testGrant
	refreshes      []string
	failures       int
	jwksCalls      int
	protocolErrors []string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testOIDCProvider{key: key, kid: uuid.NewString(), codes: make(map[string]testGrant), grants: make(map[string]testGrant)}
	p.server = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *testOIDCProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"ES384"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/jwks":
		p.jwksCalls++
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "ES384", Use: "sig"}}})
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", 400)
			return
		}
		var grant testGrant
		if r.Form.Get("grant_type") == "refresh_token" {
			raw := r.Form.Get("refresh_token")
			p.refreshes = append(p.refreshes, raw)
			var ok bool
			grant, ok = p.grants[raw]
			if !ok || p.failures > 0 {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			if !grant.omitRefresh {
				delete(p.grants, raw)
			}
		} else {
			var ok bool
			grant, ok = p.codes[r.Form.Get("code")]
			if !ok {
				http.Error(w, "unknown code", 400)
				return
			}
			delete(p.codes, r.Form.Get("code"))
			if grant.challenge != "" {
				digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(digest[:]) != grant.challenge {
					p.protocolErrors = append(p.protocolErrors, "PKCE verifier mismatch")
					http.Error(w, "bad verifier", 400)
					return
				}
			}
		}
		if grant.challenge != "" && r.Form.Get("resource") != testOIDCResource {
			p.protocolErrors = append(p.protocolErrors, "missing resource")
			http.Error(w, "bad resource", 400)
			return
		}
		expires := grant.expiresIn
		if expires == 0 {
			expires = 3600
		}
		access := p.signedToken(grant, false)
		if grant.mode == "opaque" {
			access = "synthetic-opaque-access-token"
		}
		response := map[string]interface{}{"access_token": access, "token_type": "Bearer", "expires_in": expires, "id_token": p.signedToken(grant, true)}
		if !grant.omitRefresh && !grant.noRefresh {
			refresh := uuid.NewString()
			p.grants[refresh] = grant
			response["refresh_token"] = refresh
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		http.NotFound(w, r)
	}
}

func (p *testOIDCProvider) signedToken(grant testGrant, id bool) string {
	claims := jwt.MapClaims{"iss": p.server.URL, "sub": grant.subject, "aud": testOIDCResource, "exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix()}
	if grant.roles != nil {
		claims["roles"] = grant.roles
	}
	method := jwt.SigningMethodES384
	key := p.key
	if id {
		claims["aud"] = "test-openlist-client"
		claims["name"] = grant.name
		claims["nonce"] = grant.nonce
		claims["roles"] = []string{"base:admin"}
	} else {
		switch grant.mode {
		case "null-roles":
			claims["roles"] = nil
		case "issuer":
			claims["iss"] = "https://other.example"
		case "audience":
			claims["aud"] = "https://other.example/api"
		case "subject":
			claims["sub"] = "other-user"
		case "expired":
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
		case "not-before":
			claims["nbf"] = time.Now().Add(time.Hour).Unix()
		case "signature":
			key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
	}
	if id && grant.mode == "nonce" {
		claims["nonce"] = "other-login"
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = p.kid
	signed, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}
	return signed
}

func (p *testOIDCProvider) code(grant testGrant, auth url.Values) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	grant.nonce, grant.challenge = auth.Get("nonce"), auth.Get("code_challenge")
	code := uuid.NewString()
	p.codes[code] = grant
	return code
}

func (p *testOIDCProvider) changeGrants(subject, mode string, roles []string, omitRefresh bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, grant := range p.grants {
		if grant.subject == subject {
			grant.roles, grant.mode, grant.omitRefresh = roles, mode, omitRefresh
			p.grants[key] = grant
		}
	}
}

type oidcFixture struct {
	provider     *testOIDCProvider
	app          *httptest.Server
	client       *http.Client
	root, mount  string
	guest, admin *model.User
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	previousKey := common.SecretKey
	t.Cleanup(func() { common.SecretKey = previousKey })
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	conf.Conf = conf.DefaultConfig(root)
	conf.Conf.JwtSecret = "synthetic-openlist-test-signing-key"
	conf.Conf.DistDir = filepath.Join(root, "frontend")
	if err := os.MkdirAll(conf.Conf.DistDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf.Conf.DistDir, "index.html"), []byte("<html>test</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"assets", "images", "streamer", "static"} {
		if err := os.MkdirAll(filepath.Join(conf.Conf.DistDir, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	conf.URL = &url.URL{}
	conf.StoragesLoaded = true
	database, err := gorm.Open(sqlite.Open("file:"+uuid.NewString()+"?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	db.Init(database)
	if err := db.SaveSettingItems(data.InitialSettings()); err != nil {
		t.Fatal(err)
	}
	op.SettingCacheUpdate()
	f := &oidcFixture{provider: newTestOIDCProvider(t), root: filepath.Join(root, "files"), mount: "/oidc-" + uuid.NewString(), client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, dir := range []string{"alice", "bob", "public"} {
		if err := os.MkdirAll(filepath.Join(f.root, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, dir, dir+".txt"), []byte("synthetic-content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.admin = (&model.User{Username: "local-admin", Role: model.ADMIN, BasePath: "/", Permission: 0x71ff}).SetPassword(uuid.NewString())
	f.guest = (&model.User{Username: "guest", Role: model.GUEST, BasePath: f.mount + "/public"}).SetPassword(uuid.NewString())
	for _, user := range []*model.User{f.admin, f.guest} {
		if err := db.CreateUser(user); err != nil {
			t.Fatal(err)
		}
	}
	f.setting(t, conf.Token, uuid.NewString())
	f.setting(t, conf.SSOLoginEnabled, "true")
	f.setting(t, conf.SSOLoginPlatform, "OIDC")
	f.setting(t, conf.SSOEndpointName, f.provider.server.URL)
	f.setting(t, conf.SSOClientId, "test-openlist-client")
	f.setting(t, conf.SSOClientSecret, uuid.NewString())
	f.setting(t, conf.SSOOIDCUsernameKey, "name")
	f.setting(t, conf.SSOExtraScopes, "")
	f.setting(t, conf.SSOCompatibilityMode, "false")
	f.setting(t, conf.SSOAutoRegister, "true")
	f.setting(t, conf.SSODefaultDir, f.mount+"/alice")
	f.setting(t, conf.SSODefaultPermission, "136")
	f.setting(t, conf.SSOOIDCResource, testOIDCResource)
	f.setting(t, conf.SSOOIDCRoleMapping, testOIDCPolicy)
	addition, _ := json.Marshal(map[string]string{"root_folder_path": f.root})
	if _, err := op.CreateStorage(context.Background(), model.Storage{Driver: "Local", MountPath: f.mount, Addition: string(addition)}); err != nil {
		t.Fatal(err)
	}
	for _, user := range []*model.User{f.admin, f.guest} {
		if err := op.DelUserCache(user.Username); err != nil {
			t.Fatal(err)
		}
	}
	// Populate native singleton caches before concurrent request tests.
	if _, err := op.GetAdmin(); err != nil {
		t.Fatal(err)
	}
	if _, err := op.GetGuest(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	Init(router)
	f.app = httptest.NewServer(router)
	conf.Conf.SiteURL = f.app.URL
	t.Cleanup(func() { f.app.Close(); db.Close(); op.Cache.ClearAll() })
	return f
}

func (f *oidcFixture) setting(t *testing.T, key, value string) {
	t.Helper()
	item := &model.SettingItem{Key: key, Value: value}
	if err := db.SaveSettingItem(item); err != nil {
		t.Fatal(err)
	}
	op.Cache.SetSetting(key, item)
}

func (f *oidcFixture) request(t *testing.T, method, path, token string, body interface{}) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, f.app.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func (f *oidcFixture) api(t *testing.T, method, path, token string, body interface{}, want int) json.RawMessage {
	t.Helper()
	status, data := f.request(t, method, path, token, body)
	var result struct {
		Code    int             `json:"code"`
		Data    json.RawMessage `json:"data"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("%s: invalid API response: %v", path, err)
	}
	if status != 200 || result.Code != want {
		t.Fatalf("%s: HTTP %d / code %d, want %d: %s", path, status, result.Code, want, result.Message)
	}
	return result.Data
}

var loginTokenPattern = regexp.MustCompile(`"token":"([^"]+)"`)

func (f *oidcFixture) login(t *testing.T, grant testGrant, wantSuccess bool) string {
	t.Helper()
	resp, err := f.client.Get(f.app.URL + "/api/auth/sso?method=sso_get_token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("login redirect failed: %s", data)
	}
	auth, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := auth.Query()
	policy, _, err := common.OIDCPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy != nil && (query.Get("resource") != testOIDCResource || query.Get("code_challenge_method") != "S256" || query.Get("nonce") == "" || !strings.Contains(query.Get("scope"), "offline_access")) {
		t.Fatal("authorization request omitted resource, PKCE, nonce, or offline_access")
	}
	code := f.provider.code(grant, query)
	_, body := f.request(t, "GET", "/api/auth/sso_callback?method=sso_get_token&state="+url.QueryEscape(query.Get("state"))+"&code="+url.QueryEscape(code), "", nil)
	match := loginTokenPattern.FindSubmatch(body)
	if wantSuccess && len(match) != 2 {
		t.Fatalf("OIDC callback did not issue a native token: %s", body)
	}
	if !wantSuccess {
		if len(match) != 0 {
			t.Fatal("invalid access token issued a login credential")
		}
		return ""
	}
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	if len(f.provider.protocolErrors) != 0 {
		t.Fatalf("provider protocol errors: %v", f.provider.protocolErrors)
	}
	return string(match[1])
}

func (f *oidcFixture) current(t *testing.T, token string) model.User {
	t.Helper()
	var user model.User
	if err := json.Unmarshal(f.api(t, "GET", "/api/me", token, nil, 200), &user); err != nil {
		t.Fatal(err)
	}
	return user
}

func (f *oidcFixture) account(t *testing.T, subject string) *model.User {
	t.Helper()
	user, err := db.GetUserBySSOID(oidcauth.Identity(f.provider.server.URL, subject))
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func (f *oidcFixture) upload(t *testing.T, token, path string, want int) {
	t.Helper()
	req, err := http.NewRequest("PUT", f.app.URL+"/api/fs/put", strings.NewReader("synthetic upload content"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("File-Path", url.PathEscape(path))
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Code != want {
		t.Fatalf("upload: code %d, want %d: %s", result.Code, want, result.Message)
	}
}

func TestOIDCNativeTokenRolesAndAccountIsolation(t *testing.T) {
	f := newOIDCFixture(t)
	first := f.login(t, testGrant{subject: "alice-sub", name: "alice", roles: []string{"base:admin"}}, true)
	second := f.login(t, testGrant{subject: "alice-sub", name: "alice renamed", roles: []string{"base:reader"}}, true)
	if first == second {
		t.Fatal("two logins share a token")
	}
	admin := f.current(t, first)
	general := f.current(t, second)
	if admin.ID != general.ID || admin.Role != model.ADMIN || general.Role != model.GENERAL {
		t.Fatal("session roles were not independently applied to the same account")
	}
	stored := f.account(t, "alice-sub")
	if stored.Role != model.GENERAL || stored.BasePath != f.mount+"/alice" || stored.Permission != 136 {
		t.Fatal("mapping persisted roles or replaced native initial permissions")
	}
	f.api(t, "GET", "/api/admin/setting/list", first, nil, 200)
	f.api(t, "GET", "/api/admin/setting/list", second, nil, 403)
	_, response := f.request(t, "GET", "/api/me", first, nil)
	if strings.Contains(string(response), "refresh_token") || strings.Contains(string(response), "access_token") {
		t.Fatal("provider token leaked to frontend")
	}
	f.api(t, "POST", "/api/me/update", first, map[string]interface{}{"username": "alice", "password": "new-synthetic-password", "sso_id": ""}, 403)
	f.api(t, "POST", "/api/me/sshkey/add", first, map[string]interface{}{}, 403)
	f.api(t, "GET", "/api/authn/webauthn_begin_registration", first, nil, 403)
	f.api(t, "POST", "/api/auth/2fa/generate", first, nil, 403)
	f.api(t, "POST", "/api/admin/user/update", first, map[string]interface{}{"id": stored.ID, "username": stored.Username, "role": stored.Role, "sso_id": ""}, 403)
	f.api(t, "POST", "/api/admin/user/cancel_2fa?id="+strconv.FormatUint(uint64(stored.ID), 10), first, nil, 403)
	publicKey, err := ssh.NewPublicKey(&f.provider.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sshKey := &model.SSHPublicKey{UserId: stored.ID, Title: "existing-admin-key", KeyStr: string(ssh.MarshalAuthorizedKey(publicKey))}
	if err, _ := op.CreateSSHPublicKey(sshKey); err != nil {
		t.Fatal(err)
	}
	f.api(t, "POST", "/api/admin/user/sshkey/delete?id="+strconv.FormatUint(uint64(sshKey.ID), 10), first, nil, 403)

	bobToken := f.login(t, testGrant{subject: "bob-sub", name: "alice", roles: []string{"base:reader"}}, true)
	bob := f.account(t, "bob-sub")
	if bob.ID == stored.ID || bob.Username == stored.Username {
		t.Fatal("same display name reused another identity")
	}
	bob.BasePath, bob.Permission = f.mount+"/bob", 0
	if err := op.UpdateUser(bob); err != nil {
		t.Fatal(err)
	}
	if f.current(t, bobToken).BasePath != bob.BasePath {
		t.Fatal("updated base path ignored")
	}
	f.api(t, "POST", "/api/fs/mkdir", second, map[string]string{"path": "/created"}, 200)
	f.api(t, "POST", "/api/fs/mkdir", bobToken, map[string]string{"path": "/denied"}, 403)
	f.upload(t, second, "/uploaded.txt", 200)
	f.upload(t, bobToken, "/denied.txt", 403)
	if contents, err := os.ReadFile(filepath.Join(f.root, "alice", "uploaded.txt")); err != nil || string(contents) != "synthetic upload content" {
		t.Fatal("upload did not use the external user's base path")
	}
	stored.Permission = 0
	if err := op.UpdateUser(stored); err != nil {
		t.Fatal(err)
	}
	f.upload(t, first, "/admin-denied.txt", 403)
	stored.Permission = 136
	if err := op.UpdateUser(stored); err != nil {
		t.Fatal(err)
	}
	f.api(t, "POST", "/api/fs/remove", second, map[string]interface{}{"dir": "/", "names": []string{"alice.txt"}}, 200)
	f.api(t, "POST", "/api/fs/remove", bobToken, map[string]interface{}{"dir": "/", "names": []string{"bob.txt"}}, 403)
	if _, err := os.Stat(filepath.Join(f.root, "bob", "bob.txt")); err != nil {
		t.Fatal("another user's file changed")
	}
	f.api(t, "POST", "/api/fs/list", bobToken, map[string]string{"path": "/"}, 200)
	bob.Permission = 1 << 3
	if err := op.UpdateUser(bob); err != nil {
		t.Fatal(err)
	}
	f.api(t, "POST", "/api/fs/mkdir", bobToken, map[string]string{"path": "/now-allowed"}, 200)
}

func TestOIDCGuestUsesNativeGuestRestrictions(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.login(t, testGrant{subject: "visitor-sub", name: "visitor"}, true)
	user := f.current(t, token)
	if user.ID != f.guest.ID || user.Role != model.GUEST || user.BasePath != f.guest.BasePath || user.Permission != f.guest.Permission {
		t.Fatal("guest inherited the external account's permissions")
	}
	list := f.api(t, "POST", "/api/fs/list", token, map[string]string{"path": "/"}, 200)
	if !strings.Contains(string(list), "public.txt") || strings.Contains(string(list), "alice.txt") {
		t.Fatal("guest did not see the visitor root")
	}
	f.api(t, "POST", "/api/fs/mkdir", token, map[string]string{"path": "/denied"}, 403)
	// Metadata must use the effective guest ID, not the privileged account ID.
	owner := f.account(t, "visitor-sub")
	if err := op.CreateMeta(&model.Meta{Path: f.guest.BasePath, ReadUsers: []uint{owner.ID}, ReadUsersSub: true}); err != nil {
		t.Fatal(err)
	}
	f.api(t, "POST", "/api/fs/list", token, map[string]string{"path": "/"}, 403)
	f.guest.Disabled = true
	if err := op.UpdateUser(f.guest); err != nil {
		t.Fatal(err)
	}
	f.api(t, "GET", "/api/me", token, nil, 401)
}

func TestOIDCRejectsInvalidAccessTokens(t *testing.T) {
	f := newOIDCFixture(t)
	for _, mode := range []string{"signature", "issuer", "audience", "subject", "expired", "not-before", "opaque", "nonce", "null-roles"} {
		t.Run(mode, func(t *testing.T) {
			f.login(t, testGrant{subject: "invalid-" + mode, name: "invalid-" + mode, roles: []string{"base:admin"}, mode: mode}, false)
		})
	}
	var count int64
	if err := db.GetDb().Model(&model.User{}).Where("sso_id LIKE ?", "oidc:%").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("invalid authorization created external users")
	}
}

func TestOIDCPolicyErrorsDenyAuthorization(t *testing.T) {
	f := newOIDCFixture(t)
	for _, expression := range []string{"'unsupported'", "claims.missing == 'x' ? 'admin' : 'guest'"} {
		f.setting(t, conf.SSOOIDCRoleMapping, expression)
		f.login(t, testGrant{subject: "policy-sub", name: "policy-user"}, false)
	}
	f.setting(t, conf.SSOOIDCRoleMapping, testOIDCPolicy)
	token := f.login(t, testGrant{subject: "valid-sub", name: "valid-user", roles: []string{"base:admin"}}, true)
	f.setting(t, conf.SSOOIDCRoleMapping, "claims.")
	f.api(t, "GET", "/api/me", token, nil, 401)
	f.api(t, "GET", "/api/auth/sso?method=sso_get_token", "", nil, 400)
}

func TestOIDCRefreshRotationConcurrencyAndDemotion(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.login(t, testGrant{subject: "refresh-sub", name: "refresh-user", roles: []string{"base:admin"}, expiresIn: 1}, true)
	f.current(t, token)
	f.provider.changeGrants("refresh-sub", "", []string{"base:reader"}, false)
	time.Sleep(1100 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if user := f.current(t, token); user.Role != model.GENERAL {
				t.Errorf("refresh retained role %d", user.Role)
			}
		}()
	}
	wg.Wait()
	f.provider.mu.Lock()
	calls := len(f.provider.refreshes)
	f.provider.mu.Unlock()
	if calls != 1 {
		t.Fatalf("%d refresh requests, want one", calls)
	}
	f.api(t, "GET", "/api/admin/setting/list", token, nil, 403)
	f.provider.changeGrants("refresh-sub", "", nil, false)
	time.Sleep(1100 * time.Millisecond)
	if user := f.current(t, token); user.Role != model.GUEST || user.BasePath != f.guest.BasePath {
		t.Fatal("refresh failed to switch to visitor permissions")
	}
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	if len(f.provider.refreshes) != 2 || f.provider.refreshes[0] == f.provider.refreshes[1] {
		t.Fatal("rotated refresh token was not used")
	}
}

func TestOIDCRefreshFailureAndSubjectChangeFailClosed(t *testing.T) {
	for _, mode := range []string{"provider-error", "subject", "expired", "omit-refresh", "no-refresh"} {
		t.Run(mode, func(t *testing.T) {
			f := newOIDCFixture(t)
			token := f.login(t, testGrant{subject: "failure-sub", name: "failure-user", roles: []string{"base:admin"}, expiresIn: 1, noRefresh: mode == "no-refresh"}, true)
			if mode == "provider-error" {
				f.provider.mu.Lock()
				f.provider.failures = 1
				f.provider.mu.Unlock()
			} else {
				f.provider.changeGrants("failure-sub", mode, []string{"base:reader"}, mode == "omit-refresh")
			}
			time.Sleep(1100 * time.Millisecond)
			if mode == "omit-refresh" {
				if f.current(t, token).Role != model.GENERAL {
					t.Fatal("refresh failed")
				}
				time.Sleep(1100 * time.Millisecond)
				f.current(t, token)
				f.provider.mu.Lock()
				calls := append([]string(nil), f.provider.refreshes...)
				f.provider.mu.Unlock()
				if len(calls) != 2 || calls[0] != calls[1] {
					t.Fatal("missing refresh token erased the existing token")
				}
			} else {
				f.api(t, "GET", "/api/me", token, nil, 401)
				f.api(t, "GET", "/api/admin/setting/list", token, nil, 401)
			}
		})
	}
}

func TestOIDCRefreshAfterCallbackContextAndKeyRotation(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.login(t, testGrant{subject: "rotation-sub", name: "rotation-user", roles: []string{"base:reader"}, expiresIn: 1}, true)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.mu.Lock()
	f.provider.key, f.provider.kid = key, uuid.NewString()
	before := f.provider.jwksCalls
	f.provider.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	f.current(t, token)
	f.provider.mu.Lock()
	after := f.provider.jwksCalls
	f.provider.mu.Unlock()
	if after <= before {
		t.Fatal("new signing key was not fetched after callback request ended")
	}
}

func TestOIDCLogoutDisabledAccountAndMissingSession(t *testing.T) {
	f := newOIDCFixture(t)
	first := f.login(t, testGrant{subject: "logout-sub", name: "logout-user"}, true)
	second := f.login(t, testGrant{subject: "logout-sub", name: "logout-user"}, true)
	f.api(t, "GET", "/api/auth/logout", first, nil, 200)
	f.api(t, "GET", "/api/me", first, nil, 401)
	f.current(t, second)
	user := f.account(t, "logout-sub")
	user.Disabled = true
	if err := op.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	f.api(t, "GET", "/api/me", second, nil, 401)
	if f.guest.Disabled {
		t.Fatal("logout or disable mutated the shared guest")
	}

	active := f.login(t, testGrant{subject: "active-sub", name: "active-user", roles: []string{"base:reader"}}, true)
	claims, err := common.ParseToken(active)
	if err != nil {
		t.Fatal(err)
	}
	claims.OIDCSessionID = uuid.NewString()
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(common.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	f.api(t, "GET", "/api/me", forged, nil, 401)
}

func TestOIDCLegacyAccountsAndLocalRecoveryStaySeparate(t *testing.T) {
	f := newOIDCFixture(t)
	legacy := (&model.User{Username: "legacy-user", SsoID: "legacy-display", Role: model.GENERAL, BasePath: f.mount + "/bob", Permission: 0}).SetPassword(uuid.NewString())
	if err := db.CreateUser(legacy); err != nil {
		t.Fatal(err)
	}
	f.login(t, testGrant{subject: "legacy-sub", name: "legacy-display", roles: []string{"base:admin"}}, false)
	persisted, err := db.GetUserById(legacy.ID)
	if err != nil || persisted.SsoID != legacy.SsoID {
		t.Fatal("legacy account was silently rebound")
	}
	// An operator may explicitly bind the stable identity using existing user administration.
	legacy.SsoID = oidcauth.Identity(f.provider.server.URL, "legacy-sub")
	if err := op.UpdateUser(legacy); err != nil {
		t.Fatal(err)
	}
	token := f.login(t, testGrant{subject: "legacy-sub", name: "renamed-user", roles: []string{"base:reader"}}, true)
	if user := f.current(t, token); user.ID != legacy.ID || user.BasePath != legacy.BasePath || user.Permission != legacy.Permission {
		t.Fatal("explicit binding did not preserve existing account permissions")
	}
	if _, err := common.GenerateToken(legacy); err == nil {
		t.Fatal("alternate login issued a managed account token")
	}
	_, ok := tryLogin(legacy.Username, "irrelevant-password")
	if ok {
		t.Fatal("WebDAV allowed a managed account login")
	}
	recovery, err := common.GenerateToken(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	f.api(t, "GET", "/api/admin/setting/list", recovery, nil, 200)
}

func TestOIDCManagedPasswordLoginAndDisabledAutoRegistration(t *testing.T) {
	f := newOIDCFixture(t)
	_ = f.login(t, testGrant{subject: "managed-sub", name: "managed-user", roles: []string{"base:reader"}}, true)
	user := f.account(t, "managed-sub")
	user.SetPassword("synthetic-managed-password")
	if err := op.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	f.api(t, "POST", "/api/auth/login", "", map[string]string{"username": user.Username, "password": "synthetic-managed-password"}, 401)
	if _, ok := tryLogin(user.Username, "synthetic-managed-password"); ok {
		t.Fatal("WebDAV bypassed OIDC with correct local password")
	}
	f.setting(t, conf.SSOAutoRegister, "false")
	f.login(t, testGrant{subject: "new-sub", name: "new-user", roles: []string{"base:reader"}}, false)
	f.setting(t, conf.SSOOIDCRoleMapping, "")
	f.api(t, "GET", "/api/me", mustNativeRecoveryToken(t, f.admin), nil, 200)
}

func mustNativeRecoveryToken(t *testing.T, user *model.User) string {
	t.Helper()
	token, err := common.GenerateToken(user)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type oidcFTPClient struct{ ftpserver.ClientContext }

func (oidcFTPClient) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 12345}
}

type oidcSSHClient struct {
	ssh.ConnMetadata
	username string
}

func (c oidcSSHClient) User() string { return c.username }
func (oidcSSHClient) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 12345}
}

func TestOIDCFileProtocolAuthenticationCannotBypass(t *testing.T) {
	f := newOIDCFixture(t)
	f.login(t, testGrant{subject: "protocol-sub", name: "protocol-user", roles: []string{"base:reader"}}, true)
	user := f.account(t, "protocol-sub")
	user.SetPassword("synthetic-protocol-password")
	user.Permission |= 1<<10 | 1<<8
	if err := op.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err, _ := op.CreateSSHPublicKey(&model.SSHPublicKey{UserId: user.ID, Title: "pre-existing", KeyStr: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}); err != nil {
		t.Fatal(err)
	}
	ftpDriver, sftpDriver := &FtpMainDriver{}, &SftpDriver{}
	client := oidcSSHClient{username: user.Username}
	if _, err := ftpDriver.AuthUser(oidcFTPClient{}, user.Username, "synthetic-protocol-password"); err == nil {
		t.Fatal("FTP accepted a managed password")
	}
	if _, err := sftpDriver.PasswordAuth(client, []byte("synthetic-protocol-password")); err == nil {
		t.Fatal("SFTP accepted a managed password")
	}
	if _, err := sftpDriver.PublicKeyAuth(client, signer.PublicKey()); err == nil {
		t.Fatal("SFTP accepted a pre-existing managed key")
	}
	f.setting(t, conf.LdapLoginEnabled, "true")
	f.api(t, "POST", "/api/auth/login/ldap", "", map[string]string{"username": user.Username, "password": "synthetic-protocol-password"}, 401)
	f.setting(t, conf.WebauthnLoginEnabled, "true")
	conf.Conf.SiteURL = "https://openlist.example"
	f.api(t, "GET", "/api/authn/webauthn_begin_login?username="+url.QueryEscape(user.Username), "", nil, 401)
	// Explicit operator unbinding restores the native account; the same valid
	// password and key demonstrate that rejection was caused by OIDC binding.
	user.SsoID = ""
	if err := op.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	if _, err := ftpDriver.AuthUser(oidcFTPClient{}, user.Username, "synthetic-protocol-password"); err != nil {
		t.Fatalf("native FTP failed: %v", err)
	}
	if _, err := sftpDriver.PasswordAuth(client, []byte("synthetic-protocol-password")); err != nil {
		t.Fatalf("native SFTP password failed: %v", err)
	}
	if _, err := sftpDriver.PublicKeyAuth(client, signer.PublicKey()); err != nil {
		t.Fatalf("native SFTP key failed: %v", err)
	}
	if _, ok := tryLogin(user.Username, "synthetic-protocol-password"); !ok {
		t.Fatal("native WebDAV password failed")
	}
}

func TestOIDCLegacyFlowAndPreBindingToken(t *testing.T) {
	f := newOIDCFixture(t)
	legacy := (&model.User{Username: "old-user", SsoID: "oidc:old-display", Role: model.GENERAL, BasePath: f.mount + "/bob"}).SetPassword(uuid.NewString())
	if err := db.CreateUser(legacy); err != nil {
		t.Fatal(err)
	}
	f.setting(t, conf.SSOOIDCRoleMapping, "")
	token := f.login(t, testGrant{subject: "old-sub", name: "oidc:old-display", mode: "opaque"}, true)
	if f.current(t, token).ID != legacy.ID {
		t.Fatal("disabled feature did not preserve legacy SSO identity")
	}
	legacy.SsoID = oidcauth.Identity(f.provider.server.URL, "old-sub")
	if err := op.UpdateUser(legacy); err != nil {
		t.Fatal(err)
	}
	// A still-valid native token issued before binding cannot skip OAuth2.
	f.api(t, "GET", "/api/me", token, nil, 401)
	f.setting(t, conf.SSOOIDCRoleMapping, testOIDCPolicy)
	active := f.login(t, testGrant{subject: "old-sub", name: "", roles: []string{"base:reader"}}, true)
	legacy.PwdTS++
	if err := op.UpdateUser(legacy); err != nil {
		t.Fatal(err)
	}
	f.api(t, "GET", "/api/me", active, nil, 401)
}

func TestOIDCRefreshSessionsAreIndependent(t *testing.T) {
	f := newOIDCFixture(t)
	first := f.login(t, testGrant{subject: "two-session-sub", name: "two-session-user", roles: []string{"base:admin"}, expiresIn: 1}, true)
	second := f.login(t, testGrant{subject: "two-session-sub", name: "two-session-user", roles: []string{"base:reader"}, expiresIn: 1}, true)
	time.Sleep(1100 * time.Millisecond)
	if f.current(t, first).Role != model.ADMIN || f.current(t, second).Role != model.GENERAL {
		t.Fatal("independent refresh changed another session's role")
	}
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	if len(f.provider.refreshes) != 2 || f.provider.refreshes[0] == f.provider.refreshes[1] {
		t.Fatal("separate logins shared a refresh token")
	}
}

func TestOIDCConcurrentRefreshFailureIsTerminal(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.login(t, testGrant{subject: "failed-concurrent-sub", name: "failed-concurrent-user", roles: []string{"base:admin"}, expiresIn: 1}, true)
	f.provider.mu.Lock()
	f.provider.failures = 1
	f.provider.mu.Unlock()
	time.Sleep(1100 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.api(t, "GET", "/api/me", token, nil, 401)
		}()
	}
	wg.Wait()
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	if len(f.provider.refreshes) != 1 {
		t.Fatalf("failed refresh was redeemed %d times", len(f.provider.refreshes))
	}
}

func TestOIDCLoginStateIsSingleUse(t *testing.T) {
	f := newOIDCFixture(t)
	resp, err := f.client.Get(f.app.URL + "/api/auth/sso?method=sso_get_token")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := auth.Query()
	grant := testGrant{subject: "state-sub", name: "state-user", roles: []string{"base:reader"}}
	code := f.provider.code(grant, query)
	callback := "/api/auth/sso_callback?method=sso_get_token&state=" + url.QueryEscape(query.Get("state")) + "&code=" + url.QueryEscape(code)
	_, body := f.request(t, "GET", callback, "", nil)
	if len(loginTokenPattern.FindSubmatch(body)) != 2 {
		t.Fatal("valid login flow failed")
	}
	// A fresh code cannot be redeemed using an already consumed login state.
	code = f.provider.code(grant, query)
	f.api(t, "GET", "/api/auth/sso_callback?method=sso_get_token&state="+url.QueryEscape(query.Get("state"))+"&code="+url.QueryEscape(code), "", nil, 400)
}

func TestOIDCRestartRequiresNewLogin(t *testing.T) {
	f := newOIDCFixture(t)
	if previous := os.Getenv("OPENLIST_OIDC_RESTART_TEST_TOKEN"); previous != "" {
		// Preserve the signing key across processes: rejection must come from
		// missing in-memory authorization, rather than an invalid signature.
		parsed, err := jwt.ParseWithClaims(previous, &common.UserClaims{}, func(*jwt.Token) (interface{}, error) { return common.SecretKey, nil })
		if err != nil || !parsed.Valid {
			t.Fatal("pre-restart native credential is not cryptographically valid")
		}
		f.api(t, "GET", "/api/me", previous, nil, 401)
		fresh := f.login(t, testGrant{subject: "restart-sub", name: "restart-user", roles: []string{"base:reader"}}, true)
		f.current(t, fresh)
		return
	}
	token := f.login(t, testGrant{subject: "restart-sub", name: "restart-user", roles: []string{"base:reader"}}, true)
	f.current(t, token)
	command := exec.Command(os.Args[0], "-test.run=^TestOIDCRestartRequiresNewLogin$", "-test.count=1")
	command.Env = append(os.Environ(), "OPENLIST_OIDC_RESTART_TEST_TOKEN="+token)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("new backend process failed restart verification: %v\n%s", err, output)
	}
}

func TestOIDCSettingsRoundTripThroughAdminAPI(t *testing.T) {
	f := newOIDCFixture(t)
	token, err := common.GenerateToken(f.admin)
	if err != nil {
		t.Fatal(err)
	}
	var defaults []model.SettingItem
	if err := json.Unmarshal(f.api(t, "POST", "/api/admin/setting/default?group="+strconv.Itoa(model.SSO), token, nil, 200), &defaults); err != nil {
		t.Fatal(err)
	}
	var updates []model.SettingItem
	for _, item := range defaults {
		switch item.Key {
		case conf.SSOOIDCResource:
			if item.Type != conf.TypeString {
				t.Fatal("resource must render as a string input")
			}
			item.Value = testOIDCResource
		case conf.SSOOIDCRoleMapping:
			if item.Type != conf.TypeText {
				t.Fatal("role mapping must render as a multiline input")
			}
			item.Value = testOIDCPolicy
		default:
			continue
		}
		if item.Flag != model.PRIVATE || item.Group != model.SSO || item.Help == "" {
			t.Fatalf("missing private SSO metadata for %s", item.Key)
		}
		updates = append(updates, item)
	}
	if len(updates) != 2 {
		t.Fatal("OIDC settings missing from SSO defaults")
	}
	f.api(t, "POST", "/api/admin/setting/save", token, updates, 200)
	var saved []model.SettingItem
	if err := json.Unmarshal(f.api(t, "GET", "/api/admin/setting/list?group="+strconv.Itoa(model.SSO), token, nil, 200), &saved); err != nil {
		t.Fatal(err)
	}
	for _, want := range updates {
		found := false
		for _, got := range saved {
			if got.Key == want.Key {
				found = got.Value == want.Value && got.Help == want.Help && got.Type == want.Type && got.Flag == want.Flag
			}
		}
		if !found {
			t.Fatalf("setting did not survive save and reload: %s", want.Key)
		}
	}
	var public map[string]string
	if err := json.Unmarshal(f.api(t, "GET", "/api/public/settings", "", nil, 200), &public); err != nil {
		t.Fatal(err)
	}
	for _, item := range updates {
		if _, ok := public[item.Key]; ok {
			t.Fatalf("private OIDC setting exposed publicly: %s", item.Key)
		}
	}
	f.login(t, testGrant{subject: "settings-user", name: "settings-user", roles: []string{"base:reader"}}, true)
}
