// Package oidcauth authorizes server-managed OAuth2 sessions from access tokens.
package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"cel.dev/cel-go/cel"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

var ErrUnauthorized = errors.New("OIDC session is not authorized; login again")

const identityPrefix = "oidc:"

// Identity separates issuers and subjects without requiring a database migration.
// A legacy SSO binding is migrated only when the operator explicitly rebinds it.
func Identity(issuer, subject string) string {
	encoded, _ := json.Marshal([]string{issuer, subject})
	digest := sha256.Sum256(encoded)
	return identityPrefix + base64.RawURLEncoding.EncodeToString(digest[:])
}

func ManagedIdentity(identity string) bool {
	encoded, ok := strings.CutPrefix(identity, identityPrefix)
	if !ok || len(encoded) != 43 {
		return false
	}
	digest, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(digest) == sha256.Size
}

type RoleMapping struct {
	Resource string
	program  cel.Program
}

// NewRoleMapping compiles one side-effect-free policy. Its only input is the
// verified access-token claims; the output is one of the native role names.
func NewRoleMapping(resource, expression string) (*RoleMapping, error) {
	if strings.TrimSpace(resource) == "" {
		return nil, errors.New("OIDC role mapping requires a resource audience")
	}
	env, err := cel.NewEnv(cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)), cel.ParserExpressionSizeLimit(4096), cel.ParserRecursionLimit(64))
	if err != nil {
		return nil, err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, errors.New("invalid OIDC role mapping expression")
	}
	if ast.OutputType() != cel.StringType {
		return nil, errors.New("OIDC role mapping expression must return a string")
	}
	program, err := env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(100))
	if err != nil {
		return nil, errors.New("invalid OIDC role mapping program")
	}
	return &RoleMapping{Resource: resource, program: program}, nil
}

func (m *RoleMapping) Role(ctx context.Context, claims map[string]interface{}) (int, error) {
	value, _, err := m.program.ContextEval(ctx, map[string]interface{}{"claims": claims})
	if err != nil {
		return 0, ErrUnauthorized
	}
	switch value.Value() {
	case "admin":
		return model.ADMIN, nil
	case "general":
		return model.GENERAL, nil
	case "guest":
		return model.GUEST, nil
	default:
		return 0, ErrUnauthorized
	}
}
