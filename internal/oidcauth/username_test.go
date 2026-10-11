package oidcauth

import (
	"context"
	"testing"
)

func TestUsernameMapping(t *testing.T) {
	claims := map[string]interface{}{"sub": "alice"}
	name, err := Username(context.Background(), "'oidc:' + claims.sub", claims)
	if err != nil || name != "oidc:alice" {
		t.Fatalf("unexpected username: %q, %v", name, err)
	}
	for _, expression := range []string{"true", "claims.missing", "''", "'../alice'", "' alice'", "'alice\\n'"} {
		if _, err := Username(context.Background(), expression, claims); err == nil {
			t.Errorf("accepted invalid expression %q", expression)
		}
	}
}
