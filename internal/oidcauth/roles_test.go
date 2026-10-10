package oidcauth

import (
	"context"
	"testing"
)

func TestRoleMappingRejectsInvalidPrograms(t *testing.T) {
	for _, expression := range []string{"claims.", "42", "userinfo.roles", "claims.roles.map(r, r)"} {
		t.Run(expression, func(t *testing.T) {
			if _, err := NewRoleMapping("https://openlist.example/api", expression); err == nil {
				t.Fatal("invalid program was accepted")
			}
		})
	}
}

func TestRoleMappingEvaluationFailsClosed(t *testing.T) {
	for _, expression := range []string{"'unknown'", "claims.missing == 'admin' ? 'admin' : 'general'"} {
		mapping, err := NewRoleMapping("https://openlist.example/api", expression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mapping.Role(context.Background(), map[string]interface{}{}); err == nil {
			t.Fatalf("%s unexpectedly authorized", expression)
		}
	}
}

func TestRoleMappingBoundsEvaluationCost(t *testing.T) {
	mapping, err := NewRoleMapping("https://openlist.example/api", "claims.items.all(x, claims.items.all(y, x >= 0 && y >= 0)) ? 'admin' : 'guest'")
	if err != nil {
		t.Fatal(err)
	}
	items := make([]interface{}, 500)
	for i := range items {
		items[i] = i
	}
	if _, err := mapping.Role(context.Background(), map[string]interface{}{"items": items}); err == nil {
		t.Fatal("unbounded evaluation authorized")
	}
}
