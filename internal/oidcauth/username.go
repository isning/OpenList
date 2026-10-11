package oidcauth

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"
)

// Username evaluates verified ID-token claims only during account provisioning.
func Username(ctx context.Context, expression string, claims map[string]interface{}) (string, error) {
	env, err := cel.NewEnv(cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)), cel.ParserExpressionSizeLimit(4096), cel.ParserRecursionLimit(64))
	if err != nil {
		return "", err
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return "", errors.New("invalid OIDC username expression")
	}
	if ast.OutputType() != cel.StringType {
		return "", errors.New("OIDC username expression must return a string")
	}
	program, err := env.Program(ast, cel.CostLimit(10000), cel.InterruptCheckFrequency(100))
	if err != nil {
		return "", errors.New("invalid OIDC username program")
	}
	value, _, err := program.ContextEval(ctx, map[string]interface{}{"claims": claims})
	if err != nil {
		return "", errors.New("OIDC username evaluation failed")
	}
	name, ok := value.Value().(string)
	if !ok || name == "" || len(name) > 255 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "/\\") || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("invalid generated OIDC username")
	}
	return name, nil
}
