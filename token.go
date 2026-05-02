package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// roleNameRe enforces ASCII-only names matching Kubernetes resource naming conventions
// (DNS label subset: max 63 chars, must start with alphanumeric). Consistent with docs/role-mapping.md.
var roleNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

func validRoleName(role string) error {
	if role == "" {
		return errors.New("empty role name")
	}
	if !roleNameRe.MatchString(role) {
		return fmt.Errorf("role name %q does not match [a-zA-Z0-9][a-zA-Z0-9_-]{0,62}", role)
	}
	return nil
}

func readSAToken(tokenDir, role string) (string, error) {
	if err := validRoleName(role); err != nil {
		return "", fmt.Errorf("invalid role: %w", err)
	}
	path := fmt.Sprintf("%s/%s/token", tokenDir, role)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading SA token for role %q: %w", role, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func roleFromClaims(claims map[string]any, groupsClaim string) string {
	v, ok := claims[groupsClaim]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case []any:
		if len(val) > 0 {
			if s, ok := val[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// jwtIssuerMatches decodes the JWT payload without verifying the signature and
// checks whether the iss claim matches the given issuer. Used only to distinguish
// "failed OIDC validation" from "structurally non-OIDC token" — never for authorization.
func jwtIssuerMatches(rawToken, issuer string) bool {
	parts := strings.SplitN(rawToken, ".", 3)
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	return claims.Iss == issuer
}
