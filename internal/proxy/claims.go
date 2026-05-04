package proxy

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// RoleFromClaims extracts string values from the named groups claim.
// Returns the values in claim order; non-string entries are skipped.
func RoleFromClaims(claims map[string]any, groupsClaim string) []string {
	v, ok := claims[groupsClaim]
	if !ok {
		return []string{}
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		groups := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	}
	return []string{}
}

// JWTIssuerMatches decodes the JWT payload without verifying the signature and
// checks whether the iss claim matches the given issuer. Used only to distinguish
// "failed OIDC validation" from "structurally non-OIDC token" — never for authorization.
func JWTIssuerMatches(rawToken, issuer string) bool {
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
