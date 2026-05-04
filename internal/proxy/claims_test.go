package proxy

import (
	"encoding/base64"
	"testing"
)

func TestRoleFromClaims_StringClaim(t *testing.T) {
	groups := RoleFromClaims(map[string]any{"groups": "admin"}, "groups")
	if len(groups) != 1 || groups[0] != "admin" {
		t.Errorf("got %v, want [admin]", groups)
	}
}

func TestRoleFromClaims_SliceClaim(t *testing.T) {
	groups := RoleFromClaims(map[string]any{"groups": []any{"admins", "k8s-admin"}}, "groups")
	if len(groups) != 2 || groups[0] != "admins" || groups[1] != "k8s-admin" {
		t.Errorf("got %v, want [admins k8s-admin]", groups)
	}
}

func TestRoleFromClaims_MissingClaim(t *testing.T) {
	groups := RoleFromClaims(map[string]any{"email": "alice@example.com"}, "groups")
	if len(groups) != 0 {
		t.Errorf("got %v, want empty", groups)
	}
}

func TestRoleFromClaims_UnexpectedType(t *testing.T) {
	for _, val := range []any{42, true, map[string]any{}} {
		groups := RoleFromClaims(map[string]any{"groups": val}, "groups")
		if len(groups) != 0 {
			t.Errorf("claim value %T: got %v, want empty", val, groups)
		}
	}
}

func TestRoleFromClaims_EmptySlice(t *testing.T) {
	groups := RoleFromClaims(map[string]any{"groups": []any{}}, "groups")
	if len(groups) != 0 {
		t.Errorf("got %v, want empty", groups)
	}
}

func TestRoleFromClaims_MixedTypeSlice(t *testing.T) {
	groups := RoleFromClaims(map[string]any{"groups": []any{"admin", 42, "viewer"}}, "groups")
	if len(groups) != 2 || groups[0] != "admin" || groups[1] != "viewer" {
		t.Errorf("got %v, want [admin viewer]", groups)
	}
}

// --- JWTIssuerMatches ---

func TestJWTIssuerMatches_MatchingIssuer(t *testing.T) {
	token := fakeJWT(t, `{"iss":"https://issuer.example.com"}`)
	if !JWTIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected true for matching issuer")
	}
}

func TestJWTIssuerMatches_NonMatchingIssuer(t *testing.T) {
	token := fakeJWT(t, `{"iss":"https://other.example.com"}`)
	if JWTIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false for non-matching issuer")
	}
}

func TestJWTIssuerMatches_MissingIssClaim(t *testing.T) {
	token := fakeJWT(t, `{"sub":"alice"}`)
	if JWTIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false when iss claim is absent")
	}
}

func TestJWTIssuerMatches_NotAJWT(t *testing.T) {
	if JWTIssuerMatches("not-a-jwt", "https://issuer.example.com") {
		t.Error("expected false for non-JWT string")
	}
}

func TestJWTIssuerMatches_InvalidBase64Payload(t *testing.T) {
	if JWTIssuerMatches("header.!!!.sig", "https://issuer.example.com") {
		t.Error("expected false for invalid base64 payload")
	}
}

func TestJWTIssuerMatches_InvalidJSONPayload(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not-json`))
	token := "header." + payload + ".sig"
	if JWTIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false for invalid JSON payload")
	}
}
