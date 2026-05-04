package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidRoleName_PathTraversal(t *testing.T) {
	attacks := []string{
		"../etc/passwd",
		"../../root/.ssh/id_rsa",
		"view/../admin",
		"view/../../etc",
		"./view",
		"/etc/passwd",
	}
	for _, role := range attacks {
		if err := validRoleName(role); err == nil {
			t.Errorf("validRoleName(%q): expected error, got nil", role)
		}
	}
}

func TestValidRoleName_ShellUnsafe(t *testing.T) {
	attacks := []string{
		"view;rm -rf /",
		"view|cat /etc/passwd",
		"view$(whoami)",
		"view`id`",
		"view\x00admin",
		"view admin",
		"view\tadmin",
		"view\nadmin",
	}
	for _, role := range attacks {
		if err := validRoleName(role); err == nil {
			t.Errorf("validRoleName(%q): expected error, got nil", role)
		}
	}
}

func TestValidRoleName_ValidInputs(t *testing.T) {
	valid := []string{
		"view",
		"edit",
		"admin",
		"cluster-admin",
		"my_role",
		"role123",
		"ROLE",
		"role-1_A",
	}
	for _, role := range valid {
		if err := validRoleName(role); err != nil {
			t.Errorf("validRoleName(%q): unexpected error: %v", role, err)
		}
	}
}

func TestValidRoleName_Empty(t *testing.T) {
	if err := validRoleName(""); err == nil {
		t.Error("expected error for empty role name")
	}
}

func TestValidRoleName_UnicodeLettersRejected(t *testing.T) {
	// Homoglyph attacks via non-ASCII letters must be blocked — role names are
	// ASCII-only to match Kubernetes resource naming conventions.
	attacks := []string{
		"аdmin",  // Cyrillic 'а' instead of ASCII 'a'
		"admïn",  // Latin with diacritic
		"管理者",    // CJK
		"admin١", // Arabic-Indic digit
	}
	for _, role := range attacks {
		if err := validRoleName(role); err == nil {
			t.Errorf("validRoleName(%q): expected error for non-ASCII, got nil", role)
		}
	}
}

func TestValidRoleName_LeadingHyphenRejected(t *testing.T) {
	for _, role := range []string{"-role", "_role"} {
		if err := validRoleName(role); err == nil {
			t.Errorf("validRoleName(%q): expected error for leading punctuation, got nil", role)
		}
	}
}

func TestValidRoleName_TooLongRejected(t *testing.T) {
	role := strings.Repeat("a", 64)
	if err := validRoleName(role); err == nil {
		t.Errorf("validRoleName(64-char string): expected error, got nil")
	}
}

func TestValidRoleName_MaxLengthAccepted(t *testing.T) {
	role := strings.Repeat("a", 63)
	if err := validRoleName(role); err != nil {
		t.Errorf("validRoleName(63-char string): unexpected error: %v", err)
	}
}

func TestReadSAToken_PathTraversalBlocked(t *testing.T) {
	dir := t.TempDir()

	// plant a sensitive file one level up from tokenDir
	secret := filepath.Join(filepath.Dir(dir), "secret")
	_ = os.WriteFile(secret, []byte("sensitive"), 0o600)
	t.Cleanup(func() { _ = os.Remove(secret) })

	attempts := []string{
		"../secret",
		"../../etc/passwd",
		"view/../../secret",
	}
	for _, role := range attempts {
		_, err := readSAToken(dir, role)
		if err == nil {
			t.Errorf("readSAToken with role %q: expected error, got nil", role)
		}
	}
}

func TestReadSAToken_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, "view"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, "view", "token"), []byte("  mytoken\n"), 0o600)

	tok, err := readSAToken(dir, "view")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "mytoken" {
		t.Errorf("got %q, want %q", tok, "mytoken")
	}
}

func TestReadSAToken_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := readSAToken(dir, "nonexistent")
	if err == nil {
		t.Error("expected error for missing token file")
	}
}

func TestRoleFromClaims_StringClaim(t *testing.T) {
	groups := roleFromClaims(map[string]any{"groups": "admin"}, "groups")
	if len(groups) != 1 || groups[0] != "admin" {
		t.Errorf("got %v, want [admin]", groups)
	}
}

func TestRoleFromClaims_SliceClaim(t *testing.T) {
	groups := roleFromClaims(map[string]any{"groups": []any{"admins", "k8s-admin"}}, "groups")
	if len(groups) != 2 || groups[0] != "admins" || groups[1] != "k8s-admin" {
		t.Errorf("got %v, want [admins k8s-admin]", groups)
	}
}

func TestRoleFromClaims_MissingClaim(t *testing.T) {
	groups := roleFromClaims(map[string]any{"email": "alice@example.com"}, "groups")
	if len(groups) != 0 {
		t.Errorf("got %v, want empty", groups)
	}
}

func TestRoleFromClaims_UnexpectedType(t *testing.T) {
	// A numeric or boolean claim value must not produce a role — it should be
	// treated as absent so the caller can apply the safe default.
	for _, val := range []any{42, true, map[string]any{}} {
		groups := roleFromClaims(map[string]any{"groups": val}, "groups")
		if len(groups) != 0 {
			t.Errorf("claim value %T: got %v, want empty", val, groups)
		}
	}
}

func TestRoleFromClaims_EmptySlice(t *testing.T) {
	groups := roleFromClaims(map[string]any{"groups": []any{}}, "groups")
	if len(groups) != 0 {
		t.Errorf("got %v, want empty", groups)
	}
}

func TestRoleFromClaims_MixedTypeSlice(t *testing.T) {
	// Non-string items must be silently skipped; valid strings must be returned.
	groups := roleFromClaims(map[string]any{"groups": []any{"admin", 42, "viewer"}}, "groups")
	if len(groups) != 2 || groups[0] != "admin" || groups[1] != "viewer" {
		t.Errorf("got %v, want [admin viewer]", groups)
	}
}

// --- jwtIssuerMatches ---

func TestJWTIssuerMatches_MatchingIssuer(t *testing.T) {
	token := fakeJWT(t, `{"iss":"https://issuer.example.com"}`)
	if !jwtIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected true for matching issuer")
	}
}

func TestJWTIssuerMatches_NonMatchingIssuer(t *testing.T) {
	token := fakeJWT(t, `{"iss":"https://other.example.com"}`)
	if jwtIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false for non-matching issuer")
	}
}

func TestJWTIssuerMatches_MissingIssClaim(t *testing.T) {
	token := fakeJWT(t, `{"sub":"alice"}`)
	if jwtIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false when iss claim is absent")
	}
}

func TestJWTIssuerMatches_NotAJWT(t *testing.T) {
	if jwtIssuerMatches("not-a-jwt", "https://issuer.example.com") {
		t.Error("expected false for non-JWT string")
	}
}

func TestJWTIssuerMatches_InvalidBase64Payload(t *testing.T) {
	if jwtIssuerMatches("header.!!!.sig", "https://issuer.example.com") {
		t.Error("expected false for invalid base64 payload")
	}
}

func TestJWTIssuerMatches_InvalidJSONPayload(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not-json`))
	token := "header." + payload + ".sig"
	if jwtIssuerMatches(token, "https://issuer.example.com") {
		t.Error("expected false for invalid JSON payload")
	}
}
