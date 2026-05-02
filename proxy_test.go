package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// --- stripImpersonationHeaders ---

func TestStripImpersonationHeaders_PrivilegeEscalationHeaders(t *testing.T) {
	dangerous := []string{
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"X-Remote-User",
		"X-Remote-Group",
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, h := range dangerous {
		r.Header.Set(h, "attacker-value")
	}
	stripImpersonationHeaders(r)
	for _, h := range dangerous {
		if r.Header.Get(h) != "" {
			t.Errorf("header %q was not stripped", h)
		}
	}
}

func TestStripImpersonationHeaders_WildcardExtraHeaders(t *testing.T) {
	// k8s honors X-Remote-Extra-* and Impersonate-Extra-* for extended
	// impersonation attributes — these must also be stripped.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Remote-Extra-Scopes", "admin")
	r.Header.Set("X-Remote-Extra-Groups", "system:masters")
	r.Header.Set("Impersonate-Extra-Uid", "1000")
	stripImpersonationHeaders(r)
	for _, h := range []string{"X-Remote-Extra-Scopes", "X-Remote-Extra-Groups", "Impersonate-Extra-Uid"} {
		if r.Header.Get(h) != "" {
			t.Errorf("wildcard header %q was not stripped", h)
		}
	}
}

func TestStripImpersonationHeaders_PreservesLegitimateHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	stripImpersonationHeaders(r)
	for _, h := range []string{"Authorization", "Content-Type", "Accept"} {
		if r.Header.Get(h) == "" {
			t.Errorf("legitimate header %q was incorrectly stripped", h)
		}
	}
}

// --- handler helpers ---

// testBackend returns a backend server that captures the Authorization header
// sent by the proxy into *receivedAuth.
func testBackend(t *testing.T, receivedAuth *string) (*httptest.Server, *url.URL, *httputil.ReverseProxy) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return srv, target, httputil.NewSingleHostReverseProxy(target)
}

func testTokenDir(t *testing.T, roles map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for role, token := range roles {
		_ = os.MkdirAll(filepath.Join(dir, role), 0o755)
		_ = os.WriteFile(filepath.Join(dir, role, "token"), []byte(token), 0o600)
	}
	return dir
}

// fakeJWT builds a syntactically valid JWT (header.payload.sig) with the given
// JSON payload. The signature is garbage so any real verifier will reject it.
func fakeJWT(t *testing.T, payloadJSON string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".invalidsignature"
}

// --- handler ---

func TestHandler_ImpersonationHeadersStrippedOnPassThrough(t *testing.T) {
	// Even when the token is not OIDC (pass-through path), impersonation headers
	// must be stripped before forwarding — the destination SA might have impersonate permissions.
	var receivedHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Impersonate-User")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	cfg := config{GroupsClaim: "groups", TokenDir: t.TempDir()}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer sa-token")
	r.Header.Set("Impersonate-User", "system:admin")

	handler(cfg, verify, proxy)(httptest.NewRecorder(), r)

	if receivedHeader != "" {
		t.Errorf("Impersonate-User reached the backend: %q", receivedHeader)
	}
}

func TestHandler_NonOIDCTokenPassedThrough(t *testing.T) {
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	cfg := config{GroupsClaim: "groups", TokenDir: t.TempDir()}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer in-cluster-sa-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if receivedAuth != "Bearer in-cluster-sa-token" {
		t.Errorf("backend received %q, want original SA token", receivedAuth)
	}
}

func TestHandler_NonJWTOpaqueTokenPassedThrough(t *testing.T) {
	// An opaque token (no dots) that fails verification must be forwarded unchanged —
	// it is structurally not a JWT and therefore not an OIDC token from our issuer.
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	cfg := config{OIDCIssuer: "https://issuer.example.com", GroupsClaim: "groups", TokenDir: t.TempDir()}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("parse error: not a jwt")
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer opaque-sa-token-no-dots")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if receivedAuth != "Bearer opaque-sa-token-no-dots" {
		t.Errorf("backend received %q, want original opaque token", receivedAuth)
	}
}

func TestHandler_ExpiredOIDCTokenRejectedWith401(t *testing.T) {
	// A JWT from our issuer that fails verification (e.g. expired) must be rejected
	// with 401, not silently forwarded to the backend.
	_, _, proxy := testBackend(t, new(string))
	const issuer = "https://issuer.example.com"
	cfg := config{OIDCIssuer: issuer, GroupsClaim: "groups", TokenDir: t.TempDir()}
	expiredToken := fakeJWT(t, `{"iss":"`+issuer+`","sub":"alice","exp":1}`)
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("token is expired")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for expired OIDC token", w.Code)
	}
}

func TestHandler_NoAuthHeaderPassedThrough(t *testing.T) {
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	cfg := config{GroupsClaim: "groups", TokenDir: t.TempDir()}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if receivedAuth != "" {
		t.Errorf("expected no Authorization header, got %q", receivedAuth)
	}
}

func TestHandler_LowercaseBearerVerified(t *testing.T) {
	// RFC 7235 §2.1: auth-scheme is case-insensitive — "bearer" must trigger OIDC verification.
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	dir := testTokenDir(t, map[string]string{"admin": "admin-sa-token"})
	cfg := config{GroupsClaim: "groups", TokenDir: dir}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin"}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer oidc-id-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if receivedAuth != "Bearer admin-sa-token" {
		t.Errorf("backend received %q, want SA token for lowercase bearer", receivedAuth)
	}
}

func TestHandler_OIDCTokenSwappedForSAToken(t *testing.T) {
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	dir := testTokenDir(t, map[string]string{"admin": "admin-sa-token"})
	cfg := config{GroupsClaim: "groups", TokenDir: dir}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin", "preferred_username": "alice"}, nil
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if receivedAuth != "Bearer admin-sa-token" {
		t.Errorf("backend received %q, want SA token", receivedAuth)
	}
}

func TestHandler_NoRoleClaimDefaultsToView(t *testing.T) {
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	dir := testTokenDir(t, map[string]string{"view": "view-sa-token"})
	cfg := config{GroupsClaim: "groups", TokenDir: dir}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"sub": "alice"}, nil // no groups claim
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if receivedAuth != "Bearer view-sa-token" {
		t.Errorf("backend received %q, want view SA token", receivedAuth)
	}
}

func TestHandler_MissingSATokenFile_Returns403(t *testing.T) {
	_, _, proxy := testBackend(t, new(string))
	cfg := config{
		GroupsClaim: "groups",
		TokenDir:    t.TempDir(), // empty — no token files
	}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin"}, nil
	}

	r := httptest.NewRequest("GET", "/api/v1/secrets", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandler_MaliciousRoleClaimBlocked(t *testing.T) {
	// An OIDC token with a crafted groups claim containing path traversal characters
	// must not reach the filesystem — it must be rejected with 403, not 500.
	_, _, proxy := testBackend(t, new(string))
	cfg := config{GroupsClaim: "groups", TokenDir: t.TempDir()}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "../etc/passwd"}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	handler(cfg, verify, proxy)(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for malicious role claim", w.Code)
	}
}

func TestHandler_OIDCTokenNotLeakedToBackend(t *testing.T) {
	// The original OIDC token must never reach the k8s API — only the SA token should.
	const oidcToken = "secret-oidc-id-token"
	var receivedAuth string
	_, _, proxy := testBackend(t, &receivedAuth)
	dir := testTokenDir(t, map[string]string{"view": "view-sa-token"})
	cfg := config{GroupsClaim: "groups", TokenDir: dir}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+oidcToken)
	handler(cfg, verify, proxy)(httptest.NewRecorder(), r)

	if receivedAuth == "Bearer "+oidcToken {
		t.Error("OIDC token was forwarded to the backend unchanged")
	}
}
