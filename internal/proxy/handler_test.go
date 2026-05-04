package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestHandler_NonBearerAuthPassedThrough(t *testing.T) {
	// Schemes other than Bearer (e.g. Basic) must bypass OIDC verification entirely.
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		t.Error("verify must not be called for non-Bearer schemes")
		return nil, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if receivedAuth != "Basic dXNlcjpwYXNz" {
		t.Errorf("backend received %q, want original Basic auth header", receivedAuth)
	}
}

func TestHandler_ForeignIssuerJWTRejectedWhenPassthroughDisabled(t *testing.T) {
	// A JWT from a different issuer should be treated as non-OIDC.
	// With passthrough disabled it must be rejected with 401, not forwarded.
	upstream := testBackend(t, new(string))
	const configuredIssuer = "https://issuer.example.com"
	cfg := HandlerConfig{OIDCIssuer: configuredIssuer, GroupsClaim: "groups", AllowPassthrough: false}
	foreignToken := fakeJWT(t, `{"iss":"https://other.example.com","sub":"alice"}`)
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("unknown issuer")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer "+foreignToken)
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for foreign-issuer JWT with passthrough disabled", w.Code)
	}
}

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
	upstream := httputil.NewSingleHostReverseProxy(target)
	cfg := HandlerConfig{GroupsClaim: "groups", AllowPassthrough: true}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer sa-token")
	r.Header.Set("Impersonate-User", "system:admin")

	Handler(cfg, verify, upstream, testStore(nil))(httptest.NewRecorder(), r)

	if receivedHeader != "" {
		t.Errorf("Impersonate-User reached the backend: %q", receivedHeader)
	}
}

func TestHandler_NonOIDCTokenPassedThrough(t *testing.T) {
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	cfg := HandlerConfig{GroupsClaim: "groups", AllowPassthrough: true}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer in-cluster-sa-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if receivedAuth != "Bearer in-cluster-sa-token" {
		t.Errorf("backend received %q, want original SA token", receivedAuth)
	}
}

func TestHandler_NonJWTOpaqueTokenPassedThrough(t *testing.T) {
	// An opaque token (no dots) that fails verification must be forwarded unchanged —
	// it is structurally not a JWT and therefore not an OIDC token from our issuer.
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	cfg := HandlerConfig{OIDCIssuer: "https://issuer.example.com", GroupsClaim: "groups", AllowPassthrough: true}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("parse error: not a jwt")
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer opaque-sa-token-no-dots")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if receivedAuth != "Bearer opaque-sa-token-no-dots" {
		t.Errorf("backend received %q, want original opaque token", receivedAuth)
	}
}

func TestHandler_NonOIDCTokenRejectedWhenPassthroughDisabled(t *testing.T) {
	upstream := testBackend(t, new(string))
	cfg := HandlerConfig{OIDCIssuer: "https://issuer.example.com", GroupsClaim: "groups", AllowPassthrough: false}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer in-cluster-sa-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when passthrough is disabled", w.Code)
	}
}

func TestHandler_ExpiredOIDCTokenRejectedWith401(t *testing.T) {
	// A JWT from our issuer that fails verification (e.g. expired) must be rejected
	// with 401, not silently forwarded to the backend.
	upstream := testBackend(t, new(string))
	const issuer = "https://issuer.example.com"
	cfg := HandlerConfig{OIDCIssuer: issuer, GroupsClaim: "groups"}
	expiredToken := fakeJWT(t, `{"iss":"`+issuer+`","sub":"alice","exp":1}`)
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("token is expired")
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer "+expiredToken)
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for expired OIDC token", w.Code)
	}
}

func TestHandler_NoAuthHeaderPassedThrough(t *testing.T) {
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return nil, errors.New("not oidc")
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

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
	upstream := testBackend(t, &receivedAuth)
	store := testStore(map[string]string{"admin": "admin-sa-token"})
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin"}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, store)(w, r)

	if receivedAuth != "Bearer admin-sa-token" {
		t.Errorf("backend received %q, want SA token for lowercase bearer", receivedAuth)
	}
}

func TestHandler_OIDCTokenSwappedForSAToken(t *testing.T) {
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	store := testStore(map[string]string{"admin": "admin-sa-token"})
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin", "preferred_username": "alice"}, nil
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, store)(w, r)

	if receivedAuth != "Bearer admin-sa-token" {
		t.Errorf("backend received %q, want SA token", receivedAuth)
	}
}

func TestHandler_NoGroupsClaim_Returns403(t *testing.T) {
	upstream := testBackend(t, new(string))
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"sub": "alice"}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when no groups claim", w.Code)
	}
}

func TestHandler_FirstGroupWithTokenIsUsed(t *testing.T) {
	// User has groups [admins, k8s-admin]; only k8s-admin has a token.
	// The shim must skip admins and pick k8s-admin.
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	store := testStore(map[string]string{"k8s-admin": "k8s-admin-sa-token"})
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": []any{"admins", "k8s-admin"}}, nil
	}

	r := httptest.NewRequest("GET", "/api/v1/pods", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, store)(w, r)

	if receivedAuth != "Bearer k8s-admin-sa-token" {
		t.Errorf("backend received %q, want k8s-admin SA token", receivedAuth)
	}
}

func TestHandler_MissingSAToken_Returns403(t *testing.T) {
	upstream := testBackend(t, new(string))
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "admin"}, nil
	}

	r := httptest.NewRequest("GET", "/api/v1/secrets", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestHandler_UnknownRoleClaim_Returns403(t *testing.T) {
	upstream := testBackend(t, new(string))
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{"groups": "../etc/passwd"}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer oidc-id-token")
	w := httptest.NewRecorder()

	Handler(cfg, verify, upstream, testStore(nil))(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for unknown/malicious role claim", w.Code)
	}
}

func TestHandler_OIDCTokenNotLeakedToBackend(t *testing.T) {
	const oidcToken = "secret-oidc-id-token" //nolint:gosec
	var receivedAuth string
	upstream := testBackend(t, &receivedAuth)
	store := testStore(map[string]string{"view": "view-sa-token"})
	cfg := HandlerConfig{GroupsClaim: "groups"}
	verify := func(_ context.Context, _ string) (map[string]any, error) {
		return map[string]any{}, nil
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+oidcToken)
	Handler(cfg, verify, upstream, store)(httptest.NewRecorder(), r)

	if receivedAuth == "Bearer "+oidcToken {
		t.Error("OIDC token was forwarded to the backend unchanged")
	}
}
