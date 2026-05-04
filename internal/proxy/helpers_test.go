package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"github.com/lajosbencz/doks-oidc-shim/internal/tokenstore"
)

// testBackend returns a backend server that captures the Authorization header
// sent by the proxy into *receivedAuth.
func testBackend(t *testing.T, receivedAuth *string) *httputil.ReverseProxy {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	return httputil.NewSingleHostReverseProxy(target)
}

// mockStore is a test double for tokenstore.Store backed by an in-memory map.
type mockStore struct {
	tokens map[string]string
}

func (m *mockStore) Get(_ context.Context, role string) (string, error) {
	tok, ok := m.tokens[role]
	if !ok {
		return "", tokenstore.ErrNoSAFound
	}
	return tok, nil
}

// testStore returns a Store pre-loaded with the given role→token map.
func testStore(roles map[string]string) tokenstore.Store {
	return &mockStore{tokens: roles}
}

// fakeJWT builds a syntactically valid JWT (header.payload.sig) with the given
// JSON payload. The signature is garbage so any real verifier will reject it.
func fakeJWT(t *testing.T, payloadJSON string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".invalidsignature"
}
