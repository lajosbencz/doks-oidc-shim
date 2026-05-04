// Package proxy implements the OIDC-aware reverse-proxy HTTP handler.
package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/lajosbencz/doks-oidc-shim/internal/tokenstore"
)

// VerifyFunc verifies a raw bearer token and returns its claims.
// Errors signal that the token is not a valid OIDC token — not a fatal condition.
type VerifyFunc func(ctx context.Context, rawToken string) (map[string]any, error)

// NewVerifyFunc adapts a *gooidc.IDTokenVerifier to a VerifyFunc.
func NewVerifyFunc(v *gooidc.IDTokenVerifier) VerifyFunc {
	return func(ctx context.Context, rawToken string) (map[string]any, error) {
		idToken, err := v.Verify(ctx, rawToken)
		if err != nil {
			return nil, err //nolint:wrapcheck // raw error needed by caller for issuer-match check
		}
		var claims map[string]any
		return claims, idToken.Claims(&claims) //nolint:wrapcheck
	}
}

// HandlerConfig is the subset of settings the HTTP handler consults per request.
type HandlerConfig struct {
	OIDCIssuer       string
	GroupsClaim      string
	AllowPassthrough bool
}

// Handler returns the http.HandlerFunc that performs OIDC verification, role
// resolution, token swap, and forwarding to the upstream proxy.
func Handler(cfg HandlerConfig, verify VerifyFunc, upstream http.Handler, store tokenstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stripImpersonationHeaders(r)

		// RFC 7235 §2.1: auth-scheme is case-insensitive.
		parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			rawToken := parts[1]
			claims, err := verify(r.Context(), rawToken)
			if err != nil {
				// If the token's iss matches our OIDC issuer it was intended for us — reject it
				// rather than silently forwarding an expired/revoked token.
				if JWTIssuerMatches(rawToken, cfg.OIDCIssuer) {
					slog.Warn("OIDC token validation failed, rejecting", "err", err)
					http.Error(w, "token validation failed", http.StatusUnauthorized)
					return
				}
				if !cfg.AllowPassthrough {
					slog.Warn("non-OIDC token rejected (passthrough disabled)", "err", err)
					http.Error(w, "non-OIDC token not accepted", http.StatusUnauthorized)
					return
				}
				// Structurally non-OIDC (opaque SA token, bootstrap token, etc.) — pass through.
				slog.Debug("non-OIDC token, passing through", "err", err)
				upstream.ServeHTTP(w, r)
				return
			}

			groups := RoleFromClaims(claims, cfg.GroupsClaim)

			var role, saToken string
			for _, g := range groups {
				tok, err := store.Get(r.Context(), g)
				if err == nil {
					role, saToken = g, tok
					break
				}
			}
			if role == "" {
				slog.Error("no SA token matched any group", "groups", groups)
				http.Error(w, "no SA token available for role", http.StatusForbidden)
				return
			}

			slog.Info("proxying authenticated request", "role", role, "path", r.URL.Path)
			slog.Debug("authenticated user", "sub", claims["sub"], "username", claims["preferred_username"])

			r.Header.Set("Authorization", "Bearer "+saToken)
		}

		upstream.ServeHTTP(w, r)
	}
}

// proxyErrorResponder satisfies kubeproxy's ErrorResponder interface.
type proxyErrorResponder struct{}

func (proxyErrorResponder) Error(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("proxy error", "path", r.URL.Path, "err", err)
	http.Error(w, "upstream error", http.StatusBadGateway)
}
