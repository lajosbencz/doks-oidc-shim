package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	kubeproxy "k8s.io/apimachinery/pkg/util/proxy"
)

// impersonationHeaders lists fixed Kubernetes privilege-escalation headers.
// Verified complete as of k8s 1.30.
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authenticating-proxy
var impersonationHeaders = []string{
	"Impersonate-User",
	"Impersonate-Group",
	"Impersonate-Uid", // added in k8s 1.22
	"X-Remote-User",   // requestheader authenticating proxy
	"X-Remote-Group",  // requestheader authenticating proxy
}

// verifyFunc verifies a raw bearer token and returns its claims.
// Errors signal that the token is not a valid OIDC token — not a fatal condition.
type verifyFunc func(ctx context.Context, rawToken string) (map[string]any, error)

func newVerifyFunc(v *gooidc.IDTokenVerifier) verifyFunc {
	return func(ctx context.Context, rawToken string) (map[string]any, error) {
		idToken, err := v.Verify(ctx, rawToken)
		if err != nil {
			return nil, err
		}
		var claims map[string]any
		return claims, idToken.Claims(&claims)
	}
}

type proxyErrorResponder struct{}

func (proxyErrorResponder) Error(w http.ResponseWriter, r *http.Request, err error) {
	logger.Error("proxy error", "path", r.URL.Path, "err", err)
	http.Error(w, "upstream error", http.StatusBadGateway)
}

func buildProxy(cfg config, target *url.URL, caCert []byte) http.Handler {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.DialKeepAlive,
		}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		MaxIdleConns:          cfg.MaxIdleConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
	}

	h := kubeproxy.NewUpgradeAwareHandler(target, transport, false, false, proxyErrorResponder{})
	h.UseRequestLocation = true
	return h
}

// hasPrefixFold reports whether s has the given lowercase prefix,
// using ASCII case-folding without allocating.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := range len(prefix) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

func stripImpersonationHeaders(r *http.Request) {
	for _, h := range impersonationHeaders {
		r.Header.Del(h)
	}
	for key := range r.Header {
		if hasPrefixFold(key, "x-remote-extra-") || hasPrefixFold(key, "impersonate-extra-") {
			r.Header.Del(key)
		}
	}
}

func handler(cfg config, verify verifyFunc, proxy http.Handler) http.HandlerFunc {
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
				if jwtIssuerMatches(rawToken, cfg.OIDCIssuer) {
					logger.Warn("OIDC token validation failed, rejecting", "err", err)
					http.Error(w, "token validation failed", http.StatusUnauthorized)
					return
				}
				if !cfg.AllowPassthrough {
					logger.Warn("non-OIDC token rejected (passthrough disabled)", "err", err)
					http.Error(w, "non-OIDC token not accepted", http.StatusUnauthorized)
					return
				}
				// Structurally non-OIDC (opaque SA token, bootstrap token, etc.) — pass through.
				logger.Debug("non-OIDC token, passing through", "err", err)
				proxy.ServeHTTP(w, r)
				return
			}

			groups := roleFromClaims(claims, cfg.GroupsClaim)

			var role, saToken string
			for _, g := range groups {
				tok, err := readSAToken(cfg.TokenDir, g)
				if err == nil {
					role, saToken = g, tok
					break
				}
			}
			if role == "" {
				logger.Error("no SA token matched any group", "groups", groups)
				http.Error(w, "no SA token available for role", http.StatusForbidden)
				return
			}

			logger.Info("proxying authenticated request",
				"sub", claims["sub"],
				"username", claims["preferred_username"],
				"role", role,
				"path", r.URL.Path,
			)

			r.Header.Set("Authorization", "Bearer "+saToken)
		}

		proxy.ServeHTTP(w, r)
	}
}
