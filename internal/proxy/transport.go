package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	kubeproxy "k8s.io/apimachinery/pkg/util/proxy"
)

const maxRedirects = 10

// TransportConfig is the subset of settings used to construct the upstream
// HTTP transport and reverse-proxy handler.
type TransportConfig struct {
	DialTimeout           time.Duration
	DialKeepAlive         time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	MaxIdleConns          int
	IdleConnTimeout       time.Duration
	FollowRedirects       bool
}

// NewReverseProxy builds a tuned http.Handler that proxies to target, using
// caCert (appended to the system pool) for upstream TLS verification.
func NewReverseProxy(cfg TransportConfig, target *url.URL, caCert []byte) (http.Handler, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system cert pool: %w", err)
	}
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
		MaxIdleConnsPerHost:   cfg.MaxIdleConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
	}

	// UpgradeAwareHandler generates a spurious 301 for every path-less GET when
	// loc.Path == "" (see upgradeaware.go proxyRedirectsForRootPath). Cloning the
	// URL and setting Path="/" suppresses it; UseRequestLocation=true means the
	// actual request path is taken from req.URL, so routing is unaffected.
	loc := *target
	if loc.Path == "" {
		loc.Path = "/"
	}
	var rt http.RoundTripper = transport
	if cfg.FollowRedirects {
		rt = &redirectFollowingTransport{base: transport, target: &loc}
	}
	h := kubeproxy.NewUpgradeAwareHandler(&loc, rt, false, false, proxyErrorResponder{})
	h.UseRequestLocation = true
	return h, nil
}

// redirectFollowingTransport follows same-host 3xx redirects internally so
// they never reach the browser — browser cookies scoped to a sub-path would
// otherwise be dropped, breaking cookie-authenticated UIs like Headlamp.
// Only GET and HEAD are followed; other methods are returned as-is to avoid
// consuming an already-drained request body.
type redirectFollowingTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t *redirectFollowingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req) //nolint:wrapcheck // pass-through of interface method
	}
	for range maxRedirects {
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err //nolint:wrapcheck // pass-through of interface method
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}
		next, err := url.Parse(loc)
		if err != nil {
			return resp, nil
		}
		next = req.URL.ResolveReference(next)
		if next.Host != t.target.Host {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		clone := req.Clone(req.Context())
		clone.URL = next
		clone.RequestURI = ""
		req = clone
	}
	return nil, fmt.Errorf("redirect loop: exceeded %d hops", maxRedirects)
}
