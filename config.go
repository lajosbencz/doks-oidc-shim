package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/peterbourgon/ff/v4"
)

type config struct {
	Listen           string        `ff:"long: listen, default: :8080, usage: address to listen on"`
	TLSCertFile      string        `ff:"long: tls-cert-file, usage: path to TLS certificate file; enables TLS when set together with tls-key-file"`
	TLSKeyFile       string        `ff:"long: tls-key-file, usage: path to TLS private key file; enables TLS when set together with tls-cert-file"`
	OIDCIssuer       string        `ff:"long: oidc-issuer, usage: OIDC issuer URL (required)"`
	OIDCClientID     string        `ff:"long: oidc-client-id, usage: OIDC client ID (required)"`
	OIDCInitTimeout  time.Duration `ff:"long: oidc-init-timeout, default: 30s, usage: max time to fetch OIDC discovery and JWKS at startup"`
	GroupsClaim      string        `ff:"long: groups-claim, default: groups, usage: JWT claim mapped to SA role"`
	AllowPassthrough bool          `ff:"long: allow-passthrough, default: false, usage: forward non-OIDC bearer tokens to the k8s API unchanged; if false (default) non-OIDC tokens are rejected with 401"`
	FollowRedirects  bool          `ff:"long: follow-redirects, default: false, usage: follow same-host 3xx redirects inside the transport instead of returning them to the client"`
	K8sAPI           string        `ff:"long: k8s-api, usage: Kubernetes API server URL; derived from KUBERNETES_SERVICE_HOST/PORT if unset"`
	K8sCAFile        string        `ff:"long: k8s-ca-file, default: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt, usage: path to K8s cluster CA certificate"`
	TokenDir         string        `ff:"long: token-dir, default: /var/run/secrets/tokens, usage: directory containing per-role SA token subdirectories"`
	ConfigFile       string        `ff:"long: config, usage: path to config file (plain key=value format)"`

	ReadHeaderTimeout time.Duration `ff:"long: read-header-timeout, default: 10s, usage: max time to read request headers"`
	ReadTimeout       time.Duration `ff:"long: read-timeout, default: 30s, usage: max time to read an entire request"`
	WriteTimeout      time.Duration `ff:"long: write-timeout, default: 60s, usage: max time to write a response"`
	IdleTimeout       time.Duration `ff:"long: idle-timeout, default: 120s, usage: max keep-alive idle time between requests"`

	DialTimeout           time.Duration `ff:"long: dial-timeout, default: 10s, usage: max time to establish a TCP connection to the upstream"`
	DialKeepAlive         time.Duration `ff:"long: dial-keep-alive, default: 30s, usage: interval between TCP keep-alive probes to the upstream"`
	TLSHandshakeTimeout   time.Duration `ff:"long: tls-handshake-timeout, default: 10s, usage: max time for the upstream TLS handshake"`
	ResponseHeaderTimeout time.Duration `ff:"long: response-header-timeout, default: 30s, usage: max time to wait for upstream response headers after the request is sent"`
	IdleConnTimeout       time.Duration `ff:"long: idle-conn-timeout, default: 90s, usage: max time an idle upstream connection is kept in the pool"`
	MaxIdleConns          int           `ff:"long: max-idle-conns, default: 100, usage: max idle upstream connections across all hosts"`

	ShutdownTimeout time.Duration `ff:"long: shutdown-timeout, default: 10s, usage: max time to wait for in-flight requests to complete on shutdown"`
	MaxHeaderBytes  int           `ff:"long: max-header-bytes, default: 262144, usage: max bytes the server reads parsing request headers (default 256 KiB)"`
}

func warnZeroTimeouts(cfg config) {
	timeouts := []struct {
		name  string
		value time.Duration
	}{
		{"read-header-timeout", cfg.ReadHeaderTimeout},
		{"read-timeout", cfg.ReadTimeout},
		{"write-timeout", cfg.WriteTimeout},
		{"idle-timeout", cfg.IdleTimeout},
		{"dial-timeout", cfg.DialTimeout},
		{"tls-handshake-timeout", cfg.TLSHandshakeTimeout},
		{"response-header-timeout", cfg.ResponseHeaderTimeout},
		{"shutdown-timeout", cfg.ShutdownTimeout},
	}
	for _, t := range timeouts {
		if t.value <= 0 {
			logger.Warn("timeout is zero or less", "field", t.name)
		}
	}
}

func loadConfig(args []string) (config, error) {
	var cfg config
	fs := ff.NewFlagSetFrom("doks-oidc-shim", &cfg)

	if err := ff.Parse(fs, args,
		ff.WithEnvVars(),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		ff.WithConfigAllowMissingFile(),
	); err != nil {
		return config{}, fmt.Errorf("parsing config: %w", err)
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return config{}, errors.New("tls-cert-file and tls-key-file must both be set or both be unset")
	}

	if cfg.OIDCIssuer == "" {
		return config{}, errors.New("oidc-issuer / OIDC_ISSUER is required")
	}
	if cfg.OIDCClientID == "" {
		return config{}, errors.New("oidc-client-id / OIDC_CLIENT_ID is required")
	}

	if cfg.K8sAPI == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return config{}, errors.New("k8s-api / K8S_API or KUBERNETES_SERVICE_HOST/PORT must be set")
		}
		// net.JoinHostPort brackets IPv6 addresses correctly per RFC 3986 §3.2.2.
		cfg.K8sAPI = "https://" + net.JoinHostPort(host, port)
	}

	return cfg, nil
}
