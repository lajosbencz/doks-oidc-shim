// Package config defines the proxy's configuration struct, CLI flag registration,
// and viper-backed loading from flags + environment variables + config files.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Config holds all proxy command settings. Populated by Load().
type Config struct {
	Listen                string
	TLSCertFile           string
	TLSKeyFile            string
	OIDCIssuer            string
	OIDCClientID          string
	OIDCInitTimeout       time.Duration
	OIDCSkipClientIDCheck bool
	GroupsClaim           string
	AllowPassthrough      bool
	FollowRedirects       bool
	K8sAPI                string
	K8sCAFile             string
	SANamespace           string
	TokenTTL              time.Duration
	TokenAudiences        []string
	CacheStore            string
	RedisAddr             string

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	DialTimeout           time.Duration
	DialKeepAlive         time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConns          int

	ShutdownTimeout time.Duration
	MaxHeaderBytes  int
}

// RegisterFlags declares all proxy flags on cmd. Defaults match production-sane values.
func RegisterFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("config", "", "path to config file (YAML, TOML, or JSON)")
	f.String("listen", ":8080", "address to listen on")
	f.String("tls-cert-file", "", "path to TLS certificate file; enables TLS when set with --tls-key-file")
	f.String("tls-key-file", "", "path to TLS private key file; enables TLS when set with --tls-cert-file")
	f.String("oidc-issuer", "", "OIDC issuer URL (required)")
	f.String("oidc-client-id", "", "OIDC client ID (required)")
	f.Duration("oidc-init-timeout", 30*time.Second, "max time to fetch OIDC discovery and JWKS at startup")
	f.Bool("oidc-skip-client-id-check", false, "skip validating token audience against the client ID; accepts tokens from any client of the issuer")
	f.String("groups-claim", "groups", "JWT claim mapped to SA role")
	f.Bool("allow-passthrough", false, "forward non-OIDC bearer tokens to the k8s API unchanged; if false non-OIDC tokens are rejected with 401")
	f.Bool("follow-redirects", false, "follow same-host 3xx redirects inside the transport instead of returning them to the client")
	f.String("k8s-api", "", "Kubernetes API server URL; derived from KUBERNETES_SERVICE_HOST/PORT if unset")
	f.String("k8s-ca-file", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "path to K8s cluster CA certificate")
	f.String("sa-namespace", "", "namespace where role ServiceAccounts live; defaults to the proxy's own namespace")
	f.Duration("token-ttl", time.Hour, "requested lifetime for TokenRequest tokens")
	f.StringSlice("token-audience", []string{"https://kubernetes.default.svc"}, "audiences requested in TokenRequest (comma-separated)")
	f.String("cache-store", "memory", "token cache backend: memory or redis")
	f.String("redis-addr", "localhost:6379", "Redis address (host:port) when cache-store=redis")
	f.Duration("read-header-timeout", 10*time.Second, "max time to read request headers")
	f.Duration("read-timeout", 30*time.Second, "max time to read an entire request")
	f.Duration("write-timeout", 60*time.Second, "max time to write a response")
	f.Duration("idle-timeout", 120*time.Second, "max keep-alive idle time between requests")
	f.Duration("dial-timeout", 10*time.Second, "max time to establish a TCP connection to the upstream")
	f.Duration("dial-keep-alive", 30*time.Second, "interval between TCP keep-alive probes to the upstream")
	f.Duration("tls-handshake-timeout", 10*time.Second, "max time for the upstream TLS handshake")
	f.Duration("response-header-timeout", 30*time.Second, "max time to wait for upstream response headers after the request is sent")
	f.Duration("idle-conn-timeout", 90*time.Second, "max time an idle upstream connection is kept in the pool")
	f.Int("max-idle-conns", 100, "max idle upstream connections across all hosts")
	f.Duration("shutdown-timeout", 10*time.Second, "max time to wait for in-flight requests to complete on shutdown")
	f.Int("max-header-bytes", 262144, "max bytes the server reads parsing request headers (256 KiB)")
}

// Load reads flags + environment + optional config file and returns a validated Config.
func Load(cmd *cobra.Command) (Config, error) {
	v := viper.New()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return Config{}, fmt.Errorf("binding flags: %w", err)
	}

	if cfgFile := v.GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("reading config file: %w", err)
		}
	}

	cfg := Config{
		Listen:                v.GetString("listen"),
		TLSCertFile:           v.GetString("tls-cert-file"),
		TLSKeyFile:            v.GetString("tls-key-file"),
		OIDCIssuer:            v.GetString("oidc-issuer"),
		OIDCClientID:          v.GetString("oidc-client-id"),
		OIDCInitTimeout:       v.GetDuration("oidc-init-timeout"),
		OIDCSkipClientIDCheck: v.GetBool("oidc-skip-client-id-check"),
		GroupsClaim:           v.GetString("groups-claim"),
		AllowPassthrough:      v.GetBool("allow-passthrough"),
		FollowRedirects:       v.GetBool("follow-redirects"),
		K8sAPI:                v.GetString("k8s-api"),
		K8sCAFile:             v.GetString("k8s-ca-file"),
		SANamespace:           v.GetString("sa-namespace"),
		TokenTTL:              v.GetDuration("token-ttl"),
		TokenAudiences:        v.GetStringSlice("token-audience"),
		CacheStore:            v.GetString("cache-store"),
		RedisAddr:             v.GetString("redis-addr"),
		ReadHeaderTimeout:     v.GetDuration("read-header-timeout"),
		ReadTimeout:           v.GetDuration("read-timeout"),
		WriteTimeout:          v.GetDuration("write-timeout"),
		IdleTimeout:           v.GetDuration("idle-timeout"),
		DialTimeout:           v.GetDuration("dial-timeout"),
		DialKeepAlive:         v.GetDuration("dial-keep-alive"),
		TLSHandshakeTimeout:   v.GetDuration("tls-handshake-timeout"),
		ResponseHeaderTimeout: v.GetDuration("response-header-timeout"),
		IdleConnTimeout:       v.GetDuration("idle-conn-timeout"),
		MaxIdleConns:          v.GetInt("max-idle-conns"),
		ShutdownTimeout:       v.GetDuration("shutdown-timeout"),
		MaxHeaderBytes:        v.GetInt("max-header-bytes"),
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, errors.New("tls-cert-file and tls-key-file must both be set or both be unset")
	}
	if cfg.OIDCIssuer == "" {
		return Config{}, errors.New("oidc-issuer / OIDC_ISSUER is required")
	}
	if cfg.OIDCClientID == "" {
		return Config{}, errors.New("oidc-client-id / OIDC_CLIENT_ID is required")
	}
	if cfg.K8sAPI == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return Config{}, errors.New("k8s-api / K8S_API or KUBERNETES_SERVICE_HOST/PORT must be set")
		}
		// net.JoinHostPort brackets IPv6 addresses correctly per RFC 3986 §3.2.2.
		cfg.K8sAPI = "https://" + net.JoinHostPort(host, port)
	}

	return cfg, nil
}

// WarnZeroTimeouts emits a warning for any timeout that is zero or negative,
// flagging configurations that disable Slowloris and similar protections.
func WarnZeroTimeouts(cfg Config) {
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
			slog.Warn("timeout is zero or less", "field", t.name)
		}
	}
}
