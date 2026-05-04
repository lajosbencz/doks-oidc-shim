package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/lajosbencz/doks-oidc-shim/internal/config"
	"github.com/lajosbencz/doks-oidc-shim/internal/proxy"
	"github.com/lajosbencz/doks-oidc-shim/internal/tokenstore"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the OIDC reverse proxy",
		RunE:  runProxy,
	}
	config.RegisterFlags(cmd)
	return cmd
}

func runProxy(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load(cmd)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	config.WarnZeroTimeouts(cfg)

	slog.Info("starting doks-oidc-shim",
		"listen", cfg.Listen,
		"oidc_issuer", cfg.OIDCIssuer,
		"k8s_api", cfg.K8sAPI,
		"groups_claim", cfg.GroupsClaim,
	)

	initCtx, initCancel := context.WithTimeout(context.Background(), cfg.OIDCInitTimeout)
	provider, err := gooidc.NewProvider(initCtx, cfg.OIDCIssuer)
	initCancel()
	if err != nil {
		return fmt.Errorf("creating OIDC provider: %w", err)
	}
	verify := proxy.NewVerifyFunc(provider.Verifier(&gooidc.Config{
		ClientID:          cfg.OIDCClientID,
		SkipClientIDCheck: cfg.OIDCSkipClientIDCheck,
	}))

	target, err := url.Parse(cfg.K8sAPI)
	if err != nil {
		return fmt.Errorf("invalid k8s-api URL: %w", err)
	}

	caCert, err := os.ReadFile(cfg.K8sCAFile)
	if err != nil {
		return fmt.Errorf("reading K8s CA cert: %w", err)
	}

	upstream, err := proxy.NewReverseProxy(proxy.TransportConfig{
		DialTimeout:           cfg.DialTimeout,
		DialKeepAlive:         cfg.DialKeepAlive,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		MaxIdleConns:          cfg.MaxIdleConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		FollowRedirects:       cfg.FollowRedirects,
	}, target, caCert)
	if err != nil {
		return fmt.Errorf("building proxy: %w", err)
	}

	store, err := buildStore(cfg)
	if err != nil {
		return fmt.Errorf("building token store: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", proxy.Handler(proxy.HandlerConfig{
		OIDCIssuer:       cfg.OIDCIssuer,
		GroupsClaim:      cfg.GroupsClaim,
		AllowPassthrough: cfg.AllowPassthrough,
	}, verify, upstream, store))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.Listen, "tls", cfg.TLSCertFile != "")
		var err error
		if cfg.TLSCertFile != "" {
			err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		stop()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		err := srv.Shutdown(shutdownCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	case err := <-serveErr:
		stop()
		return fmt.Errorf("server: %w", err)
	}

	return nil
}

func buildStore(cfg config.Config) (tokenstore.Store, error) {
	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("building in-cluster k8s config: %w", err)
	}
	client, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		return nil, fmt.Errorf("creating k8s client: %w", err)
	}

	ns := cfg.SANamespace
	if ns == "" {
		b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, fmt.Errorf("reading namespace file (set --sa-namespace explicitly): %w", err)
		}
		ns = string(b)
	}

	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}

	switch cfg.CacheStore {
	case "redis":
		store, err := tokenstore.NewRedisStore(client, ns, ttl, cfg.TokenAudiences, cfg.RedisAddr)
		if err != nil {
			return nil, fmt.Errorf("creating redis token store: %w", err)
		}
		return store, nil
	default:
		return tokenstore.NewInMemoryStore(client, ns, ttl, cfg.TokenAudiences, ttl/2), nil
	}
}
