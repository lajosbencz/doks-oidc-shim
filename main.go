package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func main() {
	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	logger.Info("starting doks-oidc-shim",
		"listen", cfg.Listen,
		"oidc_issuer", cfg.OIDCIssuer,
		"k8s_api", cfg.K8sAPI,
		"groups_claim", cfg.GroupsClaim,
	)

	initCtx, initCancel := context.WithTimeout(context.Background(), cfg.OIDCInitTimeout)
	defer initCancel()
	provider, err := gooidc.NewProvider(initCtx, cfg.OIDCIssuer)
	if err != nil {
		logger.Error("failed to create OIDC provider", "err", err)
		os.Exit(1)
	}
	verify := newVerifyFunc(provider.Verifier(&gooidc.Config{ClientID: cfg.OIDCClientID}))

	target, err := url.Parse(cfg.K8sAPI)
	if err != nil {
		logger.Error("invalid k8s-api URL", "err", err)
		os.Exit(1)
	}

	caCert, err := os.ReadFile(cfg.K8sCAFile)
	if err != nil {
		logger.Error("reading K8s CA cert", "err", err)
		os.Exit(1)
	}

	proxy := buildProxy(cfg, target, caCert)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", handler(cfg, verify, proxy))

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
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "tls", cfg.TLSCertFile != "")
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
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "err", err)
			os.Exit(1)
		}
	case err := <-serveErr:
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
