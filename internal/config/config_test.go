package config

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newTestCmd builds a cobra command with all proxy flags registered, suitable
// for passing to Load() in tests.
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	RegisterFlags(cmd)
	return cmd
}

// setBaseEnv configures the minimum valid environment for Load tests.
// Individual tests override specific fields to exercise their scenario.
func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("OIDC_CLIENT_ID", "client")
	t.Setenv("K8S_API", "https://k8s.example.com")
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
}

func TestLoad_RequiresOIDCIssuer(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("OIDC_ISSUER", "")

	_, err := Load(newTestCmd())
	if err == nil || !strings.Contains(err.Error(), "OIDC_ISSUER") {
		t.Errorf("expected OIDC_ISSUER error, got: %v", err)
	}
}

func TestLoad_RequiresOIDCClientID(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("OIDC_CLIENT_ID", "")

	_, err := Load(newTestCmd())
	if err == nil || !strings.Contains(err.Error(), "OIDC_CLIENT_ID") {
		t.Errorf("expected OIDC_CLIENT_ID error, got: %v", err)
	}
}

func TestLoad_RequiresK8sAPI(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := Load(newTestCmd())
	if err == nil {
		t.Error("expected error when no K8s API address available")
	}
}

func TestLoad_K8sAPIDerivedFromServiceEnv(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	cfg, err := Load(newTestCmd())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K8sAPI != "https://10.0.0.1:443" {
		t.Errorf("K8sAPI = %q, want https://10.0.0.1:443", cfg.K8sAPI)
	}
}

func TestLoad_K8sAPIDerivedFromIPv6ServiceEnv(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	cfg, err := Load(newTestCmd())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K8sAPI != "https://[::1]:443" {
		t.Errorf("K8sAPI = %q, want https://[::1]:443", cfg.K8sAPI)
	}
}

func TestLoad_K8sAPIDerivedFromIPv6FullAddr(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00:dead:beef::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	cfg, err := Load(newTestCmd())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K8sAPI != "https://[fd00:dead:beef::1]:6443" {
		t.Errorf("K8sAPI = %q, want https://[fd00:dead:beef::1]:6443", cfg.K8sAPI)
	}
}

func TestLoad_TLSCertWithoutKeyRejected(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
	t.Setenv("TLS_KEY_FILE", "")

	_, err := Load(newTestCmd())
	if err == nil {
		t.Error("expected error when tls-cert-file is set but tls-key-file is not")
	}
}

func TestLoad_TLSKeyWithoutCertRejected(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "/path/to/key.pem")

	_, err := Load(newTestCmd())
	if err == nil {
		t.Error("expected error when tls-key-file is set but tls-cert-file is not")
	}
}

func TestLoad_K8sAPIServiceHostWithoutPort(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := Load(newTestCmd())
	if err == nil {
		t.Error("expected error when KUBERNETES_SERVICE_HOST is set but KUBERNETES_SERVICE_PORT is missing")
	}
}

func TestLoad_AllowPassthroughDefaultsFalse(t *testing.T) {
	setBaseEnv(t)

	cfg, err := Load(newTestCmd())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllowPassthrough {
		t.Error("AllowPassthrough should default to false")
	}
}

func TestLoad_ExplicitK8sAPITakesPrecedence(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("K8S_API", "https://explicit.example.com:6443")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	cfg, err := Load(newTestCmd())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.K8sAPI != "https://explicit.example.com:6443" {
		t.Errorf("K8sAPI = %q, want explicit value", cfg.K8sAPI)
	}
}
