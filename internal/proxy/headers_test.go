package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestStripImpersonationHeaders_PrivilegeEscalationHeaders(t *testing.T) {
	dangerous := []string{
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"X-Remote-User",
		"X-Remote-Group",
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, h := range dangerous {
		r.Header.Set(h, "attacker-value")
	}
	stripImpersonationHeaders(r)
	for _, h := range dangerous {
		if r.Header.Get(h) != "" {
			t.Errorf("header %q was not stripped", h)
		}
	}
}

func TestStripImpersonationHeaders_WildcardExtraHeaders(t *testing.T) {
	// k8s honors X-Remote-Extra-* and Impersonate-Extra-* for extended
	// impersonation attributes — these must also be stripped.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Remote-Extra-Scopes", "admin")
	r.Header.Set("X-Remote-Extra-Groups", "system:masters")
	r.Header.Set("Impersonate-Extra-Uid", "1000")
	stripImpersonationHeaders(r)
	for _, h := range []string{"X-Remote-Extra-Scopes", "X-Remote-Extra-Groups", "Impersonate-Extra-Uid"} {
		if r.Header.Get(h) != "" {
			t.Errorf("wildcard header %q was not stripped", h)
		}
	}
}

func TestStripImpersonationHeaders_PreservesLegitimateHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	stripImpersonationHeaders(r)
	for _, h := range []string{"Authorization", "Content-Type", "Accept"} {
		if r.Header.Get(h) == "" {
			t.Errorf("legitimate header %q was incorrectly stripped", h)
		}
	}
}
