package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRedirectFollowingTransport_FollowsSameHostRedirect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis" {
			http.Redirect(w, r, "/apis/", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("final"))
	}))
	t.Cleanup(backend.Close)

	target, _ := url.Parse(backend.URL)
	tr := &redirectFollowingTransport{base: http.DefaultTransport, target: target}

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/apis", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "final" {
		t.Errorf("body = %q, want %q", string(body), "final")
	}
}

func TestRedirectFollowingTransport_CrossHostRedirectNotFollowed(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("external server must not be reached")
	}))
	t.Cleanup(external.Close)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL+"/other", http.StatusFound)
	}))
	t.Cleanup(backend.Close)

	target, _ := url.Parse(backend.URL)
	tr := &redirectFollowingTransport{base: http.DefaultTransport, target: target}

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect returned as-is)", resp.StatusCode)
	}
}

func TestRedirectFollowingTransport_NonGetNotFollowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusMovedPermanently)
	}))
	t.Cleanup(backend.Close)

	target, _ := url.Parse(backend.URL)
	tr := &redirectFollowingTransport{base: http.DefaultTransport, target: target}

	req, _ := http.NewRequest(http.MethodPost, backend.URL+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301 (POST redirect not followed)", resp.StatusCode)
	}
}

func TestRedirectFollowingTransport_LoopDetected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusMovedPermanently)
	}))
	t.Cleanup(backend.Close)

	target, _ := url.Parse(backend.URL)
	tr := &redirectFollowingTransport{base: http.DefaultTransport, target: target}

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/loop", nil)
	resp, err := tr.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Error("expected error for redirect loop, got nil")
	}
}
