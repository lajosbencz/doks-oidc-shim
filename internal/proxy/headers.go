package proxy

import "net/http"

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

func stripImpersonationHeaders(r *http.Request) {
	for _, h := range impersonationHeaders {
		r.Header.Del(h)
	}
	// Deleting during range is safe per Go spec — the removed key won't appear again.
	for key := range r.Header {
		if hasPrefixFold(key, "x-remote-extra-") || hasPrefixFold(key, "impersonate-extra-") {
			r.Header.Del(key)
		}
	}
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
