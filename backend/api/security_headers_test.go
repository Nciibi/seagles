package api

import (
	"strings"
	"testing"
)

func TestContentSecurityPolicy(t *testing.T) {
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: blob:",
		"connect-src 'self' ws: wss:",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(contentSecurityPolicy, want) {
			t.Errorf("contentSecurityPolicy missing %q", want)
		}
	}

	for _, directive := range strings.Split(contentSecurityPolicy, ";") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "script-src") && strings.Contains(directive, "unsafe-inline") {
			t.Errorf("script-src must not allow inline scripts: %q", directive)
		}
	}
}
