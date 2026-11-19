package alerts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ValidateWebhookTarget rejects webhook destinations that point at private,
// loopback, link-local or otherwise non-public addresses. Without this an
// admin-configured webhook can be used to reach internal services (cloud
// metadata endpoints, localhost admin ports) from the backend's network.
//
// WEBHOOK_ALLOW_PRIVATE_TARGETS=true is an explicit development escape hatch
// for local testing; it is never enabled by the shipped deployment configs.
func ValidateWebhookTarget(raw, webhookType string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	allowed := map[string]bool{"http": true, "https": true}
	if strings.EqualFold(webhookType, "syslog") {
		allowed = map[string]bool{"udp": true, "tcp": true}
	}
	scheme := strings.ToLower(u.Scheme)
	if !allowed[scheme] {
		return fmt.Errorf("unsupported webhook scheme %q for type %q", u.Scheme, webhookType)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("webhook URL has no host")
	}
	if u.User != nil {
		return fmt.Errorf("webhook URL must not contain credentials")
	}
	if strings.EqualFold(os.Getenv("WEBHOOK_ALLOW_PRIVATE_TARGETS"), "true") {
		return nil
	}

	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return fmt.Errorf("cannot resolve webhook host %q: %w", u.Hostname(), err)
	}
	for _, ip := range ips {
		if isPrivateOrLocalIP(ip) {
			return fmt.Errorf("webhook target %q resolves to a private or local address", u.Hostname())
		}
	}
	return nil
}

func isPrivateOrLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast()
}
