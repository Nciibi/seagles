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

	_, err = resolvePublicIPs(u.Hostname())
	return err
}

// resolvePublicIPs resolves host and rejects it if any answer is private,
// loopback, link-local or otherwise non-public. Returning the addresses lets
// callers dial the validated IP directly instead of re-resolving the hostname
// (which would allow DNS rebinding between validation and connect).
func resolvePublicIPs(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve webhook host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook host %q has no addresses", host)
	}
	for _, ip := range ips {
		if isPrivateOrLocalIP(ip) {
			return nil, fmt.Errorf("webhook target %q resolves to a private or local address", host)
		}
	}
	return ips, nil
}

// webhookDialContext validates DNS on every connection and dials the validated
// IP. This closes both the redirect bypass (a redirect to localhost) and the
// DNS-rebinding window between ValidateWebhookTarget and the actual connect.
func webhookDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if strings.EqualFold(os.Getenv("WEBHOOK_ALLOW_PRIVATE_TARGETS"), "true") {
		return dialer.DialContext(ctx, network, addr)
	}

	ips, err := resolvePublicIPs(host)
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// webhookHTTPClient is shared so idle connections are reused and no transport
// is leaked per delivery. Redirects are deliberately NOT followed: a public
// URL must not be able to bounce an authenticated webhook into an internal
// service. ProxyFromEnvironment is intentionally omitted — a proxy would
// resolve the destination itself, bypassing the pinned, validated dial.
var webhookHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		DialContext:     webhookDialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

func isPrivateOrLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast()
}
