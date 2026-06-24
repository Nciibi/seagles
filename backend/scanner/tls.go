package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"
)

// TLSResult contains the results of a TLS configuration check.
type TLSResult struct {
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	SupportsTLS10 bool      `json:"supports_tls10"`
	SupportsTLS11 bool      `json:"supports_tls11"`
	SupportsTLS12 bool      `json:"supports_tls12"`
	SupportsTLS13 bool      `json:"supports_tls13"`
	CertExpiry    time.Time `json:"cert_expiry"`
	CertExpired   bool      `json:"cert_expired"`
	SelfSigned    bool      `json:"self_signed"`
	WeakCiphers   []string  `json:"weak_ciphers"`
}

// CheckTLS tests TLS configuration on a given host and port.
func CheckTLS(host string, port int) TLSResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	result := TLSResult{
		Host:        host,
		Port:        port,
		WeakCiphers: []string{},
	}

	// Test each TLS version
	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	for _, v := range versions {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.version,
			MaxVersion:         v.version,
		}

		dialer := &tls.Dialer{
			Config: cfg,
		}

		conn, err := dialer.DialContext(nil, "tcp", addr)
		if conn != nil {
			conn.Close()
		}

		if err == nil {
			switch v.version {
			case tls.VersionTLS10:
				result.SupportsTLS10 = true
				log.Printf("[TLS] %s supports deprecated TLS 1.0", addr)
			case tls.VersionTLS11:
				result.SupportsTLS11 = true
				log.Printf("[TLS] %s supports deprecated TLS 1.1", addr)
			case tls.VersionTLS12:
				result.SupportsTLS12 = true
			case tls.VersionTLS13:
				result.SupportsTLS13 = true
			}
		}
	}

	// Attempt a full TLS connection to inspect certificate and cipher
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net_Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	weakPatterns := []string{"RC4", "DES", "3DES", "MD5"}
	for _, pattern := range weakPatterns {
		if strings.Contains(strings.ToUpper(cipherName), pattern) {
			result.WeakCiphers = append(result.WeakCiphers, cipherName)
			break
		}
	}

	// Inspect certificate chain
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertExpiry = cert.NotAfter
		result.CertExpired = time.Now().After(cert.NotAfter)

		// Check if self-signed: issuer == subject
		result.SelfSigned = cert.Issuer.String() == cert.Subject.String()

		// Also check if cert is expiring within 30 days
		if !result.CertExpired && time.Until(cert.NotAfter) < 30*24*time.Hour {
			log.Printf("[TLS] Certificate on %s expiring within 30 days", addr)
		}
	}

	return result
}
