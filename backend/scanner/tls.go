package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/yourusername/seagles/slog"
)

type TLSResult struct {
	SupportsTLS10 bool
	SupportsTLS11 bool
	SupportsTLS12 bool
	SupportsTLS13 bool
	WeakCiphers   []string
	CertExpired   bool
	CertError     string
}

var weakCipherNames = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:        "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:  "3DES-EDE-CBC-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:  "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "ECDHE-RSA-3DES-EDE-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:   "AES128-CBC-SHA (weak)",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:   "AES256-CBC-SHA (weak)",
}

func CheckTLS(ip string, port int) TLSResult {
	result := TLSResult{}
	addr := fmt.Sprintf("%s:%d", ip, port)

	versions := []struct {
		name   string
		ver    uint16
		target *bool
	}{
		{"TLS 1.0", tls.VersionTLS10, &result.SupportsTLS10},
		{"TLS 1.1", tls.VersionTLS11, &result.SupportsTLS11},
		{"TLS 1.2", tls.VersionTLS12, &result.SupportsTLS12},
		{"TLS 1.3", tls.VersionTLS13, &result.SupportsTLS13},
	}

	// Check TLS 1.0
	conn10, err10 := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	})
	if err10 == nil {
		result.SupportsTLS10 = true
		state := conn10.ConnectionState()
		for _, cipher := range state.CipherSuite {
			if name, ok := weakCipherNames[cipher]; ok {
				result.WeakCiphers = append(result.WeakCiphers, name)
			}
		}
		for _, cert := range state.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
		conn10.Close()
	}

	// Check TLS 1.1
	conn11, err11 := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	})
	if err11 == nil {
		result.SupportsTLS11 = true
		state := conn11.ConnectionState()
		for _, cipher := range state.CipherSuite {
			if name, ok := weakCipherNames[cipher]; ok {
				result.WeakCiphers = append(result.WeakCiphers, name)
			}
		}
		for _, cert := range state.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
		conn11.Close()
	}

	// Check TLS 1.2
	conn12, err12 := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err12 == nil {
		result.SupportsTLS12 = true
		state := conn12.ConnectionState()
		for _, cipher := range state.CipherSuite {
			if name, ok := weakCipherNames[cipher]; ok {
				result.WeakCiphers = append(result.WeakCiphers, name)
			}
		}
		for _, cert := range state.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
		conn12.Close()
	}

	// Check TLS 1.3
	conn13, err13 := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err13 == nil {
		result.SupportsTLS13 = true
		conn13.Close()
	}

	if result.SupportsTLS10 || result.SupportsTLS11 || len(result.WeakCiphers) > 0 {
		slog.Warn("Weak TLS detected", "ip", ip, "port", port,
			"tls10", result.SupportsTLS10,
			"tls11", result.SupportsTLS11,
			"weak_ciphers", len(result.WeakCiphers))
	}

	return result
}
