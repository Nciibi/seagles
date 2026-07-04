package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
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
	tls.TLS_RSA_WITH_RC4_128_SHA:                "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:          "3DES-EDE-CBC-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:         "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:       "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:    "ECDHE-RSA-3DES-EDE-CBC-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:           "AES128-CBC-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:           "AES256-CBC-SHA",
}

func scanTLSVersion(addr string, version uint16) (bool, *tls.ConnectionState) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return true, &state
}

func CheckTLS(ip string, port int) TLSResult {
	result := TLSResult{}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	supported10, state10 := scanTLSVersion(addr, tls.VersionTLS10)
	if supported10 {
		result.SupportsTLS10 = true
		if name, ok := weakCipherNames[state10.CipherSuite]; ok {
			result.WeakCiphers = append(result.WeakCiphers, name)
		}
		for _, cert := range state10.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
	}

	supported11, state11 := scanTLSVersion(addr, tls.VersionTLS11)
	if supported11 {
		result.SupportsTLS11 = true
		if name, ok := weakCipherNames[state11.CipherSuite]; ok {
			result.WeakCiphers = append(result.WeakCiphers, name)
		}
		for _, cert := range state11.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
	}

	supported12, state12 := scanTLSVersion(addr, tls.VersionTLS12)
	if supported12 {
		result.SupportsTLS12 = true
		if name, ok := weakCipherNames[state12.CipherSuite]; ok {
			result.WeakCiphers = append(result.WeakCiphers, name)
		}
		for _, cert := range state12.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				result.CertExpired = true
			}
		}
	}

	supported13, _ := scanTLSVersion(addr, tls.VersionTLS13)
	if supported13 {
		result.SupportsTLS13 = true
	}

	if result.SupportsTLS10 || result.SupportsTLS11 || len(result.WeakCiphers) > 0 {
		slog.Warn("Weak TLS detected", "ip", ip, "port", port,
			"tls10", result.SupportsTLS10,
			"tls11", result.SupportsTLS11,
			"weak_ciphers", len(result.WeakCiphers))
	}

	return result
}
