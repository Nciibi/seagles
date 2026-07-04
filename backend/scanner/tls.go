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

var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:        "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:  "3DES-EDE-CBC-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: "ECDHE-RSA-RC4-SHA",
	0x0005:                              "RC4-SHA (SSLv3)",
	0x000a:                              "DES-CBC3-SHA",
	0x0016:                              "DHE-RSA-DES-CBC3-SHA",
	0xc007:                              "ECDHE-ECDSA-RC4-SHA",
	0xc011:                              "ECDHE-RSA-RC4-SHA",
	0xc012:                              "ECDHE-RSA-DES-CBC3-SHA",
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

	for _, v := range versions {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         v.ver,
			MaxVersion:         v.ver,
		})
		if err != nil {
			continue
		}

		*v.target = true

		if v.ver < tls.VersionTLS12 {
			result.SupportsTLS10 = true
		}

		state := conn.ConnectionState()
		for _, cipher := range state.CipherSuite {
			if name, ok := weakCiphers[cipher]; ok {
				result.WeakCiphers = append(result.WeakCiphers, name)
			}
		}

		certs := state.PeerCertificates
		if len(certs) > 0 {
			if time.Now().After(certs[0].NotAfter) {
				result.CertExpired = true
			}
		}

		conn.Close()
		break
	}

	if result.SupportsTLS10 || result.SupportsTLS11 || len(result.WeakCiphers) > 0 {
		slog.Warn("Weak TLS detected", "ip", ip, "port", port,
			"tls10", result.SupportsTLS10,
			"tls11", result.SupportsTLS11,
			"weak_ciphers", len(result.WeakCiphers))
	}

	return result
}
