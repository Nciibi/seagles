package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestWeakCipherNames_MapSanity(t *testing.T) {
	expected := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:            "RC4-SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES-EDE-CBC-SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "ECDHE-RSA-RC4-SHA",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    "ECDHE-ECDSA-RC4-SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "ECDHE-RSA-3DES-EDE-CBC-SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:        "AES128-CBC-SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:        "AES256-CBC-SHA",
	}

	for suite, name := range expected {
		got, ok := weakCipherNames[suite]
		if !ok {
			t.Errorf("cipher suite 0x%04x missing from weakCipherNames", suite)
			continue
		}
		if got != name {
			t.Errorf("suite 0x%04x = %q, want %q", suite, got, name)
		}
	}
}

// startTestTLSServer spins up a local TLS listener with a self-signed cert.
func startTestTLSServer(t *testing.T) (port int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "seagles-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := c.Read(buf)
				if n > 0 {
					c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				}
			}(conn)
		}
	}()

	t.Cleanup(func() { tlsListener.Close() })
	return listener.Addr().(*net.TCPAddr).Port
}

func TestCheckTLS_ModernServer(t *testing.T) {
	port := startTestTLSServer(t)
	result := CheckTLS("127.0.0.1", port)

	if !result.SupportsTLS12 {
		t.Error("expected TLS 1.2 support")
	}
	if !result.SupportsTLS13 {
		t.Error("expected TLS 1.3 support")
	}
	if result.SupportsTLS10 {
		t.Error("modern server must not report TLS 1.0 support")
	}
	if result.SupportsTLS11 {
		t.Error("modern server must not report TLS 1.1 support")
	}
	if len(result.WeakCiphers) != 0 {
		t.Errorf("expected no weak ciphers, got %v", result.WeakCiphers)
	}
	if result.CertExpired {
		t.Error("test certificate is valid, should not be flagged expired")
	}
	if result.CertError != "" {
		t.Errorf("unexpected cert error: %q", result.CertError)
	}
}

func TestCheckTLS_ClosedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	result := CheckTLS("127.0.0.1", port)

	if result.SupportsTLS10 || result.SupportsTLS11 || result.SupportsTLS12 || result.SupportsTLS13 {
		t.Error("closed port must not report any TLS support")
	}
	if len(result.WeakCiphers) != 0 || result.CertExpired {
		t.Errorf("unexpected findings on closed port: %+v", result)
	}
}

func TestScanTLSVersion_PlaintextServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("not tls at all\r\n"))
			conn.Close()
		}
	}()

	ok, state := scanTLSVersion(listener.Addr().String(), tls.VersionTLS12)
	if ok || state != nil {
		t.Error("plaintext server must not pass a TLS handshake")
	}
}
