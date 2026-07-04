package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/slog"
)

type TLSConfig struct {
	Enabled        bool
	CertFile       string
	KeyFile        string
	MinVersion     uint16
	EnforceTLS13   bool
	PinnedKeysFile string
}

var DefaultTLSConfig = TLSConfig{
	MinVersion:   tls.VersionTLS12,
	EnforceTLS13: false,
}

func TLSEnforcementMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil {
			slog.Warn("non_tls_request", "path", c.Request.URL.Path, "ip", c.ClientIP())
			c.Next()
			return
		}

		version := c.Request.TLS.Version
		if version < tls.VersionTLS12 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"data": nil, "error": "TLS 1.2 or higher required",
			})
			return
		}

		c.Next()
	}
}

type CertPin struct {
	Hostname string
	SHA256   string
}

func LoadPinnedKeys(filePath string) ([]CertPin, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pinned keys file: %w", err)
	}

	var pins []CertPin
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			pins = append(pins, CertPin{Hostname: parts[0], SHA256: parts[1]})
		}
	}
	return pins, nil
}

func NewPinnedHTTPClient(pins []CertPin) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					for _, chain := range verifiedChains {
						if len(chain) == 0 {
							continue
						}
						cert := chain[0]
						fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
						for _, pin := range pins {
							if (strings.Contains(cert.Subject.CommonName, pin.Hostname) ||
								containsHost(cert.DNSNames, pin.Hostname)) &&
								fingerprint != pin.SHA256 {
								return fmt.Errorf("certificate pinning failed for %s: expected %s, got %s",
									pin.Hostname, pin.SHA256, fingerprint)
							}
						}
					}
					return nil
				},
			},
		},
	}
}

func containsHost(hosts []string, target string) bool {
	for _, h := range hosts {
		if strings.Contains(h, target) {
			return true
		}
	}
	return false
}
