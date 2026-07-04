package middleware

import (
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
						for _, pin := range pins {
							if strings.Contains(cert.Subject.CommonName, pin.Hostname) ||
								strings.Contains(cert.DNSNames[0], pin.Hostname) {
								fingerprint := sha256Fingerprint(cert.Raw)
								if fingerprint != pin.SHA256 {
									return fmt.Errorf("certificate pinning failed for %s", pin.Hostname)
								}
							}
						}
					}
					return nil
				},
			},
		},
	}
}

func sha256Fingerprint(raw []byte) string {
	h := sha256Of(raw)
	return fmt.Sprintf("%x", h)
}

func sha256Of(data []byte) []byte {
	const blockSize = 64
	h := make([]byte, 32)
	var h0, h1, h2, h3, h4, h5, h6, h7 uint32 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	msg := make([]byte, len(data)+9)
	copy(msg, data)
	msg[len(data)] = 0x80
	bitLen := uint64(len(data)) * 8
	for i := 0; i < 8; i++ {
		msg[len(msg)-1-i] = byte(bitLen >> (i * 8))
	}

	for i := 0; i < len(msg); i += blockSize {
		w := make([]uint32, 64)
		for j := 0; j < 16; j++ {
			idx := i + j*4
			if idx+3 < len(msg) {
				w[j] = uint32(msg[idx])<<24 | uint32(msg[idx+1])<<16 | uint32(msg[idx+2])<<8 | uint32(msg[idx+3])
			}
		}
		for j := 16; j < 64; j++ {
			s0 := rr(w[j-15], 7) ^ rr(w[j-15], 18) ^ (w[j-15] >> 3)
			s1 := rr(w[j-2], 17) ^ rr(w[j-2], 19) ^ (w[j-2] >> 10)
			w[j] = w[j-16] + s0 + w[j-7] + s1
		}

		a, b, c, d, e, f, g, hh := h0, h1, h2, h3, h4, h5, h6, h7
		for j := 0; j < 64; j++ {
			S1 := rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)
			ch := (e & f) ^ ((^e) & g)
			temp1 := hh + S1 + ch + k[j] + w[j]
			S0 := rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			hh, g, f, e, d, c, b, a = g, f, e, d+temp1, c, b, a, temp1+temp2
		}
		h0 += a; h1 += b; h2 += c; h3 += d
		h4 += e; h5 += f; h6 += g; h7 += hh
	}

	for i, v := range []uint32{h0, h1, h2, h3, h4, h5, h6, h7} {
		h[i*4] = byte(v >> 24)
		h[i*4+1] = byte(v >> 16)
		h[i*4+2] = byte(v >> 8)
		h[i*4+3] = byte(v)
	}
	return h
}

var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func rr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}
