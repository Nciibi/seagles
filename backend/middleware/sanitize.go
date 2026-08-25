package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type XSSConfig struct {
	StripHTML     bool
	StripScripts  bool
	MaxBodyLength int64
}

var DefaultXSSConfig = XSSConfig{
	StripHTML:     true,
	StripScripts:  true,
	MaxBodyLength: 1 << 20,
}

var dangerousHTML = []string{
	"<script", "</script", "<iframe", "</iframe",
	"<object", "</object", "<embed", "</embed",
	"onerror=", "onload=", "onclick=", "onmouseover=",
	"javascript:", "data:text/html", "vbscript:",
	"<svg", "<math", "<form", "</form",
}

func hasDangerousContent(s string) bool {
	lower := strings.ToLower(s)
	for _, pattern := range dangerousHTML {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func SanitizeInput(cfg XSSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.GetHeader("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			c.Next()
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, cfg.MaxBodyLength))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"data": nil, "error": "Failed to read request body",
			})
			return
		}
		c.Request.Body.Close()

		var raw interface{}
		if err := json.Unmarshal(body, &raw); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"data": nil, "error": "Invalid JSON in request body",
			})
			return
		}

		if cfg.StripScripts || cfg.StripHTML {
			sanitized := sanitizeValue(raw, cfg)
			newBody, err := json.Marshal(sanitized)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewReader(newBody))
				c.Request.ContentLength = int64(len(newBody))
				c.Next()
				return
			}
		}

		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		c.Next()
	}
}

func sanitizeValue(v interface{}, cfg XSSConfig) interface{} {
	switch val := v.(type) {
	case string:
		if cfg.StripScripts && hasDangerousContent(val) {
			return strings.Map(func(r rune) rune {
				if r == '<' || r == '>' || r == '"' || r == '\'' || r == '&' {
					return -1
				}
				return r
			}, val)
		}
		return val
	case map[string]interface{}:
		for k, v := range val {
			val[k] = sanitizeValue(v, cfg)
		}
		return val
	case []interface{}:
		for i, v := range val {
			val[i] = sanitizeValue(v, cfg)
		}
		return val
	default:
		return v
	}
}

var allowedFirmwareMIMETypes = map[string]string{
	"application/octet-stream":               "bin",
	"application/x-executable":               "elf",
	"application/x-sharedlib":                "so",
	"application/gzip":                       "gz",
	"application/x-gzip":                     "gz",
	"application/x-tar":                      "tar",
	"application/x-bzip2":                    "bz2",
	"application/x-xz":                       "xz",
	"application/zip":                        "zip",
	"application/x-rar-compressed":           "rar",
	"application/x-7z-compressed":            "7z",
}

var firmwareMagicBytes = []struct {
	magic  []byte
	offset int
	desc   string
}{
	{[]byte{0x1F, 0x8B}, 0, "gzip"},
	{[]byte{0x42, 0x5A, 0x68}, 0, "bzip2"},
	{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A}, 0, "xz"},
	{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "zip"},
	{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, 0, "rar"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, "7z"},
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, 0, "elf"},
}

type FileValidationError struct {
	Msg string
}

func (e *FileValidationError) Error() string {
	return e.Msg
}

func ValidateFirmwareFile(filename string, data []byte) error {
	if len(data) == 0 {
		return &FileValidationError{"Empty file"}
	}

	if len(data) > 256<<20 {
		return &FileValidationError{"File too large (max 256MB)"}
	}

	ext := strings.ToLower(filepathExt(filename))
	validExts := map[string]bool{".bin": true, ".elf": true, ".so": true,
		".gz": true, ".tar": true, ".bz2": true, ".xz": true,
		".zip": true, ".rar": true, ".7z": true, ".img": true,
		".fw": true, ".rom": true, ".squashfs": true, ".ubifs": true,
		".jffs2": true, ".cramfs": true}
	if !validExts[ext] {
		return &FileValidationError{"Invalid file extension: " + ext}
	}

	matchFound := false
	for _, fm := range firmwareMagicBytes {
		if len(data) >= fm.offset+len(fm.magic) {
			if bytes.Equal(data[fm.offset:fm.offset+len(fm.magic)], fm.magic) {
				matchFound = true
				break
			}
		}
	}

	if !matchFound {
		return &FileValidationError{"File does not match known firmware magic bytes"}
	}
	return nil
}

func filepathExt(filename string) string {
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			return filename[i:]
		}
		if filename[i] == '/' || filename[i] == '\\' {
			break
		}
	}
	return ""
}
