package middleware

import (
	"io"
	"strings"
	"testing"
)

func TestHasDangerousContent_Script(t *testing.T) {
	if !hasDangerousContent("<script>alert(1)</script>") {
		t.Fatal("expected <script> to be detected")
	}
}

func TestHasDangerousContent_Iframe(t *testing.T) {
	if !hasDangerousContent("<iframe src='evil.com'>") {
		t.Fatal("expected <iframe> to be detected")
	}
}

func TestHasDangerousContent_OnError(t *testing.T) {
	if !hasDangerousContent("onerror=alert(1)") {
		t.Fatal("expected onerror= to be detected")
	}
}

func TestHasDangerousContent_JavaScript(t *testing.T) {
	if !hasDangerousContent("javascript:alert(1)") {
		t.Fatal("expected javascript: to be detected")
	}
}

func TestHasDangerousContent_Safe(t *testing.T) {
	if hasDangerousContent("hello world") {
		t.Fatal("expected safe string to not be detected")
	}
}

func TestHasDangerousContent_CaseInsensitive(t *testing.T) {
	if !hasDangerousContent("<SCRIPT>alert(1)</SCRIPT>") {
		t.Fatal("expected uppercase <SCRIPT> to be detected")
	}
}

func TestValidateFirmwareFile_Empty(t *testing.T) {
	err := ValidateFirmwareFile("test.bin", []byte{})
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestValidateFirmwareFile_TooLarge(t *testing.T) {
	data := make([]byte, 257<<20)
	err := ValidateFirmwareFile("test.bin", data)
	if err == nil {
		t.Fatal("expected error for too large file")
	}
}

func TestValidateFirmwareFile_InvalidExtension(t *testing.T) {
	err := ValidateFirmwareFile("test.exe", []byte{0x1F, 0x8B})
	if err == nil {
		t.Fatal("expected error for invalid extension")
	}
}

func TestValidateFirmwareFile_ValidELF(t *testing.T) {
	err := ValidateFirmwareFile("firmware.elf", []byte{0x7F, 0x45, 0x4C, 0x46})
	if err != nil {
		t.Fatalf("expected nil for valid ELF, got %v", err)
	}
}

func TestValidateFirmwareFile_ValidGZip(t *testing.T) {
	err := ValidateFirmwareFile("firmware.gz", []byte{0x1F, 0x8B})
	if err != nil {
		t.Fatalf("expected nil for valid gzip, got %v", err)
	}
}

func TestValidateFirmwareFile_ValidZip(t *testing.T) {
	err := ValidateFirmwareFile("firmware.zip", []byte{0x50, 0x4B, 0x03, 0x04})
	if err != nil {
		t.Fatalf("expected nil for valid zip, got %v", err)
	}
}

func TestFilepathExt(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"file.bin", ".bin"},
		{"file.elf.gz", ".gz"},
		{"path/to/file.tar", ".tar"},
		{"noext", ""},
		{".hidden", ".hidden"},
	}

	for _, tt := range tests {
		result := filepathExt(tt.path)
		if result != tt.expected {
			t.Errorf("filepathExt(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

// Regression guard: a client that sets a default Content-Type on every request
// sends an empty body with GET and DELETE. json.Unmarshal fails on that, so
// every DELETE /devices/:id and DELETE /safelists/:id returned 400 instead of
// succeeding.
func TestSanitizeInput_EmptyJSONBodyOnBodilessMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	methods := []string{http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			r := gin.New()
			r.Use(SanitizeInput(DefaultXSSConfig))
			r.Handle(method, "/x", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"ok": true})
			})

			req := httptest.NewRequest(method, "/x", nil)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("%s with an empty application/json body returned %d, want 200: %s",
					method, w.Code, w.Body.String())
			}
		})
	}
}

// A POST that legitimately has no body (for example /alerts/:id/ack) must not
// be rejected as malformed JSON either.
func TestSanitizeInput_EmptyJSONBodyOnPost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(SanitizeInput(DefaultXSSConfig))
	r.POST("/ack", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	for _, body := range []string{"", "   ", "\n"} {
		req := httptest.NewRequest(http.MethodPost, "/ack", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("POST with body %q returned %d, want 200: %s", body, w.Code, w.Body.String())
		}
	}
}

// Genuinely malformed JSON on a POST must still be rejected.
func TestSanitizeInput_MalformedJSONStillRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(SanitizeInput(DefaultXSSConfig))
	r.POST("/x", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"a":`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON returned %d, want 400", w.Code)
	}
}

// The handler must still receive the body intact after sanitisation.
func TestSanitizeInput_BodyReachesHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var got string
	r := gin.New()
	r.Use(SanitizeInput(DefaultXSSConfig))
	r.POST("/x", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		got = string(b)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"name":"cam-01"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if !strings.Contains(got, "cam-01") {
		t.Errorf("handler received %q, want the original payload", got)
	}
}
