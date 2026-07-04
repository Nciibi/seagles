package middleware

import (
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
