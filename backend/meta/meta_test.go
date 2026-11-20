package meta_test

import (
	"testing"

	"github.com/Nciibi/seagles/meta"
)

func TestVersion(t *testing.T) {
	if meta.Version == "" {
		t.Fatal("Version must not be empty")
	}
}

func TestDefaultTenantID(t *testing.T) {
	const want = "00000000-0000-0000-0000-000000000001"
	if meta.DefaultTenantID != want {
		t.Fatalf("DefaultTenantID = %q, want %q", meta.DefaultTenantID, want)
	}
}
