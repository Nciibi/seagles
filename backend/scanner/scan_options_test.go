package scanner

import (
	"strings"
	"testing"
)

func TestPortsArgumentRespectsProfileCap(t *testing.T) {
	all := portsArgument(0)
	if got := strings.Split(all, ","); len(got) != len(DefaultScanPorts) {
		t.Fatalf("default port count = %d, want %d", len(got), len(DefaultScanPorts))
	}

	capped := portsArgument(3)
	want := "22,23,80"
	if capped != want {
		t.Fatalf("portsArgument(3) = %q, want %q", capped, want)
	}
}

func TestPortsArgumentIgnoresOversizedCap(t *testing.T) {
	got := portsArgument(999)
	if want := portsArgument(0); got != want {
		t.Fatalf("portsArgument(999) = %q, want %q", got, want)
	}
}
