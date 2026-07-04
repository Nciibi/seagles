package slog

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func captureOutput(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)
	fn()
	return buf.String()
}

func TestLevelFiltering(t *testing.T) {
	SetLevel(LevelWarn)

	out := captureOutput(func() {
		Debug("debug msg")
		Info("info msg")
		Warn("warn msg")
		Error("error msg")
	})

	if strings.Contains(out, "DEBUG") {
		t.Fatal("DEBUG should not appear when level is WARN")
	}
	if strings.Contains(out, "INFO") {
		t.Fatal("INFO should not appear when level is WARN")
	}
	if !strings.Contains(out, "WARN") {
		t.Fatal("WARN should appear when level is WARN")
	}
	if !strings.Contains(out, "ERROR") {
		t.Fatal("ERROR should appear when level is WARN")
	}
}

func TestInfoOutput(t *testing.T) {
	SetLevel(LevelDebug)
	out := captureOutput(func() {
		Info("test message")
	})

	if !strings.Contains(out, "INFO") {
		t.Fatal("expected INFO level in output")
	}
	if !strings.Contains(out, "test message") {
		t.Fatal("expected message in output")
	}
}

func TestKeyValuePairs(t *testing.T) {
	SetLevel(LevelDebug)
	out := captureOutput(func() {
		Info("request", "method", "GET", "status", 200)
	})

	if !strings.Contains(out, "method=GET") {
		t.Fatal("expected method=GET in output")
	}
	if !strings.Contains(out, "status=200") {
		t.Fatal("expected status=200 in output")
	}
}

func TestMissingValue(t *testing.T) {
	SetLevel(LevelDebug)
	out := captureOutput(func() {
		Info("missing", "key_only")
	})

	if !strings.Contains(out, "key_only=<missing>") {
		t.Fatal("expected key_only=<missing> in output")
	}
}

func TestSetLevel(t *testing.T) {
	SetLevel(LevelDebug)
	if currentLevel != LevelDebug {
		t.Fatalf("expected LevelDebug, got %v", currentLevel)
	}

	SetLevel(LevelError)
	if currentLevel != LevelError {
		t.Fatalf("expected LevelError, got %v", currentLevel)
	}
}

func TestLevelNames(t *testing.T) {
	tests := []struct {
		level Level
		name  string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
	}

	for _, tt := range tests {
		if levelNames[tt.level] != tt.name {
			t.Errorf("expected %s for level %d, got %s", tt.name, tt.level, levelNames[tt.level])
		}
	}
}

func TestLoggerPrefix(t *testing.T) {
	SetLevel(LevelDebug)
	l := New("api")
	out := captureOutput(func() {
		l.Info("started", "port", "8080")
	})

	if !strings.Contains(out, "api: started") {
		t.Fatalf("expected 'api: started' in output, got: %s", out)
	}
	if !strings.Contains(out, "port=8080") {
		t.Fatalf("expected port=8080 in output, got: %s", out)
	}
}

func TestFatalOutput(t *testing.T) {
	SetLevel(LevelDebug)
	out := captureOutput(func() {
		logf(LevelFatal, "fatal error", "code", 1)
	})

	if !strings.Contains(out, "FATAL") {
		t.Fatal("expected FATAL in output")
	}
	if !strings.Contains(out, "code=1") {
		t.Fatal("expected code=1 in output")
	}
}
