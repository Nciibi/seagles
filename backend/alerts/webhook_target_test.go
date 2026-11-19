package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateWebhookTargetRejectsPrivateAddresses(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "")
	for _, raw := range []string{
		"http://127.0.0.1:8080/hook",
		"http://localhost/hook",
		"http://192.168.1.10/hook",
		"http://10.0.0.5/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://[::1]/hook",
	} {
		if err := ValidateWebhookTarget(raw, "generic"); err == nil {
			t.Errorf("expected %q to be rejected", raw)
		}
	}
}

func TestValidateWebhookTargetRejectsBadSchemesAndCredentials(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
	if err := ValidateWebhookTarget("file:///etc/passwd", "generic"); err == nil {
		t.Error("file:// scheme accepted")
	}
	if err := ValidateWebhookTarget("https://user:pass@example.com/hook", "generic"); err == nil {
		t.Error("embedded credentials accepted")
	}
	if err := ValidateWebhookTarget("https://", "generic"); err == nil {
		t.Error("missing host accepted")
	}
}

func TestValidateWebhookTargetAllowsPublicHTTPS(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
	if err := ValidateWebhookTarget("https://hooks.example.com/path", "generic"); err != nil {
		t.Fatalf("public webhook rejected: %v", err)
	}
}

func TestValidateWebhookTargetSyslogSchemes(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
	if err := ValidateWebhookTarget("udp://syslog.example.com:514", "syslog"); err != nil {
		t.Fatalf("udp syslog rejected: %v", err)
	}
	if err := ValidateWebhookTarget("https://syslog.example.com", "syslog"); err == nil {
		t.Error("http scheme accepted for syslog type")
	}
}

func TestDeliverSyslogSendsDatagram(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "true")
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer listener.Close()

	wh := WebhookConfig{ID: "wh-1", WebhookType: "syslog", URL: "udp://" + listener.LocalAddr().String()}
	payload := []byte(`{"alert":{"severity":"high"}}`)
	if err := deliverSyslog(wh, payload); err != nil {
		t.Fatalf("deliverSyslog: %v", err)
	}

	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	msg := string(buf[:n])
	if !strings.HasPrefix(msg, "<134>") {
		t.Fatalf("message has no syslog PRI header: %q", msg)
	}
	if !strings.Contains(msg, string(payload)) {
		t.Fatalf("message does not carry the payload: %q", msg)
	}
}

func TestDeliverSyslogRejectsPrivateTargetByDefault(t *testing.T) {
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "")
	wh := WebhookConfig{ID: "wh-2", WebhookType: "syslog", URL: "udp://127.0.0.1:514"}
	if err := deliverSyslog(wh, []byte("test")); err == nil {
		t.Fatal("syslog delivery to loopback should be rejected by default")
	}
}

func TestSignWebhookPayload(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	secret := "top-secret"
	got := signWebhookPayload(payload, secret)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}

	mac2 := hmac.New(sha256.New, []byte("wrong-secret"))
	mac2.Write(payload)
	if strings.HasPrefix(got, "sha256="+hex.EncodeToString(mac2.Sum(nil))) {
		t.Fatal("signature verifies with the wrong secret")
	}
}
