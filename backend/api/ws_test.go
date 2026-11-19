package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/Nciibi/seagles/events"
)

// End-to-end check that a published backend event reaches a connected
// WebSocket client. This guards against the hub silently becoming a no-op
// again (Broadcast had no callers before the events bridge existed).
func TestWebSocketReceivesPublishedEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/ws", WSHandler([]string{"http://example.com"}))
	server := httptest.NewServer(r)
	defer server.Close()

	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	header := http.Header{"Origin": []string{"http://example.com"}}
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, dialResp, err := dialer.Dial(url, header)
	if dialResp != nil && dialResp.Body != nil {
		dialResp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	events.Publish(events.Event{Type: events.AlertCreated, Data: map[string]interface{}{
		"id": "alert-1", "severity": "critical",
	}})

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}

	var envelope struct {
		Type string                 `json:"type"`
		Data map[string]interface{} `json:"data"`
		Time time.Time              `json:"time"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if envelope.Type != events.AlertCreated {
		t.Fatalf("event type = %q, want %q", envelope.Type, events.AlertCreated)
	}
	if envelope.Data["id"] != "alert-1" {
		t.Fatalf("event data = %v, want id alert-1", envelope.Data)
	}
	if envelope.Time.IsZero() {
		t.Fatal("envelope has no timestamp")
	}
}
