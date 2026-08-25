package alerts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/Nciibi/seagles/slog"
)

type WebhookConfig struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	URL         string          `json:"url"`
	WebhookType string          `json:"webhook_type"`
	MinSeverity string          `json:"min_severity"`
	IsActive    bool            `json:"is_active"`
	Secret      sql.NullString  `json:"-"`
	Headers     json.RawMessage `json:"headers"`
}

const (
	maxWebhookRetries    = 3
	webhookRetryBaseMs   = 1000
)

func severityLevel(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func DispatchWebhooks(db *sql.DB, alertID, severity, title, description, deviceID string) {
	rows, err := db.Query(`SELECT id, name, url, webhook_type, min_severity, secret, headers
		FROM webhooks WHERE is_active = TRUE`)
	if err != nil {
		slog.Error("Failed to query webhooks", "error", err.Error())
		return
	}
	defer rows.Close()

	alertLevel := severityLevel(severity)

	for rows.Next() {
		var wh WebhookConfig
		if err := rows.Scan(&wh.ID, &wh.Name, &wh.URL, &wh.WebhookType, &wh.MinSeverity, &wh.Secret, &wh.Headers); err != nil {
			continue
		}

		if alertLevel < severityLevel(wh.MinSeverity) {
			continue
		}

		go deliverWebhookWithRetry(db, wh, alertID, severity, title, description, deviceID)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error iterating webhooks: %v", err)
		return
	}
}

func deliverWebhookWithRetry(db *sql.DB, wh WebhookConfig, alertID, severity, title, description, deviceID string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Webhook delivery panicked", "name", wh.Name, "recover", r)
		}
	}()

	lastErr := ""
	for attempt := 0; attempt < maxWebhookRetries; attempt++ {
		sc, err := deliverWebhook(db, wh, alertID, severity, title, description, deviceID, attempt)
		if err == nil {
			slog.Info("webhook delivered", "name", wh.Name, "status", sc)
			return
		}

		lastErr = err.Error()
		if attempt < maxWebhookRetries-1 {
			delay := time.Duration(webhookRetryBaseMs*int(math.Pow(2, float64(attempt)))) * time.Millisecond
			slog.Warn("webhook delivery failed, retrying",
				"name", wh.Name,
				"attempt", attempt+1,
				"max", maxWebhookRetries,
				"retry_delay_ms", delay.Milliseconds(),
				"error", lastErr)
			time.Sleep(delay)
		}
	}

	slog.Error("webhook delivery failed after all retries",
		"name", wh.Name,
		"attempts", maxWebhookRetries,
		"last_error", lastErr)
}

func deliverWebhook(db *sql.DB, wh WebhookConfig, alertID, severity, title, description, deviceID string, attempt int) (int, error) {
	var payload []byte
	var err error

	switch wh.WebhookType {
	case "slack":
		payload, err = buildSlackPayload(severity, title, description, deviceID)
	case "teams":
		payload, err = buildTeamsPayload(severity, title, description, deviceID)
	default:
		payload, err = buildGenericPayload(alertID, severity, title, description, deviceID)
	}
	if err != nil {
		logDelivery(db, wh.ID, alertID, 0, "", err.Error())
		return 0, err
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(payload))
	if err != nil {
		logDelivery(db, wh.ID, alertID, 0, "", err.Error())
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Seagles-Webhook/2.0")

	if len(wh.Headers) > 0 {
		var headers map[string]string
		if json.Unmarshal(wh.Headers, &headers) == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if attempt == maxWebhookRetries-1 {
			logDelivery(db, wh.ID, alertID, 0, "", err.Error())
		}
		return 0, err
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	logDelivery(db, wh.ID, alertID, resp.StatusCode, body, "")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		db.Exec(`UPDATE alerts SET webhook_sent = TRUE, webhook_sent_at = NOW() WHERE id = $1`, alertID)
		db.Exec(`UPDATE webhooks SET last_triggered = NOW() WHERE id = $1`, wh.ID)
		return resp.StatusCode, nil
	}

	return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
}

func logDelivery(db *sql.DB, webhookID, alertID string, statusCode int, responseBody, errMsg string) {
	db.Exec(`INSERT INTO webhook_deliveries (webhook_id, alert_id, status_code, response_body, error)
		VALUES ($1, $2, $3, $4, $5)`,
		webhookID, alertID, statusCode, responseBody, errMsg)
}

func buildSlackPayload(severity, title, description, deviceID string) ([]byte, error) {
	emoji := "⚪"
	switch severity {
	case "critical":
		emoji = "🔴"
	case "high":
		emoji = "🟠"
	case "medium":
		emoji = "🔵"
	}

	msg := map[string]interface{}{
		"text": fmt.Sprintf("%s *[%s] Seagles Alert*", emoji, strings.ToUpper(severity)),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("%s [%s] %s", emoji, strings.ToUpper(severity), title),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Description:* %s\n*Device:* `%s`\n*Severity:* %s", description, deviceID, severity),
				},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("Seagles Security Platform · %s", time.Now().Format(time.RFC3339))},
				},
			},
		},
	}
	return json.Marshal(msg)
}

func buildTeamsPayload(severity, title, description, deviceID string) ([]byte, error) {
	color := "0078D4"
	switch severity {
	case "critical":
		color = "FF0000"
	case "high":
		color = "FF8C00"
	case "medium":
		color = "1C7ED6"
	}

	msg := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": color,
		"summary":    fmt.Sprintf("[%s] %s", strings.ToUpper(severity), title),
		"sections": []map[string]interface{}{
			{
				"activityTitle": fmt.Sprintf("[%s] %s", strings.ToUpper(severity), title),
				"facts": []map[string]string{
					{"name": "Severity", "value": severity},
					{"name": "Device", "value": deviceID},
					{"name": "Description", "value": description},
					{"name": "Time", "value": time.Now().Format(time.RFC3339)},
				},
			},
		},
	}
	return json.Marshal(msg)
}

func buildGenericPayload(alertID, severity, title, description, deviceID string) ([]byte, error) {
	msg := map[string]interface{}{
		"event_type": "security_alert",
		"source":     "seagles",
		"version":    "1.0",
		"alert": map[string]string{
			"id":          alertID,
			"severity":    severity,
			"title":       title,
			"description": description,
			"device_id":   deviceID,
			"timestamp":   time.Now().Format(time.RFC3339),
		},
		"cef": fmt.Sprintf("CEF:0|Seagles|SecurityPlatform|1.0|%s|%s|%s|dst=%s msg=%s",
			"IoTAlert", title, severityCEF(severity), deviceID, description),
	}
	return json.Marshal(msg)
}

func severityCEF(sev string) string {
	switch sev {
	case "critical":
		return "10"
	case "high":
		return "7"
	case "medium":
		return "4"
	default:
		return "1"
	}
}
