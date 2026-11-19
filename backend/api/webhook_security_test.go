package api

import (
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// A private webhook URL must be rejected before any network call is made.
// The unit test of ValidateWebhookTarget proves the rule; this proves the
// admin endpoint actually enforces it.
func TestTestWebhookHandlerRejectsPrivateTarget(t *testing.T) {
	router, mock, _ := setupTestRouter(t)
	t.Setenv("WEBHOOK_ALLOW_PRIVATE_TARGETS", "")
	id := uuid.NewString()

	mock.ExpectQuery(`SELECT url, webhook_type FROM webhooks`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"url", "webhook_type"}).
			AddRow("http://127.0.0.1:8080/hook", "generic"))

	w := request(router, "POST", "/api/v1/webhooks/"+id+"/test", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
