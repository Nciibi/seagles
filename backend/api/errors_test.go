package api

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// A database error must never reach the client. Postgres error text names
// tables, columns, constraint names and index definitions, so returning
// err.Error() to an authenticated user turns any 500 into a schema map. Before
// this was fixed, 27 handlers across api/ did exactly that.
func TestFailInternal_DoesNotLeakDatabaseErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const secretish = `pq: duplicate key value violates unique constraint "devices_ip_address_key"` +
		` DETAIL: Key (ip_address)=(192.168.1.50) already exists.`

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("request_id", uuid.NewString())
		c.Next()
	})
	r.GET("/boom", func(c *gin.Context) {
		failInternal(c, http.StatusInternalServerError, "Failed to query devices", errors.New(secretish))
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	body := w.Body.String()

	for _, leak := range []string{
		"duplicate key",
		"devices_ip_address_key",
		"pq:",
		"DETAIL",
		"192.168.1.50",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
	// The operator still needs something actionable for the client.
	if !strings.Contains(body, "Failed to query devices") {
		t.Errorf("response should carry the public message, got: %s", body)
	}
}

// Regression guard: handlers must not concatenate err.Error() into a client
// response. This scans the api package source so a future handler cannot
// reintroduce the pattern.
func TestAPIPackageDoesNotLeakErrorsToClients(t *testing.T) {
	offenders := scanAPISourcesForErrorConcatenation(t)
	if len(offenders) > 0 {
		t.Errorf("handlers concatenate err.Error() into client responses, "+
			"leaking internal detail:\n  %s\nUse failInternal(c, status, "+
			"publicMessage, err) instead.", strings.Join(offenders, "\n  "))
	}
}

func TestUUIDParam_RejectsMalformedIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		id   string
		want int
	}{
		{"not-a-uuid", http.StatusBadRequest},
		{"12345", http.StatusBadRequest},
		{"'; DROP TABLE devices; --", http.StatusBadRequest},
		{`00000000-0000-0000-0000-00000000000Z`, http.StatusBadRequest},
		{uuid.NewString(), http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r := gin.New()
			var reached bool
			r.DELETE("/:id", func(c *gin.Context) {
				id, ok := uuidParam(c, "id")
				if !ok {
					return
				}
				reached = true
				c.JSON(http.StatusOK, gin.H{"id": id})
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/"+tc.id, nil))

			if w.Code != tc.want {
				t.Errorf("id %q: got %d, want %d", tc.id, w.Code, tc.want)
			}
			if tc.want == http.StatusOK && !reached {
				t.Error("handler was not reached for a valid UUID")
			}
			if tc.want == http.StatusBadRequest && reached {
				t.Error("handler was reached for a malformed UUID")
			}
		})
	}
}

// Deleting with a malformed id must not reach the database, so no 500 is
// produced and no schema detail is exposed.
func TestDeleteDevice_MalformedIDNeverQueries(t *testing.T) {
	router, mock, _ := setupTestRouter(t)

	w := request(router, "DELETE", "/api/v1/devices/oops", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "uuid") && strings.Contains(w.Body.String(), "syntax") {
		t.Errorf("response leaks database syntax detail: %s", w.Body.String())
	}
	// No query must have been issued.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the database was queried for a malformed id: %v", err)
	}
}

var _ = sql.ErrNoRows
var _ sqlmock.Sqlmock
