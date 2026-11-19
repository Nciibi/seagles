package api

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Nciibi/seagles/config"
)

// swaggerParam matches a Gin path parameter segment (":id" -> "{id}").
var swaggerParam = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

// TestSwaggerMatchesRouter keeps the published OpenAPI document honest. The
// spec is consumed by client generators and the Postman collection, so a route
// that exists in code but not in the spec (or the reverse) silently breaks
// consumers. This test runs in CI and fails on any drift.
func TestSwaggerMatchesRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := NewRouter(nil, &config.Config{}, nil)

	registered := make(map[string]bool)
	for _, ri := range router.Routes() {
		if !strings.HasPrefix(ri.Path, "/api/v1") {
			continue
		}
		path := strings.TrimPrefix(ri.Path, "/api/v1")
		if path == "" {
			path = "/"
		}
		path = swaggerParam.ReplaceAllString(path, "{$1}")
		registered[ri.Method+" "+path] = true
	}

	specBytes, err := os.ReadFile("swagger.json")
	if err != nil {
		t.Fatalf("read swagger.json: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		t.Fatalf("parse swagger.json: %v", err)
	}

	documented := make(map[string]bool)
	for path, methods := range spec.Paths {
		for method := range methods {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	for route := range registered {
		if !documented[route] {
			t.Errorf("route %s is registered but missing from swagger.json", route)
		}
	}
	for route := range documented {
		if !registered[route] {
			t.Errorf("swagger.json documents %s but the router does not register it", route)
		}
	}
}
