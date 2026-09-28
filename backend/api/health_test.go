package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Nciibi/seagles/config"
	"github.com/gin-gonic/gin"
)

// deadTCPAddr is a listener-free address. Dialing it fails fast with a
// connection-refused, which is what an unreachable dependency looks like.
const deadTCPAddr = "127.0.0.1:1"

// alwaysTrue / alwaysFalse stand in for dbpkg.IsHealthy, which reads a
// package-private monitor in the db package and cannot be controlled from here.
func alwaysTrue() bool  { return true }
func alwaysFalse() bool { return false }

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode %s: %v", w.Body.String(), err)
	}
	return out
}

func call(t *testing.T, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	handler(c)
	return w
}

// --- /livez -------------------------------------------------------------

// Liveness must succeed even when the database is down, otherwise Kubernetes
// will restart every pod during a database outage.
func TestLivez_AlwaysOKEvenWhenDBDown(t *testing.T) {
	w := call(t, LivezHandler())
	if w.Code != http.StatusOK {
		t.Fatalf("livez must always return 200, got %d", w.Code)
	}
	body := decode[map[string]any](t, w)
	if body["status"] != "alive" {
		t.Errorf("status = %v, want alive", body["status"])
	}
}

func TestLivez_LivenessProbeSignature(t *testing.T) {
	// The k8s manifests probe GET /api/v1/livez and treat only 2xx/3xx as
	// success, so a 2xx body shape is part of the deployment contract.
	if w := call(t, LivezHandler()); w.Code < 200 || w.Code > 399 {
		t.Fatalf("livez code %d is not accepted by an httpGet probe", w.Code)
	}
}

// --- /readyz ------------------------------------------------------------

func TestReadyz_NotReadyWhenDBDown(t *testing.T) {
	cfg := &config.Config{}
	h := ReadyzHandler(cfg, &depProbe{}, alwaysFalse)

	w := call(t, h)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when db is down, got %d", w.Code)
	}
	body := decode[ReadinessStatus](t, w)
	if body.Status != "not_ready" {
		t.Errorf("status = %q, want not_ready", body.Status)
	}
	if body.DBOK {
		t.Error("db_ok should be false")
	}
}

func TestReadyz_ReadyWhenDBUpAndNoDepsConfigured(t *testing.T) {
	cfg := &config.Config{}
	h := ReadyzHandler(cfg, &depProbe{}, alwaysTrue)

	w := call(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decode[ReadinessStatus](t, w)
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.Degraded {
		t.Error("unconfigured optional dependencies must not count as degraded")
	}
}

// The core anti-cascading-outage guarantee: an optional dependency being down
// must NOT pull the pod out of service.
func TestReadyz_StaysReadyWhenOptionalDepDown(t *testing.T) {
	cfg := &config.Config{
		RedisURL:            deadTCPAddr,
		S3Endpoint:          deadTCPAddr,
		FirmwareAnalyzerURL: "http://" + deadTCPAddr,
	}
	h := ReadyzHandler(cfg, &depProbe{}, alwaysTrue)

	w := call(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("optional dependency outage must not fail readiness, got %d", w.Code)
	}
	body := decode[ReadinessStatus](t, w)
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if !body.Degraded {
		t.Error("degraded should be true when optional deps are unreachable")
	}
	for _, dep := range []string{"redis", "minio", "firmware_analyzer"} {
		if !body.Unavailable[dep] {
			t.Errorf("expected %s to be reported unavailable", dep)
		}
	}
}

// --- /health ------------------------------------------------------------

func TestHealthHandler_503WhenDBDown(t *testing.T) {
	h := HealthHandler(&config.Config{}, &depProbe{}, alwaysFalse)
	w := call(t, h)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestHealthHandler_DegradedBut200WhenOnlyOptionalDepDown(t *testing.T) {
	cfg := &config.Config{RedisURL: deadTCPAddr}
	h := HealthHandler(cfg, &depProbe{}, alwaysTrue)

	w := call(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("optional dep outage must not return 503, got %d", w.Code)
	}
	body := decode[HealthStatus](t, w)
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}
	if !body.DBOK {
		t.Error("db_ok should be true")
	}
	if body.RedisOK {
		t.Error("redis_ok should be false when redis is unreachable")
	}
	if !body.MinIOOK || !body.FAOK {
		t.Error("unconfigured dependencies should report ok")
	}
}

// --- dependency caching -------------------------------------------------

// The readiness probe is polled every few seconds per replica. Without a TTL
// cache each poll would dial three dependencies (3s timeout each), so the
// probe must not re-dial within the TTL.
func TestDepProbe_CachesWithinTTL(t *testing.T) {
	cfg := &config.Config{RedisURL: deadTCPAddr}
	p := &depProbe{}

	first := p.run(cfg)
	firstChecked := first.checked

	time.Sleep(10 * time.Millisecond)
	second := p.run(cfg)

	if !second.checked.Equal(firstChecked) {
		t.Error("probe re-ran within the TTL; expected the cached result")
	}
	if second.redis != first.redis {
		t.Error("cached redis result changed")
	}
}

func TestDepProbe_RerunsAfterTTL(t *testing.T) {
	cfg := &config.Config{RedisURL: deadTCPAddr}
	p := &depProbe{}

	p.run(cfg)
	// Age the entry past the TTL.
	p.mu.Lock()
	p.last.checked = time.Now().Add(-depProbeTTL - time.Second)
	p.mu.Unlock()

	second := p.run(cfg)
	if time.Since(second.checked) > time.Second {
		t.Error("probe did not re-run after the TTL expired")
	}
}

func TestDepProbe_ConcurrentCallsShareOneRound(t *testing.T) {
	cfg := &config.Config{RedisURL: deadTCPAddr}
	p := &depProbe{}

	var wg sync.WaitGroup
	results := make([]depState, 32)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = p.run(cfg)
		}(i)
	}
	wg.Wait()

	base := results[0].checked
	for i, r := range results {
		if !r.checked.Equal(base) {
			t.Fatalf("goroutine %d triggered a separate probe round", i)
		}
	}
}

// --- route registration -------------------------------------------------

// Regression guard for the deployment blocker where the Kubernetes probes and
// the container HEALTHCHECK targeted "/health" while the route only ever
// existed at "/api/v1/health" — a 404 that made every pod CrashLoop.
//
// The probe paths below are a contract between the Go routes and files that
// Go does not compile: k8s/seagles-backend-deployment.yaml, backend/Dockerfile
// and docker-compose.yml. If a route is renamed, these tests must fail so the
// manifests get updated in the same change.
func TestProbeRoutesAreRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// nil *sql.DB is safe here: no handler on these paths touches the database,
	// and the router only stores the handle.
	router := NewRouter(nil, &config.Config{}, nil)

	registered := make(map[string]bool)
	for _, ri := range router.Routes() {
		registered[ri.Method+" "+ri.Path] = true
	}

	// livenessProbe, readinessProbe, startupProbe (k8s), HEALTHCHECK (Docker,
	// compose). All must exist and all are GET.
	for _, path := range []string{
		"/api/v1/livez",
		"/api/v1/readyz",
		"/api/v1/health",
	} {
		if !registered["GET "+path] {
			t.Errorf("route GET %s is not registered; the k8s probes and "+
				"container healthcheck target it and would 404", path)
		}
	}
}

// The old broken path must NOT be registered: if it ever is, something is
// serving probes from the root and the versioned routes may drift again.
func TestLegacyRootHealthPathIsNotRegistered(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(nil, &config.Config{}, nil)

	for _, ri := range router.Routes() {
		if ri.Path == "/health" {
			t.Errorf("unexpected root-level route %s %s; probes must use the "+
				"versioned /api/v1 path", ri.Method, ri.Path)
		}
	}
}

// --- helper semantics ---------------------------------------------------

func TestUnconfiguredOrOK(t *testing.T) {
	cases := []struct {
		name       string
		configured bool
		ok         bool
		want       bool
	}{
		{"not configured is not a failure", false, false, true},
		{"not configured ignores ok", false, true, true},
		{"configured and reachable", true, true, true},
		{"configured and unreachable", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unconfiguredOrOK(tc.configured, tc.ok); got != tc.want {
				t.Errorf("unconfiguredOrOK(%v,%v) = %v, want %v",
					tc.configured, tc.ok, got, tc.want)
			}
		})
	}
}
