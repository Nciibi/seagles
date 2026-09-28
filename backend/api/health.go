package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/Nciibi/seagles/config"
	"github.com/Nciibi/seagles/middleware"
	"github.com/gin-gonic/gin"
)

// depProbeTTL bounds how often the health/readiness endpoints open network
// connections to the external dependencies. Kubernetes polls the readiness
// probe every few seconds on every replica; without a cache each poll would
// dial Redis, MinIO and the firmware analyzer (3s timeout each), so a partial
// dependency outage would hold each poll's handler for up to 9s.
const depProbeTTL = 15 * time.Second

// HealthStatus is the detailed diagnostic payload served by /api/v1/health.
type HealthStatus struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
	DBOK    bool   `json:"db_ok"`
	RedisOK bool   `json:"redis_ok"`
	MinIOOK bool   `json:"minio_ok"`
	FAOK    bool   `json:"fa_ok"`
}

// ReadinessStatus is the payload served by /api/v1/readyz.
type ReadinessStatus struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	DBOK    bool   `json:"db_ok"`
	// Degraded is true when an optional dependency (Redis, MinIO, firmware
	// analyzer) is unreachable. It does NOT make the pod unready: only the
	// database is a hard dependency for serving the API, and failing readiness
	// on an optional dependency would pull every pod out of service during a
	// partial outage and turn a degraded system into a fully unavailable one.
	Degraded    bool            `json:"degraded"`
	Unavailable map[string]bool `json:"unavailable,omitempty"`
}

// depState caches the result of the last dependency probe round.
type depState struct {
	redis    bool
	minio    bool
	analyzer bool
	checked  time.Time
	valid    bool
}

// depProbe runs and caches the external dependency checks. It is safe for
// concurrent use; the mutex also collapses a burst of parallel probes into a
// single round of dial attempts.
type depProbe struct {
	mu   sync.Mutex
	last depState
}

func (p *depProbe) run(cfg *config.Config) depState {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.last.valid && time.Since(p.last.checked) < depProbeTTL {
		return p.last
	}

	state := depState{checked: time.Now(), valid: true}
	if cfg.RedisURL != "" {
		state.redis = middleware.CheckRedis(cfg.RedisURL)
	}
	if cfg.S3Endpoint != "" {
		state.minio = middleware.CheckMinIO(cfg.S3Endpoint)
	}
	if cfg.FirmwareAnalyzerURL != "" {
		state.analyzer = middleware.CheckFirmwareAnalyzer(cfg.FirmwareAnalyzerURL)
	}

	p.last = state
	return state
}

// unconfiguredOrOK reports whether a dependency is either not configured (in
// which case it is not a failure) or last probed successfully.
func unconfiguredOrOK(configured bool, ok bool) bool {
	if !configured {
		return true
	}
	return ok
}

// LivezHandler reports process liveness only. It performs no database query
// and no dependency check, so a downstream outage can never cause Kubernetes
// to restart otherwise-healthy pods. This is what the liveness and startup
// probes must target.
func LivezHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "alive",
			"service": "seagles-api",
		})
	}
}

// ReadyzHandler reports whether the pod can serve traffic. Readiness is gated
// on the database alone; optional dependencies are reported but do not fail
// the check (see ReadinessStatus.Degraded).
func ReadyzHandler(cfg *config.Config, probe *depProbe, dbOK func() bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		databaseUp := dbOK()
		deps := probe.run(cfg)

		redisOK := unconfiguredOrOK(cfg.RedisURL != "", deps.redis)
		minioOK := unconfiguredOrOK(cfg.S3Endpoint != "", deps.minio)
		faOK := unconfiguredOrOK(cfg.FirmwareAnalyzerURL != "", deps.analyzer)

		unavailable := make(map[string]bool)
		if !redisOK {
			unavailable["redis"] = true
		}
		if !minioOK {
			unavailable["minio"] = true
		}
		if !faOK {
			unavailable["firmware_analyzer"] = true
		}

		rs := ReadinessStatus{
			Status:      "ready",
			Service:     "seagles-api",
			DBOK:        databaseUp,
			Degraded:    len(unavailable) > 0,
			Unavailable: unavailable,
		}

		statusCode := http.StatusOK
		if !databaseUp {
			rs.Status = "not_ready"
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, rs)
	}
}

// HealthHandler serves the full diagnostic payload. It returns 503 only when
// the database is unreachable, so a partial dependency outage reports
// status="degraded" with HTTP 200 rather than taking the container out of
// service. The Kubernetes probes use /livez and /readyz instead.
func HealthHandler(cfg *config.Config, probe *depProbe, dbOK func() bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		databaseUp := dbOK()
		deps := probe.run(cfg)

		hs := HealthStatus{
			Status:  "ok",
			Service: "seagles-api",
			Version: "2.1.0",
			DBOK:    databaseUp,
			RedisOK: unconfiguredOrOK(cfg.RedisURL != "", deps.redis),
			MinIOOK: unconfiguredOrOK(cfg.S3Endpoint != "", deps.minio),
			FAOK:    unconfiguredOrOK(cfg.FirmwareAnalyzerURL != "", deps.analyzer),
		}

		allOK := hs.DBOK && hs.RedisOK && hs.MinIOOK && hs.FAOK
		if !allOK {
			hs.Status = "degraded"
		}

		statusCode := http.StatusOK
		if !databaseUp {
			statusCode = http.StatusServiceUnavailable
		}
		c.JSON(statusCode, hs)
	}
}
