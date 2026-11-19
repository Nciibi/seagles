package middleware

import (
	"database/sql"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type Metrics struct {
	mu             sync.RWMutex
	requestsTotal  map[string]int64
	requestsActive int64
	errorsTotal    map[string]int64
	latencySamples map[string][]float64
	latencyCount   map[string]int64
	latencySum     map[string]float64
	uptimeStart    time.Time
	db             *sql.DB
}

var globalMetrics = &Metrics{
	requestsTotal:  make(map[string]int64),
	errorsTotal:    make(map[string]int64),
	latencySamples: make(map[string][]float64),
	latencyCount:   make(map[string]int64),
	latencySum:     make(map[string]float64),
	uptimeStart:    time.Now(),
}

// SetMetricsDB registers the pool whose statistics are exported with the
// application metrics. It is called once at router construction; passing nil
// simply omits the database series.
func SetMetricsDB(db *sql.DB) {
	globalMetrics.mu.Lock()
	globalMetrics.db = db
	globalMetrics.mu.Unlock()
}

// maxLatencySamples caps the samples retained per endpoint for quantile
// estimation. Count and sum are tracked separately so they stay exact even
// after the sample buffer is full.
const maxLatencySamples = 1000

func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		atomic.AddInt64(&globalMetrics.requestsActive, 1)
		defer atomic.AddInt64(&globalMetrics.requestsActive, -1)

		start := time.Now()
		c.Next()

		latency := time.Since(start).Seconds()
		method := c.Request.Method
		path := normalizePath(c.Request.URL.Path)
		status := c.Writer.Status()
		key := method + " " + path

		globalMetrics.mu.Lock()
		globalMetrics.requestsTotal[key]++
		globalMetrics.latencyCount[key]++
		globalMetrics.latencySum[key] += latency
		samples := globalMetrics.latencySamples[key]
		if len(samples) < maxLatencySamples {
			globalMetrics.latencySamples[key] = append(samples, latency)
		}
		if status >= 400 {
			errKey := fmt.Sprintf("%d %s %s", status, method, path)
			globalMetrics.errorsTotal[errKey]++
		}
		globalMetrics.mu.Unlock()
	}
}

func MetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		globalMetrics.mu.RLock()
		defer globalMetrics.mu.RUnlock()

		var sb strings.Builder
		uptime := time.Since(globalMetrics.uptimeStart)

		sb.WriteString("# HELP seagles_uptime_seconds Service uptime\n")
		sb.WriteString("# TYPE seagles_uptime_seconds gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_uptime_seconds %0.f\n", uptime.Seconds()))

		sb.WriteString("\n# HELP seagles_requests_active Currently active requests\n")
		sb.WriteString("# TYPE seagles_requests_active gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_requests_active %d\n", atomic.LoadInt64(&globalMetrics.requestsActive)))

		sb.WriteString("\n# HELP seagles_requests_total Total requests by endpoint\n")
		sb.WriteString("# TYPE seagles_requests_total counter\n")
		for key, count := range globalMetrics.requestsTotal {
			labelKey := prometheusLabelKey(key)
			sb.WriteString(fmt.Sprintf("seagles_requests_total{endpoint=\"%s\"} %d\n", labelKey, count))
		}

		sb.WriteString("\n# HELP seagles_errors_total Total errors by endpoint\n")
		sb.WriteString("# TYPE seagles_errors_total counter\n")
		for key, count := range globalMetrics.errorsTotal {
			labelKey := prometheusLabelKey(key)
			sb.WriteString(fmt.Sprintf("seagles_errors_total{error=\"%s\"} %d\n", labelKey, count))
		}

		// Emit real quantiles instead of labelling a plain mean as a summary.
		// Nearest-rank estimation over the bounded sample buffer is a valid
		// Prometheus summary and makes p95/p99 alerting possible.
		sb.WriteString("\n# HELP seagles_request_latency_seconds Request latency\n")
		sb.WriteString("# TYPE seagles_request_latency_seconds summary\n")
		for key, samples := range globalMetrics.latencySamples {
			if len(samples) == 0 {
				continue
			}
			sorted := append([]float64(nil), samples...)
			sort.Float64s(sorted)
			labelKey := prometheusLabelKey(key)
			for _, q := range []struct {
				name  string
				value float64
			}{
				{"0.5", quantile(sorted, 0.50)},
				{"0.95", quantile(sorted, 0.95)},
				{"0.99", quantile(sorted, 0.99)},
			} {
				sb.WriteString(fmt.Sprintf("seagles_request_latency_seconds{endpoint=\"%s\",quantile=\"%s\"} %f\n",
					labelKey, q.name, q.value))
			}
			sb.WriteString(fmt.Sprintf("seagles_request_latency_seconds_sum{endpoint=\"%s\"} %f\n",
				labelKey, globalMetrics.latencySum[key]))
			sb.WriteString(fmt.Sprintf("seagles_request_latency_seconds_count{endpoint=\"%s\"} %d\n",
				labelKey, globalMetrics.latencyCount[key]))
		}

		// USE / saturation signals the request counters alone cannot provide.
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		var gcPause uint64
		if len(mem.PauseNs) > 0 {
			gcPause = mem.PauseNs[(mem.NumGC+255)%256]
		}
		sb.WriteString("\n# HELP seagles_go_goroutines Number of goroutines\n")
		sb.WriteString("# TYPE seagles_go_goroutines gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_go_goroutines %d\n", runtime.NumGoroutine()))
		sb.WriteString("\n# HELP seagles_memory_heap_bytes Heap memory currently allocated\n")
		sb.WriteString("# TYPE seagles_memory_heap_bytes gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_memory_heap_bytes %d\n", mem.HeapAlloc))
		sb.WriteString("\n# HELP seagles_memory_sys_bytes Total memory obtained from the OS\n")
		sb.WriteString("# TYPE seagles_memory_sys_bytes gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_memory_sys_bytes %d\n", mem.Sys))
		sb.WriteString("\n# HELP seagles_gc_collections_total Number of completed GC cycles\n")
		sb.WriteString("# TYPE seagles_gc_collections_total counter\n")
		sb.WriteString(fmt.Sprintf("seagles_gc_collections_total %d\n", mem.NumGC))
		sb.WriteString("\n# HELP seagles_gc_last_pause_seconds Duration of the most recent GC pause\n")
		sb.WriteString("# TYPE seagles_gc_last_pause_seconds gauge\n")
		sb.WriteString(fmt.Sprintf("seagles_gc_last_pause_seconds %f\n", float64(gcPause)/1e9))

		if db := globalMetrics.db; db != nil {
			stats := db.Stats()
			sb.WriteString("\n# HELP seagles_db_connections_open Open database connections\n")
			sb.WriteString("# TYPE seagles_db_connections_open gauge\n")
			sb.WriteString(fmt.Sprintf("seagles_db_connections_open %d\n", stats.OpenConnections))
			sb.WriteString("\n# HELP seagles_db_connections_in_use Connections currently checked out\n")
			sb.WriteString("# TYPE seagles_db_connections_in_use gauge\n")
			sb.WriteString(fmt.Sprintf("seagles_db_connections_in_use %d\n", stats.InUse))
			sb.WriteString("\n# HELP seagles_db_connections_idle Idle connections\n")
			sb.WriteString("# TYPE seagles_db_connections_idle gauge\n")
			sb.WriteString(fmt.Sprintf("seagles_db_connections_idle %d\n", stats.Idle))
			sb.WriteString("\n# HELP seagles_db_wait_count_total Queries that waited for a connection\n")
			sb.WriteString("# TYPE seagles_db_wait_count_total counter\n")
			sb.WriteString(fmt.Sprintf("seagles_db_wait_count_total %d\n", stats.WaitCount))
			sb.WriteString("\n# HELP seagles_db_wait_duration_seconds Time spent waiting for a connection\n")
			sb.WriteString("# TYPE seagles_db_wait_duration_seconds counter\n")
			sb.WriteString(fmt.Sprintf("seagles_db_wait_duration_seconds %f\n", stats.WaitDuration.Seconds()))
		}

		c.String(200, sb.String())
	}
}

func normalizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isUUID(part) || isNumeric(part) {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && r != '-' {
			return false
		}
	}
	return true
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func prometheusLabelKey(s string) string {
	r := strings.NewReplacer(" ", "_", "\"", "", "/", "_")
	return r.Replace(s)
}
