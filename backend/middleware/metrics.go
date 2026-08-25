package middleware

import (
	"fmt"
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
	latencyBuckets map[string][]float64
	uptimeStart    time.Time
}

var globalMetrics = &Metrics{
	requestsTotal:  make(map[string]int64),
	errorsTotal:    make(map[string]int64),
	latencyBuckets: make(map[string][]float64),
	uptimeStart:    time.Now(),
}

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
		bucket := globalMetrics.latencyBuckets[key]
		if len(bucket) < maxLatencySamples {
			globalMetrics.latencyBuckets[key] = append(bucket, latency)
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

		sb.WriteString("\n# HELP seagles_request_latency_seconds Request latency\n")
		sb.WriteString("# TYPE seagles_request_latency_seconds summary\n")
		for key, buckets := range globalMetrics.latencyBuckets {
			if len(buckets) == 0 {
				continue
			}
			var sum float64
			for _, v := range buckets {
				sum += v
			}
			avg := sum / float64(len(buckets))
			labelKey := prometheusLabelKey(key)
			sb.WriteString(fmt.Sprintf("seagles_request_latency_seconds{endpoint=\"%s\"} %f\n", labelKey, avg))
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
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == '-') {
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
