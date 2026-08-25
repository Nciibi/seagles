package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// redisAddr converts common REDIS_URL forms ("redis:6379", "redis://host:6379",
// "rediss://host:6379/2") into a dialable host:port address.
func redisAddr(redisURL string) string {
	addr := strings.TrimSpace(redisURL)
	addr = strings.TrimPrefix(addr, "rediss://")
	addr = strings.TrimPrefix(addr, "redis://")
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i] // drop database path
	}
	if addr != "" && !strings.Contains(addr, ":") {
		addr += ":6379"
	}
	return addr
}

// CheckRedis performs a real RESP PING over TCP. The previous implementation
// issued an HTTP GET to the Redis port, which Redis cannot answer — so the
// health check always failed whenever REDIS_URL was configured.
func CheckRedis(redisURL string) bool {
	conn, err := net.DialTimeout("tcp", redisAddr(redisURL), 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return false
	}

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(buf[:n]), "+PONG")
}

func CheckMinIO(endpoint string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/minio/health/live", endpoint))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func CheckFirmwareAnalyzer(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
