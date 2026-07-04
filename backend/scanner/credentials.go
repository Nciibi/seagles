package scanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/seagles/slog"
	"golang.org/x/crypto/ssh"
)

type Credential struct {
	Username string
	Password string
}

type CredentialResult struct {
	Tested    int      `json:"tested"`
	Found     bool     `json:"found"`
	Username  string   `json:"username,omitempty"`
	Password  string   `json:"password,omitempty"`
	Method    string   `json:"method"`
	LockedOut bool     `json:"locked_out"`
	AuditLog  []string `json:"audit_log"`
}

func LoadCredentials(filepath string) ([]Credential, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("credential file not found: %s", filepath)
	}
	defer file.Close()

	var creds []Credential
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		password := parts[1]
		if password == "(blank)" {
			password = ""
		}
		creds = append(creds, Credential{
			Username: parts[0],
			Password: password,
		})
		if len(creds) >= 100 {
			break
		}
	}

	return creds, scanner.Err()
}

func TestSSHCreds(ip string, port int, creds []Credential, maxPairs int) CredentialResult {
	result := CredentialResult{Method: "ssh"}
	addr := fmt.Sprintf("%s:%d", ip, port)

	limit := maxPairs
	if limit > 50 {
		limit = 50
	}
	if limit > len(creds) {
		limit = len(creds)
	}

	consecutiveFailures := 0

	for i := 0; i < limit; i++ {
		cred := creds[i]
		result.Tested++

		logEntry := fmt.Sprintf("[CRED-TEST] SSH %s user=%s", addr, cred.Username)
		result.AuditLog = append(result.AuditLog, logEntry)

		config := &ssh.ClientConfig{
			User: cred.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(cred.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		conn, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			conn.Close()
			result.Found = true
			result.Username = cred.Username
			result.Password = cred.Password
			slog.Warn("Default SSH credentials found", "ip", ip, "username", cred.Username)
			return result
		}

		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "too many") || strings.Contains(errStr, "locked") {
			result.LockedOut = true
			slog.Warn("SSH credential lockout", "ip", ip)
			return result
		}

		consecutiveFailures++
		if consecutiveFailures >= 3 {
			consecutiveFailures = 0
		}

		time.Sleep(500 * time.Millisecond)
	}

	return result
}

func TestHTTPBasicCreds(ip string, port int, path string, creds []Credential, maxPairs int) CredentialResult {
	result := CredentialResult{Method: "http-basic"}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, port, path)

	limit := maxPairs
	if limit > 50 {
		limit = 50
	}
	if limit > len(creds) {
		limit = len(creds)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for i := 0; i < limit; i++ {
		cred := creds[i]
		result.Tested++

		logEntry := fmt.Sprintf("[CRED-TEST] HTTP-BASIC %s user=%s", url, cred.Username)
		result.AuditLog = append(result.AuditLog, logEntry)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		authStr := base64.StdEncoding.EncodeToString(
			[]byte(fmt.Sprintf("%s:%s", cred.Username, cred.Password)))
		req.Header.Set("Authorization", "Basic "+authStr)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body := make([]byte, 1024)
		n, _ := io.ReadAtLeast(resp.Body, body, 1)
		resp.Body.Close()
		bodyStr := strings.ToLower(string(body[:n]))

		if resp.StatusCode == 429 {
			result.LockedOut = true
			slog.Warn("HTTP rate limited", "ip", ip)
			return result
		}

		if strings.Contains(bodyStr, "locked") || strings.Contains(bodyStr, "disabled") {
			result.LockedOut = true
			slog.Warn("HTTP account locked", "ip", ip)
			return result
		}

		if resp.StatusCode == 200 {
			result.Found = true
			result.Username = cred.Username
			result.Password = cred.Password
			slog.Warn("Default HTTP credentials found", "ip", ip, "username", cred.Username)
			return result
		}

		time.Sleep(500 * time.Millisecond)
	}

	return result
}

func TestTelnetCreds(ip string, port int, creds []Credential, maxPairs int) CredentialResult {
	result := CredentialResult{Method: "telnet"}
	addr := fmt.Sprintf("%s:%d", ip, port)

	limit := maxPairs
	if limit > 50 {
		limit = 50
	}
	if limit > len(creds) {
		limit = len(creds)
	}

	for i := 0; i < limit; i++ {
		cred := creds[i]
		result.Tested++

		logEntry := fmt.Sprintf("[CRED-TEST] TELNET %s user=%s", addr, cred.Username)
		result.AuditLog = append(result.AuditLog, logEntry)

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			break
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		banner := make([]byte, 1024)
		conn.Read(banner)

		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte(cred.Username + "\n"))

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp1 := make([]byte, 1024)
		conn.Read(resp1)

		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte(cred.Password + "\n"))

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp2 := make([]byte, 1024)
		n, _ := conn.Read(resp2)
		conn.Close()

		if n > 0 {
			response := strings.ToLower(string(resp2[:n]))
			if !strings.Contains(response, "incorrect") &&
				!strings.Contains(response, "failed") &&
				!strings.Contains(response, "denied") &&
				!strings.Contains(response, "invalid") &&
				!strings.Contains(response, "wrong") {
				result.Found = true
				result.Username = cred.Username
				result.Password = cred.Password
				slog.Warn("Default Telnet credentials found", "ip", ip, "username", cred.Username)
				return result
			}
		}

		time.Sleep(500 * time.Millisecond)
	}

	return result
}
