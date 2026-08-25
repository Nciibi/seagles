package scanner

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCredFile(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "default-credentials.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCredentials(t *testing.T) {
	path := writeCredFile(t, []string{
		"# comment line",
		"",
		"admin:admin",
		"root:(blank)",
		"no-colon-line",
		"user:pass:with:colons",
	})

	creds, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials error: %v", err)
	}

	if len(creds) != 3 {
		t.Fatalf("got %d creds, want 3: %+v", len(creds), creds)
	}
	if creds[0] != (Credential{Username: "admin", Password: "admin"}) {
		t.Errorf("unexpected first cred: %+v", creds[0])
	}
	if creds[1] != (Credential{Username: "root", Password: ""}) {
		t.Errorf("\"(blank)\" should map to empty password, got %+v", creds[1])
	}
	if creds[2] != (Credential{Username: "user", Password: "pass:with:colons"}) {
		t.Errorf("password should keep colons after first split, got %+v", creds[2])
	}
}

func TestLoadCredentials_CapsAt100(t *testing.T) {
	lines := make([]string, 0, 150)
	for i := 0; i < 150; i++ {
		lines = append(lines, fmt.Sprintf("user%d:pass%d", i, i))
	}

	creds, err := LoadCredentials(writeCredFile(t, lines))
	if err != nil {
		t.Fatalf("LoadCredentials error: %v", err)
	}
	if len(creds) != 100 {
		t.Errorf("expected cap at 100, got %d", len(creds))
	}
}

func TestLoadCredentials_MissingFile(t *testing.T) {
	if _, err := LoadCredentials(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected error for missing credential file")
	}
}

func TestHTTPBasicCreds_FindsDefaultPassword(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(gotAuth, "b2s6cGFzc3dvcmQxMjM=") { // ok:password123
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>Welcome to admin panel</html>")
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="router"`)
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	creds := []Credential{
		{Username: "wrong", Password: "nope"},
		{Username: "ok", Password: "password123"},
	}
	result := TestHTTPBasicCreds(host, port, "/", creds, 50)

	if !result.Found {
		t.Fatal("expected default credentials to be found")
	}
	if result.Username != "ok" || result.Password != "password123" {
		t.Errorf("unexpected match: %s/%s", result.Username, result.Password)
	}
	if result.Tested != 2 {
		t.Errorf("Tested = %d, want 2", result.Tested)
	}
	if result.LockedOut {
		t.Error("should not report lockout")
	}
	if result.Method != "http-basic" {
		t.Errorf("Method = %q", result.Method)
	}
	if len(result.AuditLog) != 2 {
		t.Errorf("expected 2 audit entries, got %d", len(result.AuditLog))
	}
	if !strings.Contains(gotAuth, "Basic ") {
		t.Errorf("server did not receive Basic auth header: %q", gotAuth)
	}
}

func TestHTTPBasicCreds_LockoutOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	creds := []Credential{{Username: "a", Password: "b"}, {Username: "c", Password: "d"}}
	result := TestHTTPBasicCreds(host, port, "/", creds, 50)

	if !result.LockedOut {
		t.Error("expected lockout on HTTP 429")
	}
	if result.Found {
		t.Error("nothing should be found during lockout")
	}
	if result.Tested != 1 {
		t.Errorf("lockout must stop immediately, Tested = %d", result.Tested)
	}
}

func TestHTTPBasicCreds_LockoutOnBodyKeyword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Your account has been locked by the administrator")
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	result := TestHTTPBasicCreds(host, port, "/", []Credential{{Username: "u", Password: "p"}}, 50)
	if !result.LockedOut {
		t.Error("expected lockout detection from response body keyword")
	}
}

func TestHTTPBasicCreds_MaxPairsCap(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	creds := make([]Credential, 80)
	for i := range creds {
		creds[i] = Credential{Username: fmt.Sprintf("u%d", i), Password: "p"}
	}

	result := TestHTTPBasicCreds(host, port, "/", creds, 100)
	if result.Tested > 50 {
		t.Errorf("hard cap of 50 pairs exceeded: tested %d", result.Tested)
	}
}

func TestTelnetCreds_Success(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf) // username
		user := strings.TrimSpace(string(buf[:n]))
		conn.Write([]byte("Password: "))
		n, _ = conn.Read(buf) // password
		pass := strings.TrimSpace(string(buf[:n]))

		if user == "admin" && pass == "admin" {
			conn.Write([]byte("Welcome to the router shell\r\n# "))
		} else {
			conn.Write([]byte("Login incorrect\r\n"))
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	result := TestTelnetCreds("127.0.0.1", port, []Credential{{Username: "admin", Password: "admin"}}, 10)

	if !result.Found {
		t.Fatalf("expected telnet default creds to be found, got %+v", result)
	}
	if result.Method != "telnet" || result.Username != "admin" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestTelnetCreds_Rejected(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte("Password: "))
		conn.Read(buf)
		conn.Write([]byte("Login incorrect\r\n"))
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	result := TestTelnetCreds("127.0.0.1", port, []Credential{{Username: "admin", Password: "bad"}}, 10)

	if result.Found {
		t.Error("incorrect login must not be reported as found")
	}
}

func TestSSHCreds_ConnectionRefused(t *testing.T) {
	// Closed port: dial fails instantly; loop should complete without finding.
	result := TestSSHCreds("127.0.0.1", closedTCPPort(t), []Credential{
		{Username: "admin", Password: "admin"},
	}, 5)

	if result.Found {
		t.Error("nothing should be found on a closed port")
	}
	if result.LockedOut {
		t.Error("connection refused is not a lockout")
	}
	if result.Tested != 1 {
		t.Errorf("Tested = %d, want 1", result.Tested)
	}
	if len(result.AuditLog) != 1 || !strings.Contains(result.AuditLog[0], "[CRED-TEST] SSH") {
		t.Errorf("missing SSH audit entry: %v", result.AuditLog)
	}
}

// closedTCPPort returns a local TCP port with no listener.
func closedTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}
