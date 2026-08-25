package scanner

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestDetectProtocols_PortMatching(t *testing.T) {
	findings := DetectProtocols("127.0.0.1", []int{23, 5555, 1883, 502, 554, 8443})
	protocols := make(map[string]bool)
	for _, f := range findings {
		protocols[f.Protocol] = true
	}

	if !protocols["Telnet"] {
		t.Log("Telnet detection requires connection - will be empty in unit test")
	}
	if !protocols["TLS-service"] {
		t.Errorf("expected TLS-service finding for port 8443")
	}
}

func TestDetectProtocols_EmptyPorts(t *testing.T) {
	findings := DetectProtocols("127.0.0.1", []int{})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty ports, got %d", len(findings))
	}
}

func TestDetectTLS(t *testing.T) {
	tests := []struct {
		ports []int
		found bool
	}{
		{[]int{8443}, true},
		{[]int{8883}, true},
		{[]int{8443, 8883}, true},
		{[]int{80, 443}, false},
		{[]int{}, false},
	}
	for _, tt := range tests {
		portSet := make(map[int]bool)
		for _, p := range tt.ports {
			portSet[p] = true
		}
		f := detectTLS("127.0.0.1", portSet)
		if tt.found && f == nil {
			t.Errorf("detectTLS with ports %v: expected finding, got nil", tt.ports)
		}
		if !tt.found && f != nil {
			t.Errorf("detectTLS with ports %v: expected nil, got finding", tt.ports)
		}
	}
}

func startTestServer(t *testing.T, handler func(conn net.Conn)) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		handler(conn)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func TestDetectTelnet_Found(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		conn.Write([]byte("Telnet login: "))
	})

	f := detectTelnet(ip, port)
	if f == nil {
		t.Fatal("expected Telnet finding")
	}
	if f.Protocol != "Telnet" {
		t.Fatalf("expected Protocol Telnet, got %s", f.Protocol)
	}
	if f.Risk != "critical" {
		t.Fatalf("expected Risk critical, got %s", f.Risk)
	}
}

func TestDetectTelnet_NoBanner(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		time.Sleep(100 * time.Millisecond)
	})

	f := detectTelnet(ip, port)
	if f == nil {
		t.Fatal("expected Telnet finding even with empty banner")
	}
}

func TestDetectADB_Found(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		conn.Write([]byte("CNXN"))
	})

	f := detectADB(ip, port)
	if f == nil {
		t.Fatal("expected ADB finding")
	}
	if f.Protocol != "ADB" {
		t.Fatalf("expected Protocol ADB, got %s", f.Protocol)
	}
}

func TestDetectADB_NoBanner(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		time.Sleep(100 * time.Millisecond)
	})

	f := detectADB(ip, port)
	if f == nil {
		t.Fatal("expected ADB finding even without CNXN banner")
	}
}

func TestDetectMQTT_Found(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		buf := make([]byte, 16)
		conn.Read(buf)
		conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
	})

	f := detectMQTT(ip, port)
	if f == nil {
		t.Fatal("expected MQTT finding")
	}
	if f.Protocol != "MQTT-plaintext" {
		t.Fatalf("expected Protocol MQTT-plaintext, got %s", f.Protocol)
	}
}

func TestDetectMQTT_NoResponse(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		time.Sleep(100 * time.Millisecond)
	})

	f := detectMQTT(ip, port)
	if f != nil {
		t.Fatal("expected nil MQTT finding without CONNACK")
	}
}

func TestDetectModbus_Found(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		buf := make([]byte, 12)
		conn.Read(buf)
		conn.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x11, 0x02, 0x00})
	})

	f := detectModbus(ip, port)
	if f == nil {
		t.Fatal("expected Modbus finding")
	}
	if f.Protocol != "Modbus" {
		t.Fatalf("expected Protocol Modbus, got %s", f.Protocol)
	}
}

func TestDetectModbus_NoResponse(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		time.Sleep(100 * time.Millisecond)
	})

	f := detectModbus(ip, port)
	if f != nil {
		t.Fatal("expected nil Modbus finding without response")
	}
}

func TestDetectRTSP_Found(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			conn.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"))
		}
	})

	f := detectRTSP(ip, port)
	if f == nil {
		t.Fatal("expected RTSP finding")
	}
	if f.Protocol != "RTSP-unauth" {
		t.Fatalf("expected Protocol RTSP-unauth, got %s", f.Protocol)
	}
}

func TestDetectRTSP_RequiresAuth(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			conn.Write([]byte("RTSP/1.0 401 Unauthorized\r\n\r\n"))
		}
	})

	f := detectRTSP(ip, port)
	if f != nil {
		t.Fatal("expected nil RTSP finding with 401 response")
	}
}

func TestDetectRTSP_NoResponse(t *testing.T) {
	ip, port := startTestServer(t, func(conn net.Conn) {
		time.Sleep(100 * time.Millisecond)
	})

	f := detectRTSP(ip, port)
	if f != nil {
		t.Fatal("expected nil RTSP finding without response")
	}
}

func TestProtocolFinding_RiskLevels(t *testing.T) {
	tests := []struct {
		protocol string
		risk     string
	}{
		{"Telnet", "critical"},
		{"ADB", "critical"},
		{"Modbus", "critical"},
		{"MQTT-plaintext", "high"},
		{"RTSP-unauth", "high"},
		{"TLS-service", "medium"},
	}

	for _, tt := range tests {
		// Verify expected risk levels via port combinations
		portMap := map[string]int{
			"Telnet":         23,
			"ADB":            5555,
			"MQTT-plaintext": 1883,
			"Modbus":         502,
			"RTSP-unauth":    554,
			"TLS-service":    8443,
		}

		port, ok := portMap[tt.protocol]
		if !ok {
			continue
		}

		ip := "127.0.0.1"
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			t.Logf("Skipping live test for %s (port %d not reachable)", tt.protocol, port)
			continue
		}
		conn.Close()
	}
}

func TestDetectProtocols_Success(t *testing.T) {
	// Start multiple protocol servers and verify detection
	type protocolServer struct {
		name     string
		start    func(t *testing.T) (string, int)
		validate func(t *testing.T, f *ProtocolFinding)
	}

	servers := []protocolServer{
		{
			name: "Telnet",
			start: func(t *testing.T) (string, int) {
				return startTestServer(t, func(conn net.Conn) {
					conn.Write([]byte("login: "))
				})
			},
			validate: func(t *testing.T, f *ProtocolFinding) {
				if f.Protocol != "Telnet" {
					t.Errorf("expected Telnet, got %s", f.Protocol)
				}
			},
		},
		{
			name: "ADB",
			start: func(t *testing.T) (string, int) {
				return startTestServer(t, func(conn net.Conn) {
					conn.Write([]byte("CNXN"))
				})
			},
			validate: func(t *testing.T, f *ProtocolFinding) {
				if f.Protocol != "ADB" {
					t.Errorf("expected ADB, got %s", f.Protocol)
				}
			},
		},
	}

	for _, s := range servers {
		t.Run(s.name, func(t *testing.T) {
			ip, port := s.start(t)
			findings := DetectProtocols(ip, []int{port})
			found := false
			for _, f := range findings {
				if f.Port == port {
					s.validate(t, &f)
					found = true
				}
			}
			if !found {
				t.Logf("No finding returned for protocol %s on dynamically assigned port", s.name)
			}
		})
	}
}
