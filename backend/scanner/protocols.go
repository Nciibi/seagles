package scanner

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// ProtocolFinding represents a detected dangerous protocol on a device.
type ProtocolFinding struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Risk        string `json:"risk"` // "critical", "high", "medium"
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// DetectProtocols checks for dangerous protocols on the given open ports.
func DetectProtocols(ip string, openPorts []int) []ProtocolFinding {
	var findings []ProtocolFinding
	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	// Telnet detection (port 23)
	if portSet[23] {
		if f := detectTelnet(ip, 23); f != nil {
			findings = append(findings, *f)
		}
	}

	// ADB detection (port 5555)
	if portSet[5555] {
		if f := detectADB(ip, 5555); f != nil {
			findings = append(findings, *f)
		}
	}

	// MQTT plaintext detection (port 1883)
	if portSet[1883] {
		if f := detectMQTT(ip, 1883); f != nil {
			findings = append(findings, *f)
		}
	}

	// Modbus detection (port 502)
	if portSet[502] {
		if f := detectModbus(ip, 502); f != nil {
			findings = append(findings, *f)
		}
	}

	// RTSP unauthenticated detection (port 554)
	if portSet[554] {
		if f := detectRTSP(ip, 554); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

// detectTelnet attempts a TCP connection to port 23 and reads the banner.
func detectTelnet(ip string, port int) *ProtocolFinding {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	evidence := "TCP connection accepted"
	if n > 0 {
		evidence = fmt.Sprintf("Banner: %s", strings.TrimSpace(banner))
	}

	if n == 0 || strings.Contains(strings.ToLower(banner), "login") ||
		strings.Contains(strings.ToLower(banner), "telnet") ||
		strings.Contains(strings.ToLower(banner), "username") {
		log.Printf("[PROTOCOL] Telnet detected on %s:%d", ip, port)
		return &ProtocolFinding{
			Protocol:    "Telnet",
			Port:        port,
			Risk:        "critical",
			Description: "Telnet exposes credentials in plaintext",
			Evidence:    evidence,
		}
	}

	return nil
}

// detectADB attempts to detect Android Debug Bridge on port 5555.
func detectADB(ip string, port int) *ProtocolFinding {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)

	evidence := "TCP connection accepted on ADB port"
	if n >= 4 && string(buf[:4]) == "CNXN" {
		evidence = "ADB CNXN banner detected"
	}

	log.Printf("[PROTOCOL] ADB detected on %s:%d", ip, port)
	return &ProtocolFinding{
		Protocol:    "ADB",
		Port:        port,
		Risk:        "critical",
		Description: "Android Debug Bridge exposed - BadBox 2.0 indicator",
		Evidence:    evidence,
	}
}

// detectMQTT sends an MQTT CONNECT packet to detect a plaintext MQTT broker.
func detectMQTT(ip string, port int) *ProtocolFinding {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// MQTT CONNECT packet
	mqttConnect := []byte{
		0x10, 0x0d, // Fixed header: CONNECT, remaining length 13
		0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, // Protocol name "MQTT"
		0x04,       // Protocol level 4 (MQTT 3.1.1)
		0x02,       // Connect flags (clean session)
		0x00, 0x3c, // Keep alive 60s
		0x00, 0x01, 0x00, // Client ID length 1, empty
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(mqttConnect)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 4)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return nil
	}

	// MQTT CONNACK starts with byte 0x20
	if resp[0] == 0x20 {
		log.Printf("[PROTOCOL] MQTT plaintext detected on %s:%d", ip, port)
		return &ProtocolFinding{
			Protocol:    "MQTT-plaintext",
			Port:        port,
			Risk:        "high",
			Description: "MQTT broker without TLS - credentials transmitted in cleartext",
			Evidence:    "CONNACK response received on plaintext port",
		}
	}

	return nil
}

// detectModbus sends a Modbus request to detect industrial control protocol.
func detectModbus(ip string, port int) *ProtocolFinding {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Modbus TCP: Transaction ID, Protocol ID, Length, Unit ID, Function Code 0x11 (Report Slave ID)
	modbusReq := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID (Modbus)
		0x00, 0x06, // Length
		0x01,                               // Unit ID
		0x11,                               // Function code: Report Slave ID
		0x00, 0x00, 0x00, 0x00,             // Data
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(modbusReq)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return nil
	}

	log.Printf("[PROTOCOL] Modbus detected on %s:%d", ip, port)
	return &ProtocolFinding{
		Protocol:    "Modbus",
		Port:        port,
		Risk:        "critical",
		Description: "Industrial Modbus protocol detected - no authentication by design",
		Evidence:    fmt.Sprintf("Received %d byte response to Modbus query", n),
	}
}

// detectRTSP sends an RTSP OPTIONS request to check for unauthenticated camera streams.
func detectRTSP(ip string, port int) *ProtocolFinding {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send RTSP OPTIONS request
	request := fmt.Sprintf("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port)
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte(request))
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return nil
	}

	response := string(resp[:n])
	// If we get 200 OK without 401 Unauthorized, stream is unauthenticated
	if strings.Contains(response, "200 OK") && !strings.Contains(response, "401") {
		log.Printf("[PROTOCOL] Unauthenticated RTSP detected on %s:%d", ip, port)
		return &ProtocolFinding{
			Protocol:    "RTSP-unauth",
			Port:        port,
			Risk:        "high",
			Description: "Camera stream accessible without authentication",
			Evidence:    "RTSP OPTIONS returned 200 OK without authentication challenge",
		}
	}

	return nil
}
