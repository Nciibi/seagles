package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/seagles/slog"
)

type ProtocolFinding struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

func DetectProtocols(ip string, openPorts []int) []ProtocolFinding {
	var findings []ProtocolFinding
	portSet := make(map[int]bool)
	for _, p := range openPorts {
		portSet[p] = true
	}

	if portSet[23] {
		if f := detectTelnet(ip, 23); f != nil {
			findings = append(findings, *f)
		}
	}

	if portSet[5555] {
		if f := detectADB(ip, 5555); f != nil {
			findings = append(findings, *f)
		}
	}

	if portSet[1883] {
		if f := detectMQTT(ip, 1883); f != nil {
			findings = append(findings, *f)
		}
	}

	if portSet[502] {
		if f := detectModbus(ip, 502); f != nil {
			findings = append(findings, *f)
		}
	}

	if portSet[554] {
		if f := detectRTSP(ip, 554); f != nil {
			findings = append(findings, *f)
		}
	}

	if portSet[8443] || portSet[8883] {
		if f := detectTLS(ip, portSet); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func detectTelnet(ip string, port int) *ProtocolFinding {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
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
		slog.Warn("Telnet detected", "ip", ip, "port", port)
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

func detectADB(ip string, port int) *ProtocolFinding {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
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

	slog.Warn("ADB detected", "ip", ip, "port", port)
	return &ProtocolFinding{
		Protocol:    "ADB",
		Port:        port,
		Risk:        "critical",
		Description: "Android Debug Bridge exposed - BadBox 2.0 indicator",
		Evidence:    evidence,
	}
}

func detectMQTT(ip string, port int) *ProtocolFinding {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	mqttConnect := []byte{
		0x10, 0x0d,
		0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
		0x04,
		0x02,
		0x00, 0x3c,
		0x00, 0x01, 0x00,
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

	if resp[0] == 0x20 {
		slog.Warn("Plaintext MQTT detected", "ip", ip, "port", port)
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

func detectModbus(ip string, port int) *ProtocolFinding {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	modbusReq := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x11,
		0x00, 0x00, 0x00, 0x00,
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

	slog.Warn("Modbus detected", "ip", ip, "port", port)
	return &ProtocolFinding{
		Protocol:    "Modbus",
		Port:        port,
		Risk:        "critical",
		Description: "Industrial Modbus protocol detected - no authentication by design",
		Evidence:    fmt.Sprintf("Received %d byte response to Modbus query", n),
	}
}

func detectRTSP(ip string, port int) *ProtocolFinding {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

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
	if strings.Contains(response, "200 OK") && !strings.Contains(response, "401") {
		slog.Warn("Unauthenticated RTSP detected", "ip", ip, "port", port)
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

func detectTLS(ip string, portSet map[int]bool) *ProtocolFinding {
	ports := []int{8443, 8883}
	for _, p := range ports {
		if portSet[p] {
			return &ProtocolFinding{
				Protocol:    "TLS-service",
				Port:        p,
				Risk:        "medium",
				Description: fmt.Sprintf("TLS service on port %d - verify certificate and cipher strength", p),
				Evidence:    fmt.Sprintf("Port %d is open", p),
			}
		}
	}
	return nil
}
