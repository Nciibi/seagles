package scanner

// IoT-specific port definitions for scanning

// CommonIoTPorts lists the ports IronMesh scans for IoT devices.
var CommonIoTPorts = []int{
	22,    // SSH
	23,    // Telnet (immediate red flag)
	80,    // HTTP management interface
	443,   // HTTPS management interface
	554,   // RTSP (cameras)
	1883,  // MQTT (plaintext)
	1884,  // MQTT alternate
	5555,  // ADB (Android Debug Bridge — BadBox indicator)
	8883,  // MQTTS (MQTT over TLS)
	47808, // BACnet (building automation — OT protocol)
	502,   // Modbus (industrial control — OT protocol)
}

// PortRisk maps ports to their associated risk level.
var PortRisk = map[int]string{
	23:    "critical", // Telnet — credentials in plaintext
	5555:  "critical", // ADB — supply chain compromise indicator
	502:   "critical", // Modbus — no authentication by design
	1883:  "high",     // MQTT plaintext — credentials exposed
	554:   "high",     // RTSP — potential camera surveillance
	47808: "high",     // BACnet — building automation protocol
	80:    "medium",   // HTTP — management interface
	443:   "low",      // HTTPS — check TLS version
	22:    "low",      // SSH — check for default creds
}
