package scanner

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yourusername/seagles/alerts"
)

// PassiveMonitor listens for broadcast traffic (ARP, DHCP, mDNS, UPnP) to discover devices
// without sending any active probes.
type PassiveMonitor struct {
	db        *sql.DB
	ifaceName string
	quit      chan struct{}
}

// NewPassiveMonitor creates a new passive traffic monitor.
func NewPassiveMonitor(db *sql.DB, interfaceName string) *PassiveMonitor {
	if interfaceName == "" {
		interfaceName = "eth0" // Default interface
	}
	return &PassiveMonitor{
		db:        db,
		ifaceName: interfaceName,
		quit:      make(chan struct{}),
	}
}

// Start begins passive monitoring on the configured interface.
func (pm *PassiveMonitor) Start() {
	handle, err := pcap.OpenLive(pm.ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[PASSIVE-MONITOR] Failed to open interface %s: %v", pm.ifaceName, err)
		log.Printf("[PASSIVE-MONITOR] Note: gopacket requires root/capabilities and libpcap. Skipping passive monitor.")
		return
	}
	defer handle.Close()

	// Filter for ARP, DHCP, mDNS, and SSDP/UPnP
	err = handle.SetBPFFilter("arp or port 67 or port 68 or port 5353 or port 1900")
	if err != nil {
		log.Printf("[PASSIVE-MONITOR] Failed to set BPF filter: %v", err)
		return
	}

	log.Printf("[PASSIVE-MONITOR] Started listening on %s", pm.ifaceName)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-pm.quit:
			log.Println("[PASSIVE-MONITOR] Stopping...")
			return
		case packet := <-packetSource.Packets():
			if packet != nil {
				pm.processPacket(packet)
			}
		}
	}
}

// Stop halts the passive monitor.
func (pm *PassiveMonitor) Stop() {
	close(pm.quit)
}

func (pm *PassiveMonitor) processPacket(packet gopacket.Packet) {
	// 1. ARP processing
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		// We only care about sender IP and MAC
		if arp.Operation == layers.ARPRequest || arp.Operation == layers.ARPReply {
			ip := fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
			mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp.SourceHwAddress[0], arp.SourceHwAddress[1], arp.SourceHwAddress[2], arp.SourceHwAddress[3], arp.SourceHwAddress[4], arp.SourceHwAddress[5])
			if ip != "0.0.0.0" && mac != "00:00:00:00:00:00" {
				pm.handleDiscoveredDevice(ip, mac, "ARP discovery")
			}
		}
	}

	// 2. DHCP processing (UDP port 67/68)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 67 || udp.SrcPort == 68 {
			if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
				dhcp := dhcpLayer.(*layers.DHCPv4)
				ip := dhcp.ClientIP.String()
				if ip == "0.0.0.0" {
					ip = dhcp.YourClientIP.String()
				}
				mac := dhcp.ClientHWAddr.String()
				if ip != "0.0.0.0" && mac != "" {
					pm.handleDiscoveredDevice(ip, mac, "DHCP discovery")
				}
			}
		}
	}
}

func (pm *PassiveMonitor) handleDiscoveredDevice(ip, mac, source string) {
	var deviceID string
	var existingMAC string
	
	err := pm.db.QueryRow(`SELECT id, mac_address FROM devices WHERE ip_address = $1`, ip).Scan(&deviceID, &existingMAC)
	
	if err == sql.ErrNoRows {
		// New device discovered passively
		err = pm.db.QueryRow(`INSERT INTO devices (ip_address, mac_address, tags) VALUES ($1, $2, ARRAY['passive-discovery'])
			ON CONFLICT (ip_address) DO UPDATE SET last_seen = NOW()
			RETURNING id`, ip, mac).Scan(&deviceID)
			
		if err == nil {
			log.Printf("[PASSIVE-MONITOR] Discovered new device via %s: %s (MAC: %s)", source, ip, mac)
			alerts.CreateAlert(pm.db, alerts.AlertRequest{
				DeviceID:  deviceID,
				AlertType: alerts.AlertNewDevice,
				Severity:  "high",
				Title:     fmt.Sprintf("New device passively discovered: %s", ip),
				Description: fmt.Sprintf("Device detected on network without active scanning. Source: %s, MAC: %s", source, mac),
			})
		}
	} else if err == nil {
		// Update existing device
		if existingMAC == "" || existingMAC != mac {
			pm.db.Exec(`UPDATE devices SET mac_address = $1, last_seen = NOW() WHERE id = $2`, mac, deviceID)
		} else {
			// Just update last seen periodically (throttle DB updates to once per 5 mins to avoid spam)
			pm.db.Exec(`UPDATE devices SET last_seen = NOW() WHERE id = $1 AND last_seen < NOW() - INTERVAL '5 minutes'`, deviceID)
		}
	}
}
