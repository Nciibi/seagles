package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Host contains information about a scanned network host.
type Host struct {
	IP        string
	MAC       string
	Hostname  string
	Vendor    string
	OSMatch   string
	OpenPorts []Port
	Services  map[int]Service
	RawXML    []byte
}

// Port represents an open network port.
type Port struct {
	Number   int
	Protocol string
	State    string
}

// Service represents a network service running on a port.
type Service struct {
	Name    string
	Version string
	Banner  string
}

// ScanResult contains the result of a deep scan.
type ScanResult struct {
	Host     Host
	Duration time.Duration
	Error    error
}

// nmap XML structures
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses  []nmapAddr     `xml:"address"`
	Hostnames  []nmapHostname `xml:"hostnames>hostname"`
	Ports      []nmapPort     `xml:"ports>port"`
	OS         nmapOS         `xml:"os"`
	Status     nmapStatus     `xml:"status"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPort struct {
	PortID   int          `xml:"portid,attr"`
	Protocol string       `xml:"protocol,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

// DiscoverHosts runs an nmap ping scan to discover live hosts on a network.
func DiscoverHosts(cidr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", "-sn", cidr, "-oX", "-", "--max-retries", "2", "--host-timeout", "5s")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("nmap discovery failed: %s", string(exitErr.Stderr))
		}
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("nmap not found: please install nmap")
		}
		return nil, fmt.Errorf("nmap discovery failed: %v", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(output, &run); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %v", err)
	}

	var hosts []string
	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				hosts = append(hosts, addr.Addr)
				break
			}
		}
	}

	return hosts, nil
}

// DeepScan performs a comprehensive nmap scan on a single host.
func DeepScan(ip string) (*ScanResult, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ports := "22,23,80,443,554,1883,1884,5555,8883,47808,502"
	cmd := exec.CommandContext(ctx, "nmap", "-sV", "-sC", "-O",
		"-p", ports,
		"--script=banner,http-title",
		"-oX", "-",
		"--host-timeout", "60s",
		ip)

	output, err := cmd.Output()
	if err != nil {
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("nmap not found: please install nmap")
		}
		// nmap may return exit code 1 but still produce valid XML
		if output == nil || len(output) == 0 {
			return nil, fmt.Errorf("nmap scan failed: %v", err)
		}
	}

	var run nmapRun
	if err := xml.Unmarshal(output, &run); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %v", err)
	}

	result := &ScanResult{
		Host: Host{
			IP:       ip,
			Services: make(map[int]Service),
			RawXML:   output,
		},
		Duration: time.Since(start),
	}

	if len(run.Hosts) > 0 {
		host := run.Hosts[0]

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "mac":
				result.Host.MAC = addr.Addr
				if addr.Vendor != "" {
					result.Host.Vendor = addr.Vendor
				}
			}
		}

		if len(host.Hostnames) > 0 {
			result.Host.Hostname = host.Hostnames[0].Name
		}

		if len(host.OS.OSMatches) > 0 {
			best := host.OS.OSMatches[0]
			for _, m := range host.OS.OSMatches {
				acc1, _ := strconv.Atoi(best.Accuracy)
				acc2, _ := strconv.Atoi(m.Accuracy)
				if acc2 > acc1 {
					best = m
				}
			}
			result.Host.OSMatch = best.Name
		}

		for _, port := range host.Ports {
			p := Port{
				Number:   port.PortID,
				Protocol: port.Protocol,
				State:    port.State.State,
			}
			result.Host.OpenPorts = append(result.Host.OpenPorts, p)

			if port.State.State == "open" {
				result.Host.Services[port.PortID] = Service{
					Name:    port.Service.Name,
					Version: port.Service.Version,
					Banner:  port.Service.ExtraInfo,
				}
			}
		}
	}

	return result, nil
}
