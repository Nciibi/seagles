package scanner

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/yourusername/seagles/slog"
)

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

type Port struct {
	Number   int
	Protocol string
	State    string
}

type Service struct {
	Name    string
	Version string
	Banner  string
}

type ScanResult struct {
	Host     Host
	Duration time.Duration
	Error    error
}

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

type scanJob struct {
	ip    string
	ports string
}

var scanWorkerPool = make(chan struct{}, 20)

var (
	errInvalidCIDR  = fmt.Errorf("invalid CIDR notation")
	errInvalidIP    = fmt.Errorf("invalid IP address")
	errSuspicious   = fmt.Errorf("suspicious input detected")
)

var suspiciousPatterns = []string{
	"`", "$(", ";", "|", "&&", "||",
	"\n", "\r", ">", "<", "..",
}

func sanitizeCIDR(cidr string) error {
	if len(cidr) > 50 {
		return errInvalidCIDR
	}

	for _, p := range suspiciousPatterns {
		if strings.Contains(cidr, p) {
			return errSuspicious
		}
	}

	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return errInvalidCIDR
	}

	ipParts := strings.Split(parts[0], ".")
	if len(ipParts) != 4 {
		return errInvalidCIDR
	}

	for _, p := range ipParts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return errInvalidCIDR
		}
	}

	prefix, err := strconv.Atoi(parts[1])
	if err != nil || prefix < 0 || prefix > 32 {
		return errInvalidCIDR
	}

	return nil
}

func sanitizeIP(ip string) error {
	if len(ip) > 45 {
		return errInvalidIP
	}

	for _, p := range suspiciousPatterns {
		if strings.Contains(ip, p) {
			return errSuspicious
		}
	}

	if strings.Contains(ip, ":") {
		return nil
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return errInvalidIP
	}

	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return errInvalidIP
		}
	}

	return nil
}

func acquireWorker() {
	scanWorkerPool <- struct{}{}
}

func releaseWorker() {
	<-scanWorkerPool
}

func DiscoverHosts(cidr string) ([]string, error) {
	slog.Info("Starting network discovery", "cidr", cidr)
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", "-sn", cidr, "-oX", "-", "--max-retries", "2", "--host-timeout", "5s", "-T4")
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

	slog.Info("Network discovery complete", "hosts", len(hosts), "duration", time.Since(start).String())
	return hosts, nil
}

func DeepScan(ip string) (*ScanResult, error) {
	acquireWorker()
	defer releaseWorker()

	start := time.Now()

	ports := "22,23,80,443,554,1883,1884,5555,8883,47808,502,8080,8443"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", "-sV", "-sC", "-O",
		"-p", ports,
		"--script=banner,http-title,ssl-enum-ciphers",
		"-oX", "-",
		"--host-timeout", "60s",
		"--min-rate", "100",
		ip)

	output, err := cmd.Output()
	if err != nil {
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("nmap not found: please install nmap")
		}
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

	slog.Debug("Deep scan complete", "ip", ip, "ports", len(result.Host.OpenPorts), "duration", result.Duration.String())
	return result, nil
}

type BatchScanResult struct {
	IP     string
	Result *ScanResult
	Error  error
}

func BatchDeepScan(ips []string) []BatchScanResult {
	var wg sync.WaitGroup
	results := make([]BatchScanResult, len(ips))

	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			result, err := DeepScan(addr)
			results[idx] = BatchScanResult{
				IP:     addr,
				Result: result,
				Error:  err,
			}
		}(i, ip)
	}

	wg.Wait()
	return results
}
