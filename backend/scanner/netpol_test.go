package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The Kubernetes NetworkPolicy has to name every port the scanner dials. It
// used to allow egress only to 0.0.0.0/0 on 80/443 with all RFC1918 excluded,
// so in a cluster Seagles could not reach SSH, Telnet, Modbus, RTSP, MQTT,
// ADB or BACnet and the product reported an empty network — silently, because
// a blocked probe and a closed port look identical in the results.
//
// These tests derive the ports from the scanner source and assert the policy
// permits every one of them, so adding a port to the scan cannot quietly go
// un-permitted.

const netpolPath = "../../k8s/seagles-network-policy.yaml"

// scannerSourcePorts returns every port the scanner can dial, read from the
// source rather than hardcoded here, so this test tracks the code.
func scannerSourcePorts(t *testing.T) map[int]string {
	t.Helper()
	ports := map[int]string{}

	add := func(p int, origin string) {
		if p <= 0 || p > 65535 {
			t.Errorf("%s references invalid port %d", origin, p)
			return
		}
		if prev, dup := ports[p]; dup {
			t.Logf("port %d appears in both %s and %s", p, prev, origin)
		}
		ports[p] = origin
	}

	// 1. The nmap -p list: `ports := "22,23,80,443,..."`
	nmapRe := regexp.MustCompile(`ports\s*:?=\s*"([0-9,\-]+)"`)
	src, err := os.ReadFile("nmap.go")
	if err != nil {
		t.Fatalf("failed to read nmap.go: %v", err)
	}
	m := nmapRe.FindSubmatch(src)
	if m == nil {
		t.Fatal(`could not find the nmap port list (ports := "...") in nmap.go; ` +
			"update this test if the variable was renamed")
	}
	for _, field := range strings.Split(string(m[1]), ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(field, "-"); ok {
			l, err1 := strconv.Atoi(lo)
			h, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil {
				t.Errorf("unparseable nmap port range %q", field)
				continue
			}
			for p := l; p <= h; p++ {
				add(p, "nmap -p "+field)
			}
			continue
		}
		p, err := strconv.Atoi(field)
		if err != nil {
			t.Errorf("unparseable nmap port %q", field)
			continue
		}
		add(p, "nmap -p")
	}

	// 2. DetectProtocols gates on `portSet[N]`.
	protoRe := regexp.MustCompile(`portSet\[(\d+)\]`)
	psrc, err := os.ReadFile("protocols.go")
	if err != nil {
		t.Fatalf("failed to read protocols.go: %v", err)
	}
	for _, mm := range protoRe.FindAllStringSubmatch(string(psrc), -1) {
		p, _ := strconv.Atoi(mm[1])
		add(p, "DetectProtocols portSet[]")
	}

	// 3. Credential and TLS probes are called with literal ports from
	//    api/scans.go: TestSSHCreds(ip, N, ...), TestHTTPBasicCreds(ip, N, ...)
	//    and CheckTLS(ip, N).
	asrc, err := os.ReadFile(filepath.Join("..", "api", "scans.go"))
	if err != nil {
		t.Fatalf("failed to read api/scans.go: %v", err)
	}
	probeRe := regexp.MustCompile(
		`(TestSSHCreds|TestHTTPBasicCreds|TestTelnetCreds|CheckTLS)\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*(\d+)`)
	for _, mm := range probeRe.FindAllStringSubmatch(string(asrc), -1) {
		p, _ := strconv.Atoi(mm[2])
		add(p, mm[1]+"() in api/scans.go")
	}

	return ports
}

// policyAllowsPorts returns the set of ports the backend NetworkPolicy permits
// to its single scan-target ipBlock.
func policyAllowsPorts(t *testing.T) (map[int]bool, string) {
	t.Helper()

	raw, err := os.ReadFile(netpolPath)
	if err != nil {
		t.Skipf("network policy not found at %s: %v", netpolPath, err)
	}

	var docs []struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			PodSelector map[string]interface{} `yaml:"podSelector"`
			Egress      []struct {
				To []struct {
					IPBlock *struct {
						CIDR   string   `yaml:"cidr"`
						Except []string `yaml:"except"`
					} `yaml:"ipBlock"`
					PodSelector map[string]interface{} `yaml:"podSelector"`
				} `yaml:"to"`
				Ports []struct {
					Port     int    `yaml:"port"`
					Protocol string `yaml:"protocol"`
				} `yaml:"ports"`
			} `yaml:"egress"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &docs); err != nil {
		t.Fatalf("failed to parse %s: %v", netpolPath, err)
	}

	allowed := map[int]bool{}
	var cidr string

	for _, d := range docs {
		if d.Kind != "NetworkPolicy" || d.Metadata.Name != "seagles-backend" {
			continue
		}
		for _, rule := range d.Spec.Egress {
			// Only ipBlock rules can reach a network that is not a cluster pod.
			isScanTarget := false
			for _, to := range rule.To {
				if to.IPBlock == nil {
					continue
				}
				// A rule with `except` is the internet allow-list for threat
				// feeds, not the scan target: it explicitly excludes private
				// space, which is exactly what the scanner needs to reach.
				if len(to.IPBlock.Except) > 0 {
					continue
				}
				isScanTarget = true
				cidr = to.IPBlock.CIDR
			}
			if !isScanTarget {
				continue
			}
			for _, p := range rule.Ports {
				if p.Protocol == "TCP" {
					allowed[p.Port] = true
				}
			}
		}
	}

	if cidr == "" {
		t.Fatalf("no scan-target ipBlock egress rule found for the " +
			"seagles-backend policy; the scanner would be unable to reach " +
			"any target network")
	}
	return allowed, cidr
}

func TestNetworkPolicyAllowsEveryScannerPort(t *testing.T) {
	scannerPorts := scannerSourcePorts(t)
	allowed, cidr := policyAllowsPorts(t)

	t.Logf("scan target CIDR: %s", cidr)
	t.Logf("scanner dials %d distinct ports; policy permits %d", len(scannerPorts), len(allowed))

	var missing []string
	for port, origin := range scannerPorts {
		if !allowed[port] {
			missing = append(missing, fmt.Sprintf("  port %d (%s)", port, origin))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("NetworkPolicy does not permit %d port(s) the scanner dials; "+
			"those probes would be silently dropped in Kubernetes:\n%s\n\n"+
			"Add each port to the scan-target ipBlock rule in %s, or remove the "+
			"probe from the scanner.",
			len(missing), strings.Join(missing, "\n"), netpolPath)
	}
}

// Guards the specific regression: a scan-target rule must exist and must not
// carry an `except` list, which is what previously excluded all RFC1918 space
// and made the product inoperable in a cluster.
func TestNetworkPolicyHasUnrestrictedScanTargetBlock(t *testing.T) {
	raw, err := os.ReadFile(netpolPath)
	if err != nil {
		t.Skipf("network policy not found: %v", err)
	}

	var docs []struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			Egress []struct {
				To []struct {
					IPBlock *struct {
						CIDR   string   `yaml:"cidr"`
						Except []string `yaml:"except"`
					} `yaml:"ipBlock"`
				} `yaml:"to"`
			} `yaml:"egress"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &docs); err != nil {
		t.Fatalf("failed to parse %s: %v", netpolPath, err)
	}

	found := false
	for _, d := range docs {
		if d.Kind != "NetworkPolicy" || d.Metadata.Name != "seagles-backend" {
			continue
		}
		for _, rule := range d.Spec.Egress {
			for _, to := range rule.To {
				if to.IPBlock == nil {
					continue
				}
				if len(to.IPBlock.Except) > 0 {
					continue
				}
				if to.IPBlock.CIDR == "0.0.0.0/0" {
					t.Errorf("scan-target rule is 0.0.0.0/0; a scanner must be " +
						"confined to the network an operator is authorised to test")
				}
				found = true
			}
		}
	}
	if !found {
		t.Error("seagles-backend policy has no ipBlock scan-target egress rule; " +
			"the scanner cannot reach any target network")
	}
}

// A deny-all baseline is required, otherwise unrelated workloads in the
// namespace are unrestricted despite the docs claiming "deny-all default".
func TestNetworkPolicyHasDefaultDenyBaseline(t *testing.T) {
	raw, err := os.ReadFile(netpolPath)
	if err != nil {
		t.Skipf("network policy not found: %v", err)
	}

	var docs []struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			PodSelector *map[string]interface{} `yaml:"podSelector"`
			PolicyTypes []string                `yaml:"policyTypes"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &docs); err != nil {
		t.Fatalf("failed to parse %s: %v", netpolPath, err)
	}

	for _, d := range docs {
		if d.Kind != "NetworkPolicy" {
			continue
		}
		// podSelector: {} decodes to an empty, non-nil map.
		if d.Spec.PodSelector == nil {
			continue
		}
		if len(*d.Spec.PodSelector) != 0 {
			continue
		}
		var hasIn, hasEg bool
		for _, pt := range d.Spec.PolicyTypes {
			switch pt {
			case "Ingress":
				hasIn = true
			case "Egress":
				hasEg = true
			}
		}
		if hasIn && hasEg {
			return
		}
	}
	t.Error("no default-deny policy (podSelector: {} with both policyTypes) " +
		"found; unrelated workloads in the namespace stay unrestricted")
}
