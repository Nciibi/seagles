package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const k8sDir = "../../k8s"

// k8sManifest is the subset of the cluster manifests needed to check storage
// topology invariants.
type k8sManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Replicas       *int `yaml:"replicas"`
		ScaleTargetRef struct {
			Kind string `yaml:"kind"`
			Name string `yaml:"name"`
		} `yaml:"scaleTargetRef"`
		MinReplicas *int     `yaml:"minReplicas"`
		MaxReplicas *int     `yaml:"maxReplicas"`
		AccessModes []string `yaml:"accessModes"`
		Template    struct {
			Spec struct {
				Volumes []struct {
					Name                  string `yaml:"name"`
					PersistentVolumeClaim *struct {
						ClaimName string `yaml:"claimName"`
					} `yaml:"persistentVolumeClaim"`
				} `yaml:"volumes"`
				Containers []struct {
					Name         string `yaml:"name"`
					VolumeMounts []struct {
						Name      string `yaml:"name"`
						MountPath string `yaml:"mountPath"`
						SubPath   string `yaml:"subPath"`
					} `yaml:"volumeMounts"`
				} `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func loadK8sManifests(t *testing.T) []k8sManifest {
	t.Helper()

	entries, err := os.ReadDir(k8sDir)
	if err != nil {
		t.Skipf("k8s directory not found at %s: %v", k8sDir, err)
	}

	var out []k8sManifest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(k8sDir, e.Name()))
		if err != nil {
			t.Fatalf("failed to read %s: %v", e.Name(), err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var m k8sManifest
			err := dec.Decode(&m)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("failed to parse %s: %v", e.Name(), err)
			}
			if m.Kind == "" {
				continue
			}
			out = append(out, m)
		}
	}
	return out
}

func pvcByName(manifests []k8sManifest) map[string]k8sManifest {
	out := map[string]k8sManifest{}
	for _, m := range manifests {
		if m.Kind == "PersistentVolumeClaim" {
			out[m.Metadata.Name] = m
		}
	}
	return out
}

// effectiveReplicas returns the highest replica count a workload can reach,
// accounting for an HPA that targets it. A Deployment's spec.replicas is
// ignored by the HPA once it takes over, so minReplicas/maxReplicas is the
// number that actually matters for scheduling.
func effectiveReplicas(manifests []k8sManifest, name string) int {
	best := 0

	for _, m := range manifests {
		if m.Kind == "Deployment" && m.Metadata.Name == name && m.Spec.Replicas != nil {
			if *m.Spec.Replicas > best {
				best = *m.Spec.Replicas
			}
		}
	}

	for _, m := range manifests {
		if m.Kind != "HorizontalPodAutoscaler" {
			continue
		}
		if m.Spec.ScaleTargetRef.Kind != "Deployment" || m.Spec.ScaleTargetRef.Name != name {
			continue
		}
		if m.Spec.MinReplicas != nil && *m.Spec.MinReplicas > best {
			best = *m.Spec.MinReplicas
		}
		if m.Spec.MaxReplicas != nil && *m.Spec.MaxReplicas > best {
			best = *m.Spec.MaxReplicas
		}
	}
	return best
}

// Regression guard: the backend Deployment declares 3 replicas and the HPA
// scales it to 10, while the firmware analyzer's shared claim was
// ReadWriteOnce. A ReadWriteOnce volume can only be attached by pods on one
// node, so every replica scheduled elsewhere hangs in ContainerCreating with
// "Multi-Attach error for volume". The autoscaler was therefore inert and
// high availability was nominal only.
//
// A claim is acceptable for a multi-replica workload only if it grants more
// than ReadWriteOnce.
func TestMultiReplicaWorkloadsDoNotMountReadWriteOnceClaims(t *testing.T) {
	manifests := loadK8sManifests(t)
	claims := pvcByName(manifests)

	for _, m := range manifests {
		if m.Kind != "Deployment" {
			continue
		}
		name := m.Metadata.Name
		replicas := effectiveReplicas(manifests, name)

		for _, vol := range m.Spec.Template.Spec.Volumes {
			if vol.PersistentVolumeClaim == nil {
				continue
			}
			claimName := vol.PersistentVolumeClaim.ClaimName
			claim, ok := claims[claimName]
			if !ok {
				t.Errorf("Deployment %s mounts claim %q, which is not defined "+
					"in %s", name, claimName, k8sDir)
				continue
			}
			if replicas <= 1 {
				continue
			}
			if isRWOOnly(claim.Spec.AccessModes) {
				t.Errorf("Deployment %s can run %d replica(s) but mounts claim "+
					"%q with accessModes %v (ReadWriteOnce). Pods scheduled to "+
					"different nodes will fail to attach the volume "+
					"(Multi-Attach error), so the workload cannot scale and is "+
					"not highly available. Use ReadWriteMany, or give each "+
					"replica its own volume, or remove the shared mount.",
					name, replicas, claimName, claim.Spec.AccessModes)
			}
		}
	}
}

func isRWOOnly(modes []string) bool {
	if len(modes) == 0 {
		return true // no access mode declared: treat as unusable
	}
	multi := false
	for _, m := range modes {
		switch strings.TrimSpace(m) {
		case "ReadWriteMany", "ReadWriteOncePod":
			multi = true
		}
	}
	return !multi
}

// A subPath mount requires the directory to already exist inside the volume.
// The kubelet will not create it, so the pod fails to start with
// "failed to prepare subPath" on a freshly provisioned claim. Nothing in the
// manifests created it, so the firmware analyzer could not start until the
// backend had happened to write there first.
func TestNoVolumeMountUsesSubPath(t *testing.T) {
	for _, m := range loadK8sManifests(t) {
		if m.Kind != "Deployment" && m.Kind != "StatefulSet" {
			continue
		}
		for _, c := range m.Spec.Template.Spec.Containers {
			for _, vm := range c.VolumeMounts {
				if strings.TrimSpace(vm.SubPath) == "" {
					continue
				}
				t.Errorf("%s container %s mounts %s with subPath %q; the "+
					"directory must already exist in the volume or the kubelet "+
					"fails with \"failed to prepare subPath\". Mount the volume "+
					"root and point the application's root-path configuration "+
					"at the subdirectory instead.",
					m.Kind, c.Name, vm.MountPath, vm.SubPath)
			}
		}
	}
}

// storageClassName values must not be hardcoded to a cloud-vendor legacy name.
// "standard" is a legacy GKE/AWS class and does not resolve on EKS, AKS or
// vanilla Kubernetes, which leaves the claim Pending forever.
func TestNoHardcodedLegacyStorageClassName(t *testing.T) {
	legacy := map[string]bool{"standard": true, "gp2": true}

	type sc struct {
		Spec struct {
			StorageClassName string `yaml:"storageClassName"`
		} `yaml:"spec"`
	}

	entries, err := os.ReadDir(k8sDir)
	if err != nil {
		t.Skipf("k8s directory not found: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(k8sDir, e.Name()))
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for {
			var m sc
			err := dec.Decode(&m)
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			name := m.Spec.StorageClassName
			if name == "" {
				continue
			}
			if legacy[name] {
				t.Errorf("%s sets storageClassName: %q, a legacy cloud-vendor "+
					"name that does not resolve on EKS, AKS or vanilla "+
					"Kubernetes; the claim would stay Pending. Remove it to use "+
					"the cluster default, or set your own class.", e.Name(), name)
			}
		}
	}
}

// Sanity check that this test file is actually reading real manifests, so the
// invariants above cannot pass vacuously if the parsing breaks.
func TestK8sManifestsAreDiscovered(t *testing.T) {
	manifests := loadK8sManifests(t)

	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[m.Kind]++
	}
	for _, want := range []string{"Deployment", "PersistentVolumeClaim", "HorizontalPodAutoscaler", "NetworkPolicy"} {
		if kinds[want] == 0 {
			t.Errorf("no %s found in %s; discovered kinds: %v", want, k8sDir, kinds)
		}
	}

	if got := effectiveReplicas(manifests, "seagles-backend"); got < 2 {
		t.Errorf("effectiveReplicas(seagles-backend) = %d, expected >= 2 "+
			"(3 replicas, HPA max 10); the multi-replica storage invariant "+
			"would be checked against the wrong number", got)
	}

	var names []string
	for k := range kinds {
		names = append(names, fmt.Sprintf("%s=%d", k, kinds[k]))
	}
	sort.Strings(names)
	t.Logf("discovered manifests: %s", strings.Join(names, " "))
}
