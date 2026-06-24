package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// KEVEntry represents a single vulnerability in the CISA KEV catalog.
type KEVEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
}

// KEVCatalog represents the full CISA KEV feed.
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`

	// Internal lookup map for O(1) CVE checks
	mu       sync.RWMutex
	cveIndex map[string]*KEVEntry
}

const kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// FetchKEV downloads the CISA KEV feed and saves it to the cache file.
func FetchKEV(cacheFilePath string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", kevFeedURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create KEV request: %v", err)
	}
	req.Header.Set("User-Agent", "IronMesh-Security-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download KEV feed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read KEV response: %v", err)
	}

	if err := os.WriteFile(cacheFilePath, body, 0644); err != nil {
		return fmt.Errorf("failed to save KEV cache: %v", err)
	}

	// Parse to get count for logging
	var catalog KEVCatalog
	if err := json.Unmarshal(body, &catalog); err == nil {
		log.Printf("KEV catalog updated: %d entries", len(catalog.Vulnerabilities))
	}

	return nil
}

// LoadKEV reads and parses the KEV catalog from a cache file.
func LoadKEV(cacheFilePath string) (*KEVCatalog, error) {
	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return nil, fmt.Errorf("KEV cache not found - run FetchKEV first")
	}

	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse KEV cache: %v", err)
	}

	catalog.Count = len(catalog.Vulnerabilities)
	catalog.buildIndex()
	return &catalog, nil
}

// buildIndex creates the O(1) lookup map from the vulnerability list.
func (c *KEVCatalog) buildIndex() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cveIndex = make(map[string]*KEVEntry, len(c.Vulnerabilities))
	for i := range c.Vulnerabilities {
		key := strings.ToUpper(c.Vulnerabilities[i].CVEID)
		c.cveIndex[key] = &c.Vulnerabilities[i]
	}
}

// IsKEV checks if a CVE ID exists in the KEV catalog (case-insensitive, O(1) lookup).
func IsKEV(catalog *KEVCatalog, cveID string) bool {
	if catalog == nil || catalog.cveIndex == nil {
		return false
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	_, exists := catalog.cveIndex[strings.ToUpper(cveID)]
	return exists
}

// GetKEVEntry returns the full KEV entry for a CVE ID, or nil if not found.
func GetKEVEntry(catalog *KEVCatalog, cveID string) *KEVEntry {
	if catalog == nil || catalog.cveIndex == nil {
		return nil
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	return catalog.cveIndex[strings.ToUpper(cveID)]
}

// StartKEVUpdater fetches the KEV catalog on startup and refreshes it every 24 hours.
func StartKEVUpdater(cacheFilePath string) *KEVCatalog {
	// Try to fetch fresh data
	err := FetchKEV(cacheFilePath)
	if err != nil {
		log.Printf("KEV fetch failed (will try cache): %v", err)
	}

	// Load from cache (either fresh or existing)
	catalog, err := LoadKEV(cacheFilePath)
	if err != nil {
		log.Printf("WARNING: KEV catalog not available: %v", err)
		// Return empty catalog — don't crash
		catalog = &KEVCatalog{
			Vulnerabilities: []KEVEntry{},
			cveIndex:        make(map[string]*KEVEntry),
		}
	}

	// Start background updater
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := FetchKEV(cacheFilePath); err != nil {
				log.Printf("KEV refresh failed: %v", err)
				continue
			}
			newCatalog, err := LoadKEV(cacheFilePath)
			if err != nil {
				log.Printf("KEV reload failed: %v", err)
				continue
			}
			// Update the catalog in-place
			catalog.mu.Lock()
			catalog.Vulnerabilities = newCatalog.Vulnerabilities
			catalog.Count = newCatalog.Count
			catalog.CatalogVersion = newCatalog.CatalogVersion
			catalog.DateReleased = newCatalog.DateReleased
			catalog.cveIndex = newCatalog.cveIndex
			catalog.mu.Unlock()
			log.Printf("KEV catalog refreshed: %d entries", catalog.Count)
		}
	}()

	return catalog
}
