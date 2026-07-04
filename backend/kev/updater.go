package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Nciibi/seagles/breaker"
	"github.com/Nciibi/seagles/slog"
)

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

type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`

	mu       sync.RWMutex
	cveIndex map[string]*KEVEntry
}

const kevFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

var kevBreaker = breaker.New(breaker.Options{
	Name:         "kev-feed",
	MaxFailures:  3,
	ResetTimeout: 5 * time.Minute,
})

func FetchKEV(cacheFilePath string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", kevFeedURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create KEV request: %v", err)
	}
	req.Header.Set("User-Agent", "Seagles-Security-Scanner/2.0")

	var resp *http.Response
	err = kevBreaker.Execute(func() error {
		var innerErr error
		resp, innerErr = client.Do(req)
		return innerErr
	})
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

	var catalog KEVCatalog
	if err := json.Unmarshal(body, &catalog); err == nil {
		slog.Info("KEV catalog updated", "entries", len(catalog.Vulnerabilities))
	}

	return nil
}

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

func (c *KEVCatalog) buildIndex() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cveIndex = make(map[string]*KEVEntry, len(c.Vulnerabilities))
	for i := range c.Vulnerabilities {
		key := strings.ToUpper(c.Vulnerabilities[i].CVEID)
		c.cveIndex[key] = &c.Vulnerabilities[i]
	}
}

func IsKEV(catalog *KEVCatalog, cveID string) bool {
	if catalog == nil || catalog.cveIndex == nil {
		return false
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	_, exists := catalog.cveIndex[strings.ToUpper(cveID)]
	return exists
}

func GetKEVEntry(catalog *KEVCatalog, cveID string) *KEVEntry {
	if catalog == nil || catalog.cveIndex == nil {
		return nil
	}
	catalog.mu.RLock()
	defer catalog.mu.RUnlock()
	return catalog.cveIndex[strings.ToUpper(cveID)]
}

func StartKEVUpdater(cacheFilePath string) *KEVCatalog {
	err := FetchKEV(cacheFilePath)
	if err != nil {
		slog.Warn("KEV fetch failed, using cache", "error", err.Error())
	}

	catalog, err := LoadKEV(cacheFilePath)
	if err != nil {
		slog.Warn("KEV catalog not available", "error", err.Error())
		catalog = &KEVCatalog{
			Vulnerabilities: []KEVEntry{},
			cveIndex:        make(map[string]*KEVEntry),
		}
	}

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := FetchKEV(cacheFilePath); err != nil {
				slog.Error("KEV refresh failed", "error", err.Error())
				continue
			}
			newCatalog, err := LoadKEV(cacheFilePath)
			if err != nil {
				slog.Error("KEV reload failed", "error", err.Error())
				continue
			}
			catalog.mu.Lock()
			catalog.Vulnerabilities = newCatalog.Vulnerabilities
			catalog.Count = newCatalog.Count
			catalog.CatalogVersion = newCatalog.CatalogVersion
			catalog.DateReleased = newCatalog.DateReleased
			catalog.cveIndex = newCatalog.cveIndex
			catalog.mu.Unlock()
			slog.Info("KEV catalog refreshed", "entries", catalog.Count)
		}
	}()

	return catalog
}
