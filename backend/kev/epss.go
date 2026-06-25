package kev

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const epssAPIURL = "https://api.first.org/data/v1/epss"

// EPSSScore contains EPSS data for a single CVE.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// EPSSResponse is the API response from FIRST.org.
type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Version    string      `json:"version"`
	Total      int         `json:"total"`
	Data       []EPSSScore `json:"data"`
}

// FetchEPSSScores queries the FIRST.org EPSS API for the given CVE IDs.
// It batches requests in groups of 30 to respect rate limits.
func FetchEPSSScores(cveIDs []string) (map[string]EPSSScore, error) {
	results := make(map[string]EPSSScore)
	if len(cveIDs) == 0 {
		return results, nil
	}

	batchSize := 30
	client := &http.Client{Timeout: 15 * time.Second}

	for i := 0; i < len(cveIDs); i += batchSize {
		end := i + batchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		// Build comma-separated CVE list
		cveParam := ""
		for j, cve := range batch {
			if j > 0 {
				cveParam += ","
			}
			cveParam += cve
		}

		url := fmt.Sprintf("%s?cve=%s", epssAPIURL, cveParam)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return results, fmt.Errorf("failed to create EPSS request: %v", err)
		}
		req.Header.Set("User-Agent", "IronMesh-Security-Scanner/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("EPSS API request failed: %v", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		var epssResp EPSSResponse
		if err := json.Unmarshal(body, &epssResp); err != nil {
			continue
		}

		for _, score := range epssResp.Data {
			results[score.CVE] = score
		}

		// Rate limit: 100 requests per minute
		if end < len(cveIDs) {
			time.Sleep(700 * time.Millisecond)
		}
	}

	return results, nil
}

// UpdateEPSSScores fetches EPSS scores for all unresolved CVEs and updates the database.
func UpdateEPSSScores(db *sql.DB) {
	rows, err := db.Query(`SELECT DISTINCT cve_id FROM vulnerabilities
		WHERE cve_id IS NOT NULL AND is_resolved = FALSE`)
	if err != nil {
		log.Printf("Failed to query CVEs for EPSS update: %v", err)
		return
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err == nil {
			cveIDs = append(cveIDs, cveID)
		}
	}

	if len(cveIDs) == 0 {
		log.Println("No CVEs to update EPSS scores for")
		return
	}

	scores, err := FetchEPSSScores(cveIDs)
	if err != nil {
		log.Printf("EPSS fetch failed: %v", err)
		return
	}

	updated := 0
	for cve, score := range scores {
		_, err := db.Exec(`UPDATE vulnerabilities SET epss_score = $1, epss_percentile = $2, epss_updated_at = NOW()
			WHERE cve_id = $3 AND is_resolved = FALSE`,
			score.EPSS, score.Percentile, cve)
		if err == nil {
			updated++
		}
	}

	log.Printf("EPSS scores updated: %d/%d CVEs", updated, len(cveIDs))
}

// StartEPSSUpdater runs EPSS score updates every 6 hours.
func StartEPSSUpdater(db *sql.DB) {
	// Initial update after 30 seconds (let system stabilize)
	go func() {
		time.Sleep(30 * time.Second)
		UpdateEPSSScores(db)
	}()

	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			UpdateEPSSScores(db)
		}
	}()
}
