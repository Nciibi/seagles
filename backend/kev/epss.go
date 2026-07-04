package kev

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yourusername/seagles/breaker"
	"github.com/yourusername/seagles/slog"
)

const epssAPIURL = "https://api.first.org/data/v1/epss"

type EPSSScore struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type EPSSResponse struct {
	Status     string      `json:"status"`
	StatusCode int         `json:"status-code"`
	Version    string      `json:"version"`
	Total      int         `json:"total"`
	Data       []EPSSScore `json:"data"`
}

var epssBreaker = breaker.New(breaker.Options{
	Name:         "epss-api",
	MaxFailures:  5,
	ResetTimeout: 2 * time.Minute,
})

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

		cveParam := ""
		for j, cve := range batch {
			if j > 0 {
				cveParam += ","
			}
			cveParam += cve
		}

		url := fmt.Sprintf("%s?cve=%s", epssAPIURL, cveParam)

		err := epssBreaker.Execute(func() error {
			req, reqErr := http.NewRequest("GET", url, nil)
			if reqErr != nil {
				return reqErr
			}
			req.Header.Set("User-Agent", "IronMesh-Security-Scanner/2.0")

			resp, reqErr := client.Do(req)
			if reqErr != nil {
				return reqErr
			}
			defer resp.Body.Close()

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return readErr
			}

			var epssResp EPSSResponse
			if unmarshalErr := json.Unmarshal(body, &epssResp); unmarshalErr != nil {
				return unmarshalErr
			}

			for _, score := range epssResp.Data {
				results[score.CVE] = score
			}
			return nil
		})
		if err != nil {
			slog.Warn("EPSS batch fetch failed", "batch_size", len(batch), "error", err.Error())
		}

		if end < len(cveIDs) {
			time.Sleep(700 * time.Millisecond)
		}
	}

	return results, nil
}

func UpdateEPSSScores(db *sql.DB) {
	rows, err := db.Query(`SELECT DISTINCT cve_id FROM vulnerabilities
		WHERE cve_id IS NOT NULL AND is_resolved = FALSE`)
	if err != nil {
		slog.Error("Failed to query CVEs for EPSS update", "error", err.Error())
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
		slog.Debug("No CVEs to update EPSS scores for")
		return
	}

	slog.Info("Fetching EPSS scores", "cve_count", len(cveIDs))
	scores, err := FetchEPSSScores(cveIDs)
	if err != nil {
		slog.Error("EPSS fetch failed", "error", err.Error())
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

	slog.Info("EPSS scores updated", "updated", updated, "total", len(cveIDs))
}

func StartEPSSUpdater(db *sql.DB) {
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
