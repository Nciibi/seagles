package api

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/seagles/kev"
)

// KEVStatusHandler returns the KEV catalog status.
func KEVStatusHandler(catalog *kev.KEVCatalog) gin.HandlerFunc {
	return func(c *gin.Context) {
		cacheFile := "data/cisa-kev.json"

		var lastUpdated string
		if info, err := os.Stat(cacheFile); err == nil {
			lastUpdated = info.ModTime().Format(time.RFC3339)
		} else {
			lastUpdated = "never"
		}

		totalEntries := 0
		if catalog != nil {
			totalEntries = catalog.Count
		}

		success(c, gin.H{
			"last_updated":  lastUpdated,
			"total_entries": totalEntries,
			"cache_file":    cacheFile,
		})
	}
}
