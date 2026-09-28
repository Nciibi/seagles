package retention

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The purge SQL is assembled from string constants, and sqlmock never parses
// it, so a wrong column name is invisible to the existing tests: the
// expectation simply matches whatever the code emits. That is how
// "DELETE FROM webhook_deliveries WHERE created_at ..." shipped even though
// webhook_deliveries has no created_at column, making the purge fail silently
// on every run.
//
// These tests parse the real migration files and check each (table, column)
// pairing against the actual schema, so a rename in a migration breaks the
// build instead of silently disabling retention.

var (
	createTableRE = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(`)
	alterAddRE    = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
)

// nonColumnPrefixes are the leading keywords of table-level constraints, which
// must not be mistaken for column definitions.
var nonColumnPrefixes = []string{
	"primary", "unique", "foreign", "constraint", "check", "key", "exclude",
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "db", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("migrations directory not found at %s: %v", dir, err)
	}
	return dir
}

// parseSchema returns table -> set of column names, gathered from CREATE TABLE
// bodies and ALTER TABLE ... ADD COLUMN statements.
func parseSchema(t *testing.T) map[string]map[string]bool {
	t.Helper()
	dir := migrationsDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read migrations dir: %v", err)
	}

	schema := make(map[string]map[string]bool)
	columns := func(table string) map[string]bool {
		if schema[table] == nil {
			schema[table] = make(map[string]bool)
		}
		return schema[table]
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("failed to read %s: %v", e.Name(), err)
		}
		sql := string(raw)

		// ALTER TABLE ... ADD COLUMN <name>
		for _, m := range alterAddRE.FindAllStringSubmatch(sql, -1) {
			columns(m[1])[strings.ToLower(m[2])] = true
		}

		// CREATE TABLE <name> ( ...body... )
		locs := createTableRE.FindAllStringSubmatchIndex(sql, -1)
		for i, loc := range locs {
			table := strings.ToLower(sql[loc[2]:loc[3]])
			start := loc[1] // just after the opening paren
			end := -1
			if i+1 < len(locs) {
				end = locs[i+1][0]
			} else {
				end = len(sql)
			}
			body := sql[start:end]

			// Split on top-level commas to get one definition per line-ish chunk.
			for _, def := range splitTopLevel(body) {
				def = strings.TrimSpace(stripComments(def))
				if def == "" {
					continue
				}
				first := strings.Fields(def)[0]
				first = strings.Trim(first, `("`)
				lower := strings.ToLower(first)
				skip := false
				for _, p := range nonColumnPrefixes {
					if strings.HasPrefix(lower, p) {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
				if !regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(lower) {
					continue
				}
				columns(table)[lower] = true
			}
		}
	}

	return schema
}

// splitTopLevel splits a SQL fragment on commas that are not inside
// parentheses, keeping the parentheses in the output.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	start := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuote = c
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

var lineCommentRE = regexp.MustCompile(`--[^\n]*`)

func stripComments(s string) string {
	return lineCommentRE.ReplaceAllString(s, " ")
}

// allTargets is the full set of retention purges, so a newly added purge is
// automatically covered by the schema check.
func allTargets() []purgeTarget {
	return []purgeTarget{
		purgeScans,
		purgeAlerts,
		purgeAuditLog,
		purgeWebhookDelivery,
	}
}

func TestPurgeTargetsMatchSchema(t *testing.T) {
	schema := parseSchema(t)

	for _, target := range allTargets() {
		target := target
		t.Run(target.table+"."+target.column, func(t *testing.T) {
			cols, ok := schema[target.table]
			if !ok {
				t.Fatalf("table %q is not created by any migration; "+
					"the retention purge would fail at runtime", target.table)
			}
			if !cols[target.column] {
				available := make([]string, 0, len(cols))
				for c := range cols {
					available = append(available, c)
				}
				sort.Strings(available)
				t.Fatalf("column %q does not exist on table %q; the purge "+
					"fails with \"column does not exist\" on every run.\n"+
					"columns on %s: %s",
					target.column, target.table, target.table,
					strings.Join(available, ", "))
			}
		})
	}
}

// Guards the specific regression: webhook_deliveries must be purged on
// delivered_at, because 008_create_webhooks.sql declares no created_at.
func TestWebhookDeliveryPurgesOnDeliveredAt(t *testing.T) {
	schema := parseSchema(t)

	cols := schema["webhook_deliveries"]
	if cols == nil {
		t.Fatal("webhook_deliveries is not created by any migration")
	}
	if cols["created_at"] {
		t.Error("webhook_deliveries unexpectedly has a created_at column; " +
			"if that changed, update purgeWebhookDelivery deliberately")
	}
	if !cols["delivered_at"] {
		t.Error("webhook_deliveries must have a delivered_at column to purge on")
	}
	if purgeWebhookDelivery.column != "delivered_at" {
		t.Errorf("purgeWebhookDelivery.column = %q, want delivered_at",
			purgeWebhookDelivery.column)
	}
}

// The purge query must interpolate only the hardcoded table/column constants.
// This makes the switch to Sprintf() in query() safe to keep.
func TestPurgeQueryInterpolatesOnlyConstants(t *testing.T) {
	validIdent := regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

	for _, target := range allTargets() {
		if !validIdent.MatchString(target.table) {
			t.Errorf("table %q is not a plain identifier", target.table)
		}
		if !validIdent.MatchString(target.column) {
			t.Errorf("column %q is not a plain identifier", target.column)
		}
	}

	q := purgeWebhookDelivery.query()
	want := "DELETE FROM webhook_deliveries WHERE delivered_at < NOW() - make_interval(days => $1)"
	if q != want {
		t.Errorf("query() =\n  %q\nwant\n  %q", q, want)
	}
	// Exactly one bind parameter; the day count is never interpolated.
	if n := strings.Count(q, "$"); n != 1 {
		t.Errorf("expected exactly 1 bind parameter in %q, found %d", q, n)
	}
}
