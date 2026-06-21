package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

// Firmware represents a firmware image associated with a device.
type Firmware struct {
	ID                     string          `json:"id" db:"id"`
	DeviceID               sql.NullString  `json:"device_id" db:"device_id"`
	Version                sql.NullString  `json:"version" db:"version"`
	Vendor                 sql.NullString  `json:"vendor" db:"vendor"`
	Checksum               sql.NullString  `json:"checksum" db:"checksum"`
	FilePath               sql.NullString  `json:"file_path" db:"file_path"`
	AnalyzedAt             sql.NullTime    `json:"analyzed_at" db:"analyzed_at"`
	EntropyScore           float64         `json:"entropy_score" db:"entropy_score"`
	HasDefaultCreds        bool            `json:"has_default_creds" db:"has_default_creds"`
	HasTelnet              bool            `json:"has_telnet" db:"has_telnet"`
	HasBackdoorIndicators  bool            `json:"has_backdoor_indicators" db:"has_backdoor_indicators"`
	StringsOfInterest      pq.StringArray  `json:"strings_of_interest" db:"strings_of_interest"`
	CVEMatches             pq.StringArray  `json:"cve_matches" db:"cve_matches"`
	AnalysisStatus         string          `json:"analysis_status" db:"analysis_status"`
	AnalysisReport         json.RawMessage `json:"analysis_report" db:"analysis_report"`
}

// FirmwareJSON is a JSON-friendly representation of Firmware for API responses.
type FirmwareJSON struct {
	ID                    string          `json:"id"`
	DeviceID              *string         `json:"device_id"`
	Version               *string         `json:"version"`
	Vendor                *string         `json:"vendor"`
	Checksum              *string         `json:"checksum"`
	FilePath              *string         `json:"file_path"`
	AnalyzedAt            *time.Time      `json:"analyzed_at"`
	EntropyScore          float64         `json:"entropy_score"`
	HasDefaultCreds       bool            `json:"has_default_creds"`
	HasTelnet             bool            `json:"has_telnet"`
	HasBackdoorIndicators bool            `json:"has_backdoor_indicators"`
	StringsOfInterest     []string        `json:"strings_of_interest"`
	CVEMatches            []string        `json:"cve_matches"`
	AnalysisStatus        string          `json:"analysis_status"`
	AnalysisReport        json.RawMessage `json:"analysis_report,omitempty"`
}

// ToJSON converts Firmware to a JSON-friendly representation.
func (f *Firmware) ToJSON() FirmwareJSON {
	fj := FirmwareJSON{
		ID:                    f.ID,
		EntropyScore:          f.EntropyScore,
		HasDefaultCreds:       f.HasDefaultCreds,
		HasTelnet:             f.HasTelnet,
		HasBackdoorIndicators: f.HasBackdoorIndicators,
		StringsOfInterest:     []string(f.StringsOfInterest),
		CVEMatches:            []string(f.CVEMatches),
		AnalysisStatus:        f.AnalysisStatus,
		AnalysisReport:        f.AnalysisReport,
	}
	if f.DeviceID.Valid {
		fj.DeviceID = &f.DeviceID.String
	}
	if f.Version.Valid {
		fj.Version = &f.Version.String
	}
	if f.Vendor.Valid {
		fj.Vendor = &f.Vendor.String
	}
	if f.Checksum.Valid {
		fj.Checksum = &f.Checksum.String
	}
	if f.FilePath.Valid {
		fj.FilePath = &f.FilePath.String
	}
	if f.AnalyzedAt.Valid {
		fj.AnalyzedAt = &f.AnalyzedAt.Time
	}
	if fj.StringsOfInterest == nil {
		fj.StringsOfInterest = []string{}
	}
	if fj.CVEMatches == nil {
		fj.CVEMatches = []string{}
	}
	return fj
}
