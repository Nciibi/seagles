package models

import (
	"database/sql"
	"encoding/json"
	"time"
)

// Scan represents a security scan performed on a device.
type Scan struct {
	ID          string          `json:"id" db:"id"`
	DeviceID    sql.NullString  `json:"device_id" db:"device_id"`
	StartedAt   time.Time       `json:"started_at" db:"started_at"`
	CompletedAt sql.NullTime    `json:"completed_at" db:"completed_at"`
	Status      string          `json:"status" db:"status"`
	ScanType    string          `json:"scan_type" db:"scan_type"`
	OpenPorts   json.RawMessage `json:"open_ports" db:"open_ports"`
	Services    json.RawMessage `json:"services" db:"services"`
	ScanOutput  sql.NullString  `json:"scan_output" db:"scan_output"`
}

// ScanJSON is a JSON-friendly representation of a Scan.
type ScanJSON struct {
	ID          string          `json:"id"`
	DeviceID    *string         `json:"device_id"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at"`
	Status      string          `json:"status"`
	ScanType    string          `json:"scan_type"`
	OpenPorts   json.RawMessage `json:"open_ports,omitempty"`
	Services    json.RawMessage `json:"services,omitempty"`
	ScanOutput  *string         `json:"scan_output,omitempty"`
}

// ToJSON converts a Scan to a JSON-friendly representation.
func (s *Scan) ToJSON() ScanJSON {
	sj := ScanJSON{
		ID:        s.ID,
		StartedAt: s.StartedAt,
		Status:    s.Status,
		ScanType:  s.ScanType,
		OpenPorts: s.OpenPorts,
		Services:  s.Services,
	}
	if s.DeviceID.Valid {
		sj.DeviceID = &s.DeviceID.String
	}
	if s.CompletedAt.Valid {
		sj.CompletedAt = &s.CompletedAt.Time
	}
	if s.ScanOutput.Valid {
		sj.ScanOutput = &s.ScanOutput.String
	}
	return sj
}
