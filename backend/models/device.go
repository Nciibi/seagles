package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

// Device represents an IoT device discovered on the network.
type Device struct {
	ID              string          `json:"id" db:"id"`
	IPAddress       string          `json:"ip_address" db:"ip_address"`
	MACAddress      sql.NullString  `json:"mac_address" db:"mac_address"`
	Hostname        sql.NullString  `json:"hostname" db:"hostname"`
	Vendor          sql.NullString  `json:"vendor" db:"vendor"`
	DeviceType      string          `json:"device_type" db:"device_type"`
	OSFingerprint   sql.NullString  `json:"os_fingerprint" db:"os_fingerprint"`
	FirmwareVersion sql.NullString  `json:"firmware_version" db:"firmware_version"`
	FirstSeen       time.Time       `json:"first_seen" db:"first_seen"`
	LastSeen        time.Time       `json:"last_seen" db:"last_seen"`
	RiskScore       float64         `json:"risk_score" db:"risk_score"`
	IsActive        bool            `json:"is_active" db:"is_active"`
	Tags            pq.StringArray  `json:"tags" db:"tags"`
	RawNmap         json.RawMessage `json:"raw_nmap" db:"raw_nmap"`
}

// DeviceJSON is a JSON-friendly representation of a Device for API responses.
type DeviceJSON struct {
	ID              string          `json:"id"`
	IPAddress       string          `json:"ip_address"`
	MACAddress      *string         `json:"mac_address"`
	Hostname        *string         `json:"hostname"`
	Vendor          *string         `json:"vendor"`
	DeviceType      string          `json:"device_type"`
	OSFingerprint   *string         `json:"os_fingerprint"`
	FirmwareVersion *string         `json:"firmware_version"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	RiskScore       float64         `json:"risk_score"`
	IsActive        bool            `json:"is_active"`
	Tags            []string        `json:"tags"`
	RawNmap         json.RawMessage `json:"raw_nmap,omitempty"`
}

// ToJSON converts a Device to a JSON-friendly representation.
func (d *Device) ToJSON() DeviceJSON {
	dj := DeviceJSON{
		ID:         d.ID,
		IPAddress:  d.IPAddress,
		DeviceType: d.DeviceType,
		FirstSeen:  d.FirstSeen,
		LastSeen:   d.LastSeen,
		RiskScore:  d.RiskScore,
		IsActive:   d.IsActive,
		Tags:       []string(d.Tags),
		RawNmap:    d.RawNmap,
	}
	if d.MACAddress.Valid {
		dj.MACAddress = &d.MACAddress.String
	}
	if d.Hostname.Valid {
		dj.Hostname = &d.Hostname.String
	}
	if d.Vendor.Valid {
		dj.Vendor = &d.Vendor.String
	}
	if d.OSFingerprint.Valid {
		dj.OSFingerprint = &d.OSFingerprint.String
	}
	if d.FirmwareVersion.Valid {
		dj.FirmwareVersion = &d.FirmwareVersion.String
	}
	if dj.Tags == nil {
		dj.Tags = []string{}
	}
	return dj
}
