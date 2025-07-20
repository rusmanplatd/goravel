package models

import (
	"time"
)

// WebauthnCredential represents a WebAuthn credential for a user
// @Description WebAuthn credential model for passwordless authentication
type WebauthnCredential struct {
	BaseModel
	// User ID this credential belongs to
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Human-readable name for this credential
	// @example My Security Key
	Name string `gorm:"not null" json:"name" example:"My Security Key"`

	// Unique credential ID
	// @example abc123def456
	CredentialID string `gorm:"unique;not null" json:"credential_id" example:"abc123def456"`

	// Public key data
	// @example AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/
	PublicKey string `gorm:"type:text;not null" json:"public_key" example:"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/"`

	// Attestation type used
	// @example direct
	AttestationType string `gorm:"not null" json:"attestation_type" example:"direct"`

	// Supported transports (JSON array)
	// @example ["usb","nfc","ble"]
	Transports string `gorm:"type:text" json:"transports" example:"[\"usb\",\"nfc\",\"ble\"]"`

	// Credential flags
	// @example backup_eligible,backed_up
	Flags string `gorm:"not null" json:"flags" example:"backup_eligible,backed_up"`

	// Whether this credential is backup eligible
	// @example true
	BackupEligible bool `gorm:"default:false" json:"backup_eligible" example:"true"`

	// Whether this credential is backed up
	// @example false
	BackedUp bool `gorm:"default:false" json:"backed_up" example:"false"`

	// Signature count
	// @example 42
	SignCount uint32 `gorm:"default:0" json:"sign_count" example:"42"`

	// Last time this credential was used
	// @example 2024-01-15T10:30:00Z
	LastUsedAt *time.Time `json:"last_used_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	// @Description User this credential belongs to
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}
