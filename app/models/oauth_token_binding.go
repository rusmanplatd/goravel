package models

import (
	"encoding/json"
	"time"
)

// OAuthTokenBinding represents a token binding for OAuth2 tokens
// @Description OAuth Token Binding model for mTLS and DPoP token binding
type OAuthTokenBinding struct {
	ID                    uint       `gorm:"primaryKey" json:"id"`
	BindingID             string     `gorm:"unique;not null" json:"binding_id" example:"bind_123456789"`
	TokenID               string     `gorm:"not null" json:"token_id" example:"token_123456789"`
	TokenType             string     `gorm:"default:access_token" json:"token_type" example:"access_token"`
	ClientID              string     `gorm:"type:char(26);not null" json:"client_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	UserID                *string    `gorm:"type:char(26)" json:"user_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	BindingMethod         string     `gorm:"not null" json:"binding_method" example:"mtls"`
	BindingValue          string     `gorm:"not null" json:"binding_value" example:"cert_thumbprint_123"`
	BindingData           *string    `gorm:"type:text" json:"binding_data,omitempty"`
	CertificateThumbprint *string    `json:"certificate_thumbprint,omitempty" example:"abc123def456"`
	CertificateChain      *string    `gorm:"type:text" json:"certificate_chain,omitempty"`
	DPoPJKT               *string    `json:"dpop_jkt,omitempty" example:"dpop_key_thumbprint"`
	DPoPKey               *string    `gorm:"type:json" json:"dpop_key,omitempty"`
	DeviceCertificate     *string    `json:"device_certificate,omitempty"`
	AttestationData       *string    `json:"attestation_data,omitempty"`
	Status                string     `gorm:"default:active" json:"status" example:"active"`
	BoundAt               time.Time  `gorm:"not null" json:"bound_at"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
	RevocationReason      *string    `json:"revocation_reason,omitempty"`
	Metadata              *string    `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`

	// Relationships
	Client *OAuthClient      `json:"client,omitempty" gorm:"foreignKey:ClientID"`
	User   *User             `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Token  *OAuthAccessToken `json:"token,omitempty" gorm:"foreignKey:TokenID"`
}

// TableName returns the table name for the model
func (OAuthTokenBinding) TableName() string {
	return "oauth_token_bindings"
}

// GetBindingData returns the binding data as a map
func (b *OAuthTokenBinding) GetBindingData() map[string]interface{} {
	if b.BindingData == nil || *b.BindingData == "" {
		return make(map[string]interface{})
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(*b.BindingData), &data)
	return data
}

// SetBindingData sets the binding data from a map
func (b *OAuthTokenBinding) SetBindingData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataStr := string(jsonData)
	b.BindingData = &dataStr
	return nil
}

// GetDPoPKey returns the DPoP key as a JWK map
func (b *OAuthTokenBinding) GetDPoPKey() map[string]interface{} {
	if b.DPoPKey == nil || *b.DPoPKey == "" {
		return make(map[string]interface{})
	}

	var key map[string]interface{}
	json.Unmarshal([]byte(*b.DPoPKey), &key)
	return key
}

// SetDPoPKey sets the DPoP key from a JWK map
func (b *OAuthTokenBinding) SetDPoPKey(key map[string]interface{}) error {
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	keyStr := string(data)
	b.DPoPKey = &keyStr
	return nil
}

// GetMetadata returns the metadata as a map
func (b *OAuthTokenBinding) GetMetadata() map[string]interface{} {
	if b.Metadata == nil || *b.Metadata == "" {
		return make(map[string]interface{})
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(*b.Metadata), &metadata)
	return metadata
}

// SetMetadata sets the metadata from a map
func (b *OAuthTokenBinding) SetMetadata(metadata map[string]interface{}) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	metadataStr := string(data)
	b.Metadata = &metadataStr
	return nil
}

// IsActive returns true if the binding is active
func (b *OAuthTokenBinding) IsActive() bool {
	return b.Status == "active"
}

// IsExpired returns true if the binding has expired
func (b *OAuthTokenBinding) IsExpired() bool {
	return b.ExpiresAt != nil && time.Now().After(*b.ExpiresAt)
}

// IsRevoked returns true if the binding has been revoked
func (b *OAuthTokenBinding) IsRevoked() bool {
	return b.Status == "revoked" || b.RevokedAt != nil
}

// IsValid returns true if the binding is active, not expired, and not revoked
func (b *OAuthTokenBinding) IsValid() bool {
	return b.IsActive() && !b.IsExpired() && !b.IsRevoked()
}

// Revoke marks the binding as revoked
func (b *OAuthTokenBinding) Revoke(reason string) {
	b.Status = "revoked"
	b.RevocationReason = &reason
	now := time.Now()
	b.RevokedAt = &now
}

// IsMTLS returns true if this is an mTLS binding
func (b *OAuthTokenBinding) IsMTLS() bool {
	return b.BindingMethod == "mtls"
}

// IsDPoP returns true if this is a DPoP binding
func (b *OAuthTokenBinding) IsDPoP() bool {
	return b.BindingMethod == "dpop"
}

// ValidateBinding validates the token binding based on the method
func (b *OAuthTokenBinding) ValidateBinding(value string) bool {
	switch b.BindingMethod {
	case "mtls":
		return b.CertificateThumbprint != nil && *b.CertificateThumbprint == value
	case "dpop":
		return b.DPoPJKT != nil && *b.DPoPJKT == value
	default:
		return b.BindingValue == value
	}
}
