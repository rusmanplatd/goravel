package models

import (
	"encoding/json"
	"time"
)

// OAuthJWKSKey represents a JSON Web Key for OAuth2 JWT signing
// @Description OAuth JWKS Key model for key rotation and management
type OAuthJWKSKey struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	KeyID      string     `gorm:"unique;not null" json:"key_id" example:"abc123def456"`
	KeyType    string     `gorm:"default:RSA" json:"key_type" example:"RSA"`
	Algorithm  string     `gorm:"default:RS256" json:"algorithm" example:"RS256"`
	PublicKey  string     `gorm:"type:text;not null" json:"public_key"`
	PrivateKey *string    `gorm:"type:text" json:"private_key,omitempty"`
	Use        string     `gorm:"default:sig" json:"use" example:"sig"`
	KeyOps     *string    `gorm:"type:json" json:"key_ops,omitempty"`
	X5T        *string    `json:"x5t,omitempty" example:"abc123"`
	X5TS256    *string    `json:"x5t_s256,omitempty" example:"def456"`
	IsActive   bool       `gorm:"default:true" json:"is_active" example:"true"`
	IsPrimary  bool       `gorm:"default:false" json:"is_primary" example:"false"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	Metadata   *string    `gorm:"type:text" json:"metadata,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// TableName returns the table name for the model
func (OAuthJWKSKey) TableName() string {
	return "oauth_jwks_keys"
}

// GetKeyOps returns the key operations as a slice
func (k *OAuthJWKSKey) GetKeyOps() []string {
	if k.KeyOps == nil || *k.KeyOps == "" {
		return []string{}
	}

	var ops []string
	json.Unmarshal([]byte(*k.KeyOps), &ops)
	return ops
}

// SetKeyOps sets the key operations from a slice
func (k *OAuthJWKSKey) SetKeyOps(ops []string) error {
	data, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	opsStr := string(data)
	k.KeyOps = &opsStr
	return nil
}

// GetMetadata returns the metadata as a map
func (k *OAuthJWKSKey) GetMetadata() map[string]interface{} {
	if k.Metadata == nil || *k.Metadata == "" {
		return make(map[string]interface{})
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(*k.Metadata), &metadata)
	return metadata
}

// SetMetadata sets the metadata from a map
func (k *OAuthJWKSKey) SetMetadata(metadata map[string]interface{}) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	metadataStr := string(data)
	k.Metadata = &metadataStr
	return nil
}

// IsExpired returns true if the key has expired
func (k *OAuthJWKSKey) IsExpired() bool {
	return k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt)
}

// IsValid returns true if the key is active and not expired
func (k *OAuthJWKSKey) IsValid() bool {
	return k.IsActive && !k.IsExpired()
}

// ToJWK converts the key to JWK format
func (k *OAuthJWKSKey) ToJWK() map[string]interface{} {
	jwk := map[string]interface{}{
		"kty": k.KeyType,
		"use": k.Use,
		"kid": k.KeyID,
		"alg": k.Algorithm,
	}

	if k.X5T != nil {
		jwk["x5t"] = *k.X5T
	}

	if k.X5TS256 != nil {
		jwk["x5t#S256"] = *k.X5TS256
	}

	keyOps := k.GetKeyOps()
	if len(keyOps) > 0 {
		jwk["key_ops"] = keyOps
	}

	return jwk
}
