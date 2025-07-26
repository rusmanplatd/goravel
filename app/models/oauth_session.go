package models

import (
	"encoding/json"
	"time"
)

// OAuthSession represents an OAuth2 session
// @Description OAuth Session model for managing OAuth2 sessions
type OAuthSession struct {
	ID                  uint       `gorm:"primaryKey" json:"id"`
	SessionID           string     `gorm:"unique;not null" json:"session_id" example:"sess_123456789"`
	UserID              string     `gorm:"type:char(26);not null" json:"user_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	ClientID            string     `gorm:"type:char(26);not null" json:"client_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	SessionType         string     `gorm:"default:oauth" json:"session_type" example:"oauth"`
	State               *string    `json:"state,omitempty" example:"abc123def456"`
	Nonce               *string    `json:"nonce,omitempty" example:"nonce123"`
	Scopes              *string    `gorm:"type:text" json:"scopes,omitempty"`
	RedirectURI         *string    `gorm:"type:varchar(500)" json:"redirect_uri,omitempty"`
	CodeChallenge       *string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string    `json:"code_challenge_method,omitempty" example:"S256"`
	ResponseType        *string    `json:"response_type,omitempty" example:"code"`
	ResponseMode        *string    `json:"response_mode,omitempty" example:"query"`
	IPAddress           string     `gorm:"not null" json:"ip_address" example:"192.168.1.100"`
	UserAgent           *string    `gorm:"type:text" json:"user_agent,omitempty"`
	DeviceID            *string    `json:"device_id,omitempty" example:"device_123"`
	BrowserFingerprint  *string    `json:"browser_fingerprint,omitempty"`
	SessionData         *string    `gorm:"type:json" json:"session_data,omitempty"`
	Status              string     `gorm:"default:active" json:"status" example:"active"`
	AuthTime            *time.Time `json:"auth_time,omitempty"`
	LastActivity        time.Time  `gorm:"not null" json:"last_activity"`
	ExpiresAt           time.Time  `gorm:"not null" json:"expires_at"`
	IsPersistent        bool       `gorm:"default:false" json:"is_persistent" example:"false"`
	ACR                 *string    `json:"acr,omitempty" example:"1"`
	AMR                 *string    `gorm:"type:json" json:"amr,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`

	// Relationships
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName returns the table name for the model
func (OAuthSession) TableName() string {
	return "oauth_sessions"
}

// GetScopes returns the scopes as a slice
func (s *OAuthSession) GetScopes() []string {
	if s.Scopes == nil || *s.Scopes == "" {
		return []string{}
	}

	var scopes []string
	json.Unmarshal([]byte(*s.Scopes), &scopes)
	return scopes
}

// SetScopes sets the scopes from a slice
func (s *OAuthSession) SetScopes(scopes []string) error {
	data, err := json.Marshal(scopes)
	if err != nil {
		return err
	}
	scopesStr := string(data)
	s.Scopes = &scopesStr
	return nil
}

// GetSessionData returns the session data as a map
func (s *OAuthSession) GetSessionData() map[string]interface{} {
	if s.SessionData == nil || *s.SessionData == "" {
		return make(map[string]interface{})
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(*s.SessionData), &data)
	return data
}

// SetSessionData sets the session data from a map
func (s *OAuthSession) SetSessionData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataStr := string(jsonData)
	s.SessionData = &dataStr
	return nil
}

// GetAMR returns the authentication methods references as a slice
func (s *OAuthSession) GetAMR() []string {
	if s.AMR == nil || *s.AMR == "" {
		return []string{}
	}

	var amr []string
	json.Unmarshal([]byte(*s.AMR), &amr)
	return amr
}

// SetAMR sets the authentication methods references from a slice
func (s *OAuthSession) SetAMR(amr []string) error {
	data, err := json.Marshal(amr)
	if err != nil {
		return err
	}
	amrStr := string(data)
	s.AMR = &amrStr
	return nil
}

// IsActive returns true if the session is active
func (s *OAuthSession) IsActive() bool {
	return s.Status == "active"
}

// IsExpired returns true if the session has expired
func (s *OAuthSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid returns true if the session is active and not expired
func (s *OAuthSession) IsValid() bool {
	return s.IsActive() && !s.IsExpired()
}

// UpdateLastActivity updates the last activity timestamp
func (s *OAuthSession) UpdateLastActivity() {
	s.LastActivity = time.Now()
}

// Revoke marks the session as revoked
func (s *OAuthSession) Revoke() {
	s.Status = "revoked"
}

// Expire marks the session as expired
func (s *OAuthSession) Expire() {
	s.Status = "expired"
}

// HasScope checks if the session has a specific scope
func (s *OAuthSession) HasScope(scope string) bool {
	scopes := s.GetScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
