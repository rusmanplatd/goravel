package models

import (
	"encoding/json"
	"time"
)

// OAuthSecurityEvent represents a security event in the OAuth2 system
// @Description OAuth Security Event model for tracking suspicious activities
type OAuthSecurityEvent struct {
	ID               uint       `gorm:"primaryKey" json:"id"`
	EventID          string     `gorm:"not null" json:"event_id" example:"evt_123456789"`
	EventType        string     `gorm:"not null" json:"event_type" example:"suspicious_login"`
	UserID           *string    `gorm:"type:char(26)" json:"user_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	ClientID         *string    `gorm:"type:char(26)" json:"client_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	IPAddress        *string    `json:"ip_address,omitempty" example:"192.168.1.100"`
	UserAgent        *string    `gorm:"type:text" json:"user_agent,omitempty"`
	SessionID        *string    `json:"session_id,omitempty" example:"sess_123456"`
	RequestID        *string    `json:"request_id,omitempty" example:"req_123456"`
	RiskLevel        string     `gorm:"default:MINIMAL" json:"risk_level" example:"MEDIUM"`
	RiskScore        int        `gorm:"default:0" json:"risk_score" example:"75"`
	RiskFactors      *string    `gorm:"type:json" json:"risk_factors,omitempty"`
	EventData        *string    `gorm:"type:json" json:"event_data,omitempty"`
	LocationCountry  *string    `json:"location_country,omitempty" example:"US"`
	LocationRegion   *string    `json:"location_region,omitempty" example:"California"`
	LocationCity     *string    `json:"location_city,omitempty" example:"San Francisco"`
	IsResolved       bool       `gorm:"default:false" json:"is_resolved" example:"false"`
	ResolutionAction *string    `json:"resolution_action,omitempty" example:"token_revoked"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy       *string    `gorm:"type:char(26)" json:"resolved_by,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`

	// Relationships
	User           *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client         *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
	ResolvedByUser *User        `json:"resolved_by_user,omitempty" gorm:"foreignKey:ResolvedBy"`
}

// TableName returns the table name for the model
func (OAuthSecurityEvent) TableName() string {
	return "oauth_security_events"
}

// GetRiskFactors returns the risk factors as a slice
func (e *OAuthSecurityEvent) GetRiskFactors() []string {
	if e.RiskFactors == nil || *e.RiskFactors == "" {
		return []string{}
	}

	var factors []string
	json.Unmarshal([]byte(*e.RiskFactors), &factors)
	return factors
}

// SetRiskFactors sets the risk factors from a slice
func (e *OAuthSecurityEvent) SetRiskFactors(factors []string) error {
	data, err := json.Marshal(factors)
	if err != nil {
		return err
	}
	factorsStr := string(data)
	e.RiskFactors = &factorsStr
	return nil
}

// GetEventData returns the event data as a map
func (e *OAuthSecurityEvent) GetEventData() map[string]interface{} {
	if e.EventData == nil || *e.EventData == "" {
		return make(map[string]interface{})
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(*e.EventData), &data)
	return data
}

// SetEventData sets the event data from a map
func (e *OAuthSecurityEvent) SetEventData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataStr := string(jsonData)
	e.EventData = &dataStr
	return nil
}

// IsHighRisk returns true if the event is high risk
func (e *OAuthSecurityEvent) IsHighRisk() bool {
	return e.RiskLevel == "HIGH" || e.RiskScore >= 80
}

// IsCriticalRisk returns true if the event is critical risk
func (e *OAuthSecurityEvent) IsCriticalRisk() bool {
	return e.RiskLevel == "CRITICAL" || e.RiskScore >= 95
}

// Resolve marks the event as resolved
func (e *OAuthSecurityEvent) Resolve(action string, resolvedBy string) {
	e.IsResolved = true
	e.ResolutionAction = &action
	e.ResolvedBy = &resolvedBy
	now := time.Now()
	e.ResolvedAt = &now
}

// GetLocation returns a formatted location string
func (e *OAuthSecurityEvent) GetLocation() string {
	var parts []string

	if e.LocationCity != nil && *e.LocationCity != "" {
		parts = append(parts, *e.LocationCity)
	}

	if e.LocationRegion != nil && *e.LocationRegion != "" {
		parts = append(parts, *e.LocationRegion)
	}

	if e.LocationCountry != nil && *e.LocationCountry != "" {
		parts = append(parts, *e.LocationCountry)
	}

	if len(parts) == 0 {
		return "Unknown"
	}

	location := ""
	for i, part := range parts {
		if i > 0 {
			location += ", "
		}
		location += part
	}

	return location
}
