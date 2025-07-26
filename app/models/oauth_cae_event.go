package models

import (
	"encoding/json"
	"time"
)

// OAuthCAEEvent represents a Continuous Access Evaluation event
// @Description OAuth CAE Event model for continuous access evaluation
type OAuthCAEEvent struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	EventID         string     `gorm:"unique;not null" json:"event_id" example:"cae_123456789"`
	EventType       string     `gorm:"not null" json:"event_type" example:"user_risk"`
	EventCategory   string     `gorm:"not null" json:"event_category" example:"security"`
	UserID          string     `gorm:"type:char(26);not null" json:"user_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	ClientID        *string    `gorm:"type:char(26)" json:"client_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	SessionID       *string    `json:"session_id,omitempty" example:"sess_123456"`
	TokenID         *string    `json:"token_id,omitempty" example:"token_123456"`
	Subject         string     `gorm:"not null" json:"subject" example:"user"`
	Issuer          string     `gorm:"not null" json:"issuer" example:"https://auth.example.com"`
	Audience        *string    `json:"audience,omitempty" example:"https://api.example.com"`
	IAT             int64      `gorm:"not null" json:"iat" example:"1640995200"`
	EXP             *int64     `json:"exp,omitempty" example:"1640998800"`
	JTI             string     `gorm:"unique;not null" json:"jti" example:"jti_123456"`
	Events          string     `gorm:"type:json;not null" json:"events"`
	RiskLevel       string     `gorm:"default:low" json:"risk_level" example:"medium"`
	RiskScore       int        `gorm:"default:0" json:"risk_score" example:"75"`
	IPAddress       *string    `json:"ip_address,omitempty" example:"192.168.1.100"`
	LocationCountry *string    `json:"location_country,omitempty" example:"US"`
	LocationRegion  *string    `json:"location_region,omitempty" example:"California"`
	LocationCity    *string    `json:"location_city,omitempty" example:"San Francisco"`
	DeviceID        *string    `json:"device_id,omitempty" example:"device_123"`
	UserAgent       *string    `gorm:"type:varchar(500)" json:"user_agent,omitempty"`
	Context         *string    `gorm:"type:json" json:"context,omitempty"`
	ActionTaken     *string    `json:"action_taken,omitempty" example:"revoke"`
	Status          string     `gorm:"default:pending" json:"status" example:"pending"`
	ProcessedAt     *time.Time `json:"processed_at,omitempty"`
	ProcessedBy     *string    `gorm:"type:char(26)" json:"processed_by,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	ProcessingNotes *string    `gorm:"type:text" json:"processing_notes,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`

	// Relationships
	User            *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client          *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
	ProcessedByUser *User        `json:"processed_by_user,omitempty" gorm:"foreignKey:ProcessedBy"`
}

// TableName returns the table name for the model
func (OAuthCAEEvent) TableName() string {
	return "oauth_cae_events"
}

// GetEvents returns the CAE events as a map
func (e *OAuthCAEEvent) GetEvents() map[string]interface{} {
	if e.Events == "" {
		return make(map[string]interface{})
	}

	var events map[string]interface{}
	json.Unmarshal([]byte(e.Events), &events)
	return events
}

// SetEvents sets the CAE events from a map
func (e *OAuthCAEEvent) SetEvents(events map[string]interface{}) error {
	data, err := json.Marshal(events)
	if err != nil {
		return err
	}
	e.Events = string(data)
	return nil
}

// GetContext returns the context as a map
func (e *OAuthCAEEvent) GetContext() map[string]interface{} {
	if e.Context == nil || *e.Context == "" {
		return make(map[string]interface{})
	}

	var context map[string]interface{}
	json.Unmarshal([]byte(*e.Context), &context)
	return context
}

// SetContext sets the context from a map
func (e *OAuthCAEEvent) SetContext(context map[string]interface{}) error {
	data, err := json.Marshal(context)
	if err != nil {
		return err
	}
	contextStr := string(data)
	e.Context = &contextStr
	return nil
}

// IsHighRisk returns true if the event is high risk
func (e *OAuthCAEEvent) IsHighRisk() bool {
	return e.RiskLevel == "high" || e.RiskScore >= 80
}

// IsCriticalRisk returns true if the event is critical risk
func (e *OAuthCAEEvent) IsCriticalRisk() bool {
	return e.RiskLevel == "critical" || e.RiskScore >= 95
}

// IsPending returns true if the event is pending processing
func (e *OAuthCAEEvent) IsPending() bool {
	return e.Status == "pending"
}

// IsProcessed returns true if the event has been processed
func (e *OAuthCAEEvent) IsProcessed() bool {
	return e.Status == "processed"
}

// IsIgnored returns true if the event has been ignored
func (e *OAuthCAEEvent) IsIgnored() bool {
	return e.Status == "ignored"
}

// Process marks the event as processed
func (e *OAuthCAEEvent) Process(processedBy string, notes string) {
	e.Status = "processed"
	e.ProcessedBy = &processedBy
	e.ProcessingNotes = &notes
	now := time.Now()
	e.ProcessedAt = &now
}

// Ignore marks the event as ignored
func (e *OAuthCAEEvent) Ignore(processedBy string, notes string) {
	e.Status = "ignored"
	e.ProcessedBy = &processedBy
	e.ProcessingNotes = &notes
	now := time.Now()
	e.ProcessedAt = &now
}

// IsExpired returns true if the event has expired
func (e *OAuthCAEEvent) IsExpired() bool {
	return e.EXP != nil && time.Now().Unix() > *e.EXP
}

// GetLocation returns a formatted location string
func (e *OAuthCAEEvent) GetLocation() string {
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

// ToJWT converts the CAE event to JWT format
func (e *OAuthCAEEvent) ToJWT() map[string]interface{} {
	jwt := map[string]interface{}{
		"iss":    e.Issuer,
		"sub":    e.Subject,
		"aud":    e.Audience,
		"iat":    e.IAT,
		"jti":    e.JTI,
		"events": e.GetEvents(),
	}

	if e.EXP != nil {
		jwt["exp"] = *e.EXP
	}

	return jwt
}
