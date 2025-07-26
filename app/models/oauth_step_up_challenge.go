package models

import (
	"encoding/json"
	"time"
)

// OAuthStepUpChallenge represents a step-up authentication challenge
// @Description OAuth Step-up Challenge model for stepped up authentication
type OAuthStepUpChallenge struct {
	ID               uint       `gorm:"primaryKey" json:"id"`
	ChallengeID      string     `gorm:"unique;not null" json:"challenge_id" example:"challenge_123456789"`
	UserID           string     `gorm:"type:char(26);not null" json:"user_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	ClientID         string     `gorm:"type:char(26);not null" json:"client_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	SessionID        *string    `json:"session_id,omitempty" example:"sess_123456"`
	TokenID          *string    `json:"token_id,omitempty" example:"token_123456"`
	ChallengeType    string     `gorm:"not null" json:"challenge_type" example:"mfa"`
	ChallengeMethod  string     `gorm:"not null" json:"challenge_method" example:"totp"`
	RequiredACR      string     `gorm:"not null" json:"required_acr" example:"2"`
	CurrentACR       *string    `json:"current_acr,omitempty" example:"1"`
	RequiredAMR      *string    `gorm:"type:json" json:"required_amr,omitempty"`
	CurrentAMR       *string    `gorm:"type:json" json:"current_amr,omitempty"`
	ChallengeReason  string     `gorm:"not null" json:"challenge_reason" example:"high_risk_operation"`
	ChallengeData    *string    `gorm:"type:text" json:"challenge_data,omitempty"`
	ChallengeCode    *string    `json:"challenge_code,omitempty" example:"challenge_abc123"`
	VerificationCode *string    `json:"verification_code,omitempty" example:"123456"`
	Status           string     `gorm:"default:pending" json:"status" example:"pending"`
	Attempts         int        `gorm:"default:0" json:"attempts" example:"0"`
	MaxAttempts      int        `gorm:"default:3" json:"max_attempts" example:"3"`
	IssuedAt         time.Time  `gorm:"not null" json:"issued_at"`
	ExpiresAt        time.Time  `gorm:"not null" json:"expires_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	LastAttemptAt    *time.Time `json:"last_attempt_at,omitempty"`
	CompletionMethod *string    `json:"completion_method,omitempty" example:"totp"`
	CompletionData   *string    `gorm:"type:json" json:"completion_data,omitempty"`
	FailureReason    *string    `json:"failure_reason,omitempty" example:"invalid_code"`
	IPAddress        *string    `json:"ip_address,omitempty" example:"192.168.1.100"`
	UserAgent        *string    `gorm:"type:varchar(500)" json:"user_agent,omitempty"`
	DeviceID         *string    `json:"device_id,omitempty" example:"device_123"`
	Metadata         *string    `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`

	// Relationships
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName returns the table name for the model
func (OAuthStepUpChallenge) TableName() string {
	return "oauth_step_up_challenges"
}

// GetRequiredAMR returns the required AMR as a slice
func (c *OAuthStepUpChallenge) GetRequiredAMR() []string {
	if c.RequiredAMR == nil || *c.RequiredAMR == "" {
		return []string{}
	}

	var amr []string
	json.Unmarshal([]byte(*c.RequiredAMR), &amr)
	return amr
}

// SetRequiredAMR sets the required AMR from a slice
func (c *OAuthStepUpChallenge) SetRequiredAMR(amr []string) error {
	data, err := json.Marshal(amr)
	if err != nil {
		return err
	}
	amrStr := string(data)
	c.RequiredAMR = &amrStr
	return nil
}

// GetCurrentAMR returns the current AMR as a slice
func (c *OAuthStepUpChallenge) GetCurrentAMR() []string {
	if c.CurrentAMR == nil || *c.CurrentAMR == "" {
		return []string{}
	}

	var amr []string
	json.Unmarshal([]byte(*c.CurrentAMR), &amr)
	return amr
}

// SetCurrentAMR sets the current AMR from a slice
func (c *OAuthStepUpChallenge) SetCurrentAMR(amr []string) error {
	data, err := json.Marshal(amr)
	if err != nil {
		return err
	}
	amrStr := string(data)
	c.CurrentAMR = &amrStr
	return nil
}

// GetChallengeData returns the challenge data as a map
func (c *OAuthStepUpChallenge) GetChallengeData() map[string]interface{} {
	if c.ChallengeData == nil || *c.ChallengeData == "" {
		return make(map[string]interface{})
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(*c.ChallengeData), &data)
	return data
}

// SetChallengeData sets the challenge data from a map
func (c *OAuthStepUpChallenge) SetChallengeData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataStr := string(jsonData)
	c.ChallengeData = &dataStr
	return nil
}

// GetCompletionData returns the completion data as a map
func (c *OAuthStepUpChallenge) GetCompletionData() map[string]interface{} {
	if c.CompletionData == nil || *c.CompletionData == "" {
		return make(map[string]interface{})
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(*c.CompletionData), &data)
	return data
}

// SetCompletionData sets the completion data from a map
func (c *OAuthStepUpChallenge) SetCompletionData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataStr := string(jsonData)
	c.CompletionData = &dataStr
	return nil
}

// GetMetadata returns the metadata as a map
func (c *OAuthStepUpChallenge) GetMetadata() map[string]interface{} {
	if c.Metadata == nil || *c.Metadata == "" {
		return make(map[string]interface{})
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(*c.Metadata), &metadata)
	return metadata
}

// SetMetadata sets the metadata from a map
func (c *OAuthStepUpChallenge) SetMetadata(metadata map[string]interface{}) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	metadataStr := string(data)
	c.Metadata = &metadataStr
	return nil
}

// IsPending returns true if the challenge is pending
func (c *OAuthStepUpChallenge) IsPending() bool {
	return c.Status == "pending"
}

// IsCompleted returns true if the challenge is completed
func (c *OAuthStepUpChallenge) IsCompleted() bool {
	return c.Status == "completed"
}

// IsFailed returns true if the challenge has failed
func (c *OAuthStepUpChallenge) IsFailed() bool {
	return c.Status == "failed"
}

// IsExpired returns true if the challenge has expired
func (c *OAuthStepUpChallenge) IsExpired() bool {
	return c.Status == "expired" || time.Now().After(c.ExpiresAt)
}

// IsValid returns true if the challenge is pending and not expired
func (c *OAuthStepUpChallenge) IsValid() bool {
	return c.IsPending() && !c.IsExpired()
}

// CanAttempt returns true if more attempts are allowed
func (c *OAuthStepUpChallenge) CanAttempt() bool {
	return c.IsValid() && c.Attempts < c.MaxAttempts
}

// RecordAttempt records a challenge attempt
func (c *OAuthStepUpChallenge) RecordAttempt() {
	c.Attempts++
	now := time.Now()
	c.LastAttemptAt = &now
}

// Complete marks the challenge as completed
func (c *OAuthStepUpChallenge) Complete(method string, data map[string]interface{}) error {
	c.Status = "completed"
	c.CompletionMethod = &method
	now := time.Now()
	c.CompletedAt = &now

	if data != nil {
		return c.SetCompletionData(data)
	}

	return nil
}

// Fail marks the challenge as failed
func (c *OAuthStepUpChallenge) Fail(reason string) {
	c.Status = "failed"
	c.FailureReason = &reason
}

// Expire marks the challenge as expired
func (c *OAuthStepUpChallenge) Expire() {
	c.Status = "expired"
}

// GetRemainingAttempts returns the number of remaining attempts
func (c *OAuthStepUpChallenge) GetRemainingAttempts() int {
	remaining := c.MaxAttempts - c.Attempts
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetTimeRemaining returns the time remaining before expiration
func (c *OAuthStepUpChallenge) GetTimeRemaining() time.Duration {
	remaining := time.Until(c.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
