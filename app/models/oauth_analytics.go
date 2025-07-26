package models

import (
	"encoding/json"
	"time"
)

// OAuthAnalytics represents analytics data for OAuth2 operations
// @Description OAuth Analytics model for tracking metrics and usage patterns
type OAuthAnalytics struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	MetricName string    `gorm:"not null" json:"metric_name" example:"token_requests"`
	MetricType string    `gorm:"not null" json:"metric_type" example:"counter"`
	ClientID   *string   `gorm:"type:char(26)" json:"client_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	UserID     *string   `gorm:"type:char(26)" json:"user_id,omitempty" example:"01HXZ1234567890ABCDEFGHIJK"`
	Scope      *string   `json:"scope,omitempty" example:"read"`
	GrantType  *string   `json:"grant_type,omitempty" example:"authorization_code"`
	Endpoint   *string   `json:"endpoint,omitempty" example:"/oauth/token"`
	Method     *string   `json:"method,omitempty" example:"POST"`
	StatusCode *int      `json:"status_code,omitempty" example:"200"`
	Value      int64     `gorm:"default:0" json:"value" example:"1"`
	DurationMS *float64  `json:"duration_ms,omitempty" example:"150.5"`
	IPAddress  *string   `json:"ip_address,omitempty" example:"192.168.1.100"`
	UserAgent  *string   `gorm:"type:varchar(500)" json:"user_agent,omitempty"`
	Country    *string   `json:"country,omitempty" example:"US"`
	Region     *string   `json:"region,omitempty" example:"California"`
	City       *string   `json:"city,omitempty" example:"San Francisco"`
	Labels     *string   `gorm:"type:json" json:"labels,omitempty"`
	Metadata   *string   `gorm:"type:json" json:"metadata,omitempty"`
	Date       time.Time `gorm:"type:date;not null" json:"date" example:"2023-12-01"`
	Hour       int       `gorm:"not null" json:"hour" example:"14"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Relationships
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName returns the table name for the model
func (OAuthAnalytics) TableName() string {
	return "oauth_analytics"
}

// GetLabels returns the labels as a map
func (a *OAuthAnalytics) GetLabels() map[string]string {
	if a.Labels == nil || *a.Labels == "" {
		return make(map[string]string)
	}

	var labels map[string]string
	json.Unmarshal([]byte(*a.Labels), &labels)
	return labels
}

// SetLabels sets the labels from a map
func (a *OAuthAnalytics) SetLabels(labels map[string]string) error {
	data, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	labelsStr := string(data)
	a.Labels = &labelsStr
	return nil
}

// GetMetadata returns the metadata as a map
func (a *OAuthAnalytics) GetMetadata() map[string]interface{} {
	if a.Metadata == nil || *a.Metadata == "" {
		return make(map[string]interface{})
	}

	var metadata map[string]interface{}
	json.Unmarshal([]byte(*a.Metadata), &metadata)
	return metadata
}

// SetMetadata sets the metadata from a map
func (a *OAuthAnalytics) SetMetadata(metadata map[string]interface{}) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	metadataStr := string(data)
	a.Metadata = &metadataStr
	return nil
}

// IsError returns true if this metric represents an error
func (a *OAuthAnalytics) IsError() bool {
	return a.StatusCode != nil && *a.StatusCode >= 400
}

// IsSuccess returns true if this metric represents a successful operation
func (a *OAuthAnalytics) IsSuccess() bool {
	return a.StatusCode != nil && *a.StatusCode >= 200 && *a.StatusCode < 400
}

// GetLocation returns a formatted location string
func (a *OAuthAnalytics) GetLocation() string {
	var parts []string

	if a.City != nil && *a.City != "" {
		parts = append(parts, *a.City)
	}

	if a.Region != nil && *a.Region != "" {
		parts = append(parts, *a.Region)
	}

	if a.Country != nil && *a.Country != "" {
		parts = append(parts, *a.Country)
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

// IsSlow returns true if the request was slow (over 1 second)
func (a *OAuthAnalytics) IsSlow() bool {
	return a.DurationMS != nil && *a.DurationMS > 1000
}
