package models

import (
	"time"
)

// PasswordResetToken represents a password reset token
// @Description Password reset token model for Laravel-style password resets
type PasswordResetToken struct {
	// Email address for the reset
	// @example john.doe@example.com
	Email string `gorm:"primaryKey" json:"email" example:"john.doe@example.com"`

	// Reset token
	// @example abc123def456
	Token string `gorm:"not null" json:"token" example:"abc123def456"`

	// When the token was created
	// @example 2024-01-15T10:30:00Z
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`
}
