package models

import (
	"time"
)

// FolderShare represents a folder share/permission
// @Description Folder sharing model for access control
type FolderShare struct {
	BaseModel
	// Share type (user, link, email)
	// @example user
	ShareType string `gorm:"not null" json:"share_type" example:"user"`

	// Permission level (view, edit, comment, owner)
	// @example edit
	Permission string `gorm:"not null" json:"permission" example:"edit"`

	// Whether share is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Share expiration date
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// Share token for link sharing
	// @example abc123def456ghi789
	ShareToken string `gorm:"unique" json:"share_token,omitempty" example:"abc123def456ghi789"`

	// Email for email sharing
	// @example guest@example.com
	Email string `json:"email,omitempty" example:"guest@example.com"`

	// Share message
	// @example Please review these documents
	Message string `json:"message,omitempty" example:"Please review these documents"`

	// Whether password is required for access
	// @example false
	RequirePassword bool `gorm:"default:false" json:"require_password" example:"false"`

	// Password for protected sharing
	// @example secret123
	Password string `json:"password,omitempty" example:"secret123"`

	// Whether to include subfolders
	// @example true
	IncludeSubfolders bool `gorm:"default:true" json:"include_subfolders" example:"true"`

	// Last accessed time
	// @example 2024-01-15T10:30:00Z
	LastAccessedAt *time.Time `json:"last_accessed_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Folder ID being shared
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FolderID string  `gorm:"not null;index" json:"folder_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Folder   *Folder `gorm:"foreignKey:FolderID" json:"folder,omitempty"`

	// User being shared with (for user shares)
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	SharedWithID *string `gorm:"index" json:"shared_with_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	SharedWith   *User   `gorm:"foreignKey:SharedWithID" json:"shared_with,omitempty"`

	// User who created the share
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	SharedByID string `gorm:"not null;index" json:"shared_by_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	SharedBy   *User  `gorm:"foreignKey:SharedByID" json:"shared_by,omitempty"`
}

// TableName returns the table name for the FolderShare model
func (FolderShare) TableName() string {
	return "folder_shares"
}

// IsExpired checks if the share has expired
func (fs *FolderShare) IsExpired() bool {
	if fs.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*fs.ExpiresAt)
}
