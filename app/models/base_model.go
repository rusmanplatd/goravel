package models

import (
	"time"

	"goravel/app/helpers"

	"gorm.io/gorm"
)

// BaseModel provides a base model with ULID primary key
// @Description Base model with ULID primary key and timestamps
type BaseModel struct {
	// Unique identifier (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ID string `gorm:"primaryKey;type:varchar(26)" json:"id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Creation timestamp
	// @example 2024-01-15T10:30:00Z
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`

	// Last update timestamp
	// @example 2024-01-15T10:30:00Z
	UpdatedAt time.Time `json:"updated_at" example:"2024-01-15T10:30:00Z"`

	// Soft delete timestamp
	// @example 2024-01-15T10:30:00Z
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty" example:"2024-01-15T10:30:00Z"`
}

// BeforeCreate will set a ULID rather than numeric ID
func (b *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if b.ID == "" {
		b.ID = helpers.GenerateULID()
	}
	return nil
}

// GetID returns the model's ID
func (b *BaseModel) GetID() string {
	return b.ID
}
