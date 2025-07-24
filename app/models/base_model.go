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
	ID string `gorm:"primaryKey;type:char(26)" json:"id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Creation timestamp
	// @example 2024-01-15T10:30:00Z
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`

	// Creator reference (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	CreatedBy *string `gorm:"type:char(26);index" json:"created_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// @Description Event creator
	Creator *User `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`

	// Last update timestamp
	// @example 2024-01-15T10:30:00Z
	UpdatedAt time.Time `json:"updated_at" example:"2024-01-15T10:30:00Z"`

	// Last updater reference (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	UpdatedBy *string `gorm:"type:char(26);index" json:"updated_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Updater reference (User)
	Updater *User `gorm:"foreignKey:UpdatedBy" json:"updater,omitempty"`

	// Soft delete timestamp
	// @example 2024-01-15T10:30:00Z
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Deleter reference (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	DeletedBy *string `gorm:"type:char(26);index" json:"deleted_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Deleter reference (User)
	Deleter *User `gorm:"foreignKey:DeletedBy" json:"deleter,omitempty"`
}

// BeforeCreate will set a ULID rather than numeric ID and set creator reference
func (b *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if b.ID == "" {
		b.ID = helpers.GenerateULID()
	}

	// Get current user ID from context if available
	if userID, ok := tx.Statement.Context.Value("current_user_id").(string); ok && b.CreatedBy == nil {
		b.CreatedBy = &userID
		b.UpdatedBy = &userID
	}

	return nil
}

// BeforeUpdate will set updater reference
func (b *BaseModel) BeforeUpdate(tx *gorm.DB) error {
	if userID, ok := tx.Statement.Context.Value("current_user_id").(string); ok {
		b.UpdatedBy = &userID
	}
	return nil
}

// BeforeDelete will set deleter reference
func (b *BaseModel) BeforeDelete(tx *gorm.DB) error {
	if userID, ok := tx.Statement.Context.Value("current_user_id").(string); ok {
		b.DeletedBy = &userID
	}
	return nil
}

// GetID returns the model's ID
func (b *BaseModel) GetID() string {
	return b.ID
}
