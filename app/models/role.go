package models

import (
	"time"
)

// Role represents a user role within a organization
// @Description Role model for role-based access control
type Role struct {
	BaseModel

	// Role name
	// @example admin
	Name string `gorm:"not null" json:"name" example:"admin"`

	// Authentication guard
	// @example web
	Guard string `gorm:"not null;default:'api'" json:"guard" example:"web"`

	// Organization ID for role scope
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID *string `gorm:"index;type:char(26)" json:"organization_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Role description
	// @example Administrator role with full access
	Description string `json:"description" example:"Administrator role with full access"`

	// Relationships
	// @Description Organization this role belongs to
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Permissions assigned to this role
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`

	// @Description Users assigned this role
	Users []User `gorm:"many2many:user_roles;" json:"users,omitempty"`
}

// RolePermission represents the pivot table for role-permission relationship
// @Description Role-permission relationship
type RolePermission struct {
	ID           string    `gorm:"primaryKey;type:char(26)" json:"id"`
	RoleID       string    `gorm:"type:char(26);not null" json:"role_id"`
	PermissionID string    `gorm:"type:char(26);not null" json:"permission_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
