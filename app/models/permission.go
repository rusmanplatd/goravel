package models

// Permission represents a system permission within a tenant
// @Description Permission model for permission-based access control
type Permission struct {
	BaseModel

	// Permission name
	// @example users.create
	Name string `gorm:"not null" json:"name" example:"users.create"`

	// Authentication guard
	// @example web
	Guard string `gorm:"not null;default:'api'" json:"guard" example:"web"`

	// Tenant ID for permission scope
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID *string `gorm:"index;type:char(26)" json:"tenant_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission description
	// @example Create new users
	Description string `json:"description" example:"Create new users"`

	// Relationships
	// @Description Tenant this permission belongs to
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Roles that have this permission
	Roles []Role `gorm:"many2many:role_permissions;" json:"roles,omitempty"`
}
