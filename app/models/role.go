package models

// Role represents a user role within a tenant
// @Description Role model for role-based access control
type Role struct {
	BaseModel

	// Role name
	// @example admin
	Name string `gorm:"not null" json:"name" example:"admin"`

	// Authentication guard
	// @example web
	Guard string `gorm:"not null;default:'api'" json:"guard" example:"web"`

	// Tenant ID for role scope
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID *string `gorm:"index;type:varchar(26)" json:"tenant_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Role description
	// @example Administrator role with full access
	Description string `json:"description" example:"Administrator role with full access"`

	// Relationships
	// @Description Tenant this role belongs to
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// @Description Permissions assigned to this role
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`

	// @Description Users assigned this role
	Users []User `gorm:"many2many:user_roles;" json:"users,omitempty"`
}
