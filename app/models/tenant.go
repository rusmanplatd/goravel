package models

// Tenant represents a multi-tenant organization
// @Description Tenant model for multi-tenant support
type Tenant struct {
	BaseModel

	// Tenant name
	// @example Acme Corporation
	Name string `gorm:"not null" json:"name" example:"Acme Corporation"`

	// Tenant slug for URL identification
	// @example acme-corp
	Slug string `gorm:"unique;not null" json:"slug" example:"acme-corp"`

	// Tenant domain
	// @example acme.com
	Domain string `gorm:"unique" json:"domain" example:"acme.com"`

	// Tenant description
	// @example Main tenant for Acme Corporation
	Description string `json:"description" example:"Main tenant for Acme Corporation"`

	// Whether the tenant is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Tenant settings as JSON
	// @example {"theme":"dark","timezone":"UTC"}
	Settings string `gorm:"type:json" json:"settings" example:"{\"theme\":\"dark\",\"timezone\":\"UTC\"}"`

	// Relationships
	// @Description Users associated with this tenant
	Users []User `gorm:"many2many:user_tenants;" json:"users,omitempty"`
}
