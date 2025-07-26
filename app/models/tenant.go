package models

import (
	"goravel/app/helpers"

	"gorm.io/gorm"
)

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

	// @Description Organization associated with this tenant (one-to-one relationship)
	Organization *Organization `gorm:"foreignKey:TenantID" json:"organization,omitempty"`
}

// AfterCreate automatically creates an organization when a tenant is created
func (t *Tenant) AfterCreate(tx *gorm.DB) error {
	// Create a corresponding organization for this tenant
	organization := Organization{
		BaseModel: BaseModel{
			ID:        helpers.GenerateULID(),
			CreatedBy: t.CreatedBy,
			UpdatedBy: t.UpdatedBy,
		},
		Name:        t.Name,
		Slug:        t.Slug,
		Domain:      t.Domain,
		Description: t.Description,
		Type:        "company",    // Default type
		Industry:    "Technology", // Default industry
		Size:        "medium",     // Default size
		IsActive:    t.IsActive,
		IsVerified:  false, // Default to unverified
		Settings:    t.Settings,
		TenantID:    t.ID,
		Level:       0,
		Path:        "/",
	}

	// Create the organization within the same transaction
	return tx.Create(&organization).Error
}
