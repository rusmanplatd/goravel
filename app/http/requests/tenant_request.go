package requests

// CreateTenantRequest represents the request for creating a tenant
// @Description Request model for creating a new tenant
type CreateTenantRequest struct {
	// Tenant name
	// @example Acme Corporation
	Name string `json:"name" binding:"required" example:"Acme Corporation" validate:"required"`

	// Tenant slug (unique identifier)
	// @example acme-corp
	Slug string `json:"slug" binding:"required" example:"acme-corp" validate:"required"`

	// Tenant domain
	// @example acme.example.com
	Domain string `json:"domain" example:"acme.example.com"`

	// Tenant description
	// @example A leading technology company
	Description string `json:"description" example:"A leading technology company"`

	// Whether the tenant is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Tenant settings (JSON)
	// @example {"theme": "dark", "timezone": "UTC"}
	Settings string `json:"settings" example:"{\"theme\": \"dark\", \"timezone\": \"UTC\"}"`
}

// UpdateTenantRequest represents the request for updating a tenant
// @Description Request model for updating an existing tenant
type UpdateTenantRequest struct {
	// Tenant name
	// @example Acme Corporation
	Name string `json:"name" example:"Acme Corporation"`

	// Tenant slug (unique identifier)
	// @example acme-corp
	Slug string `json:"slug" example:"acme-corp"`

	// Tenant domain
	// @example acme.example.com
	Domain string `json:"domain" example:"acme.example.com"`

	// Tenant description
	// @example A leading technology company
	Description string `json:"description" example:"A leading technology company"`

	// Whether the tenant is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Tenant settings (JSON)
	// @example {"theme": "dark", "timezone": "UTC"}
	Settings string `json:"settings" example:"{\"theme\": \"dark\", \"timezone\": \"UTC\"}"`
}
