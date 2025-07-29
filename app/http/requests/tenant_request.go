package requests

// CreateOrganizationRequest represents the request for creating a organization
// @Description Request model for creating a new organization
type CreateOrganizationRequest struct {
	// Organization name
	// @example Acme Corporation
	Name string `json:"name" binding:"required" example:"Acme Corporation" validate:"required"`

	// Organization slug (unique identifier)
	// @example acme-corp
	Slug string `json:"slug" binding:"required" example:"acme-corp" validate:"required"`

	// Organization domain
	// @example acme.example.com
	Domain string `json:"domain" example:"acme.example.com"`

	// Organization description
	// @example A leading technology company
	Description string `json:"description" example:"A leading technology company"`

	// Whether the organization is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Organization settings (JSON)
	// @example {"theme": "dark", "timezone": "UTC"}
	Settings string `json:"settings" example:"{\"theme\": \"dark\", \"timezone\": \"UTC\"}"`
}

// UpdateOrganizationRequest represents the request for updating a organization
// @Description Request model for updating an existing organization
type UpdateOrganizationRequest struct {
	// Organization name
	// @example Acme Corporation
	Name string `json:"name" example:"Acme Corporation"`

	// Organization slug (unique identifier)
	// @example acme-corp
	Slug string `json:"slug" example:"acme-corp"`

	// Organization domain
	// @example acme.example.com
	Domain string `json:"domain" example:"acme.example.com"`

	// Organization description
	// @example A leading technology company
	Description string `json:"description" example:"A leading technology company"`

	// Whether the organization is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Organization settings (JSON)
	// @example {"theme": "dark", "timezone": "UTC"}
	Settings string `json:"settings" example:"{\"theme\": \"dark\", \"timezone\": \"UTC\"}"`
}
