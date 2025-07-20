package requests

// CreateCountryRequest represents the request for creating a country
// @Description Request model for creating a new country
type CreateCountryRequest struct {
	// Country name
	// @example United States
	Name string `json:"name" binding:"required" example:"United States" validate:"required"`

	// ISO 3166-1 alpha-2 country code
	// @example US
	Code string `json:"code" binding:"required,len=2" example:"US" validate:"required,len=2"`

	// ISO 3166-1 alpha-3 country code
	// @example USA
	Code3 string `json:"code3" binding:"omitempty,len=3" example:"USA" validate:"omitempty,len=3"`

	// Numeric country code
	// @example 840
	NumericCode string `json:"numeric_code" binding:"omitempty,len=3" example:"840" validate:"omitempty,len=3"`

	// Whether the country is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`
}

// UpdateCountryRequest represents the request for updating a country
// @Description Request model for updating an existing country
type UpdateCountryRequest struct {
	// Country name
	// @example United States
	Name string `json:"name" example:"United States"`

	// ISO 3166-1 alpha-2 country code
	// @example US
	Code string `json:"code" binding:"omitempty,len=2" example:"US" validate:"omitempty,len=2"`

	// ISO 3166-1 alpha-3 country code
	// @example USA
	Code3 string `json:"code3" binding:"omitempty,len=3" example:"USA" validate:"omitempty,len=3"`

	// Numeric country code
	// @example 840
	NumericCode string `json:"numeric_code" binding:"omitempty,len=3" example:"840" validate:"omitempty,len=3"`

	// Whether the country is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`
}
