package requests

// CreateCityRequest represents the request for creating a city
// @Description Request model for creating a new city
type CreateCityRequest struct {
	// City name
	// @example Los Angeles
	Name string `json:"name" binding:"required" example:"Los Angeles" validate:"required"`

	// City code/abbreviation
	// @example LA
	Code string `json:"code" example:"LA"`

	// Whether the city is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Province ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID string `json:"province_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// UpdateCityRequest represents the request for updating a city
// @Description Request model for updating an existing city
type UpdateCityRequest struct {
	// City name
	// @example Los Angeles
	Name string `json:"name" example:"Los Angeles"`

	// City code/abbreviation
	// @example LA
	Code string `json:"code" example:"LA"`

	// Whether the city is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Province ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID string `json:"province_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}
