package requests

// CreateProvinceRequest represents the request for creating a province
// @Description Request model for creating a new province
type CreateProvinceRequest struct {
	// Province name
	// @example California
	Name string `json:"name" binding:"required" example:"California" validate:"required"`

	// Province code/abbreviation
	// @example CA
	Code string `json:"code" binding:"required" example:"CA" validate:"required"`

	// Whether the province is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Country ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID string `json:"country_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// UpdateProvinceRequest represents the request for updating a province
// @Description Request model for updating an existing province
type UpdateProvinceRequest struct {
	// Province name
	// @example California
	Name string `json:"name" example:"California"`

	// Province code/abbreviation
	// @example CA
	Code string `json:"code" example:"CA"`

	// Whether the province is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// Country ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID string `json:"country_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}
