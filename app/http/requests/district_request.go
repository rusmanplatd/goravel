package requests

// CreateDistrictRequest represents the request for creating a district
// @Description Request model for creating a new district
type CreateDistrictRequest struct {
	// District name
	// @example Downtown
	Name string `json:"name" binding:"required" example:"Downtown" validate:"required"`

	// District code/abbreviation
	// @example DT
	Code string `json:"code" example:"DT"`

	// Whether the district is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// City ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID string `json:"city_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// UpdateDistrictRequest represents the request for updating a district
// @Description Request model for updating an existing district
type UpdateDistrictRequest struct {
	// District name
	// @example Downtown
	Name string `json:"name" example:"Downtown"`

	// District code/abbreviation
	// @example DT
	Code string `json:"code" example:"DT"`

	// Whether the district is active
	// @example true
	IsActive bool `json:"is_active" example:"true"`

	// City ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID string `json:"city_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}
