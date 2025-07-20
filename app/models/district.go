package models

// District represents a district in the system
// @Description District model with city relationship
type District struct {
	BaseModel
	// District name
	// @example Downtown
	Name string `gorm:"not null" json:"name" example:"Downtown"`

	// District code/abbreviation
	// @example DT
	Code string `json:"code" example:"DT"`

	// Whether the district is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Foreign key to city
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID string `gorm:"not null" json:"city_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description District's city
	City City `gorm:"foreignKey:CityID" json:"city,omitempty"`
}
