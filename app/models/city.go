package models

// City represents a city in the system
// @Description City model with province and districts relationships
type City struct {
	BaseModel
	// City name
	// @example Los Angeles
	Name string `gorm:"not null" json:"name" example:"Los Angeles"`

	// City code/abbreviation
	// @example LA
	Code string `json:"code" example:"LA"`

	// Whether the city is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Foreign key to province
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID string `gorm:"not null" json:"province_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description City's province
	Province Province `gorm:"foreignKey:ProvinceID" json:"province,omitempty"`

	// @Description City's districts
	Districts []District `gorm:"foreignKey:CityID" json:"districts,omitempty"`
}
