package models

// Province represents a province/state in the system
// @Description Province model with country and cities relationships
type Province struct {
	BaseModel
	// Province name
	// @example California
	Name string `gorm:"not null" json:"name" example:"California"`

	// Province code/abbreviation
	// @example CA
	Code string `gorm:"not null" json:"code" example:"CA"`

	// Numeric province code
	// @example 32
	NumericCode int `gorm:"size:3" json:"numeric_code" example:"32"`

	// Whether the province is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Foreign key to country
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID string `gorm:"not null" json:"country_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Province's country
	Country Country `gorm:"foreignKey:CountryID" json:"country,omitempty"`

	// @Description Province's cities
	Cities []City `gorm:"foreignKey:ProvinceID" json:"cities,omitempty"`
}
