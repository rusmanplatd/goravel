package models

// Country represents a country in the system
// @Description Country model with provinces relationship
type Country struct {
	BaseModel
	// Country name
	// @example United States
	Name string `gorm:"not null" json:"name" example:"United States"`

	// ISO 3166-1 alpha-2 country code
	// @example US
	Code string `gorm:"unique;not null;size:2" json:"code" example:"US"`

	// ISO 3166-1 alpha-3 country code
	// @example USA
	Code3 string `gorm:"unique;size:3" json:"code3" example:"USA"`

	// Numeric country code
	// @example 840
	NumericCode string `gorm:"size:3" json:"numeric_code" example:"840"`

	// Whether the country is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Relationships
	// @Description Country's provinces/states
	Provinces []Province `gorm:"foreignKey:CountryID" json:"provinces,omitempty"`
}
