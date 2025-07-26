package models

import (
	"encoding/json"
	"time"
)

// UserProfile represents a user's extended profile information
// @Description User profile model with comprehensive profile data for OAuth2 and identity provider integration
type UserProfile struct {
	BaseModel

	// Reference to users table
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"unique;not null;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Personal Information
	// @example John
	FirstName *string `json:"first_name,omitempty" example:"John"`
	// @example Michael
	MiddleName *string `json:"middle_name,omitempty" example:"Michael"`
	// @example Doe
	LastName *string `json:"last_name,omitempty" example:"Doe"`
	// @example Johnny
	DisplayName *string `json:"display_name,omitempty" example:"Johnny"`
	// @example JD
	Nickname *string `json:"nickname,omitempty" example:"JD"`
	// @example male
	Gender *string `json:"gender,omitempty" example:"male"`
	// @example 1990-01-15
	Birthdate *time.Time `gorm:"type:date" json:"birthdate,omitempty" example:"1990-01-15"`
	// @example https://johndoe.com
	Website *string `json:"website,omitempty" example:"https://johndoe.com"`
	// @example Software engineer passionate about building great products
	Bio *string `json:"bio,omitempty" example:"Software engineer passionate about building great products"`

	// Contact Information
	// @example true
	PhoneVerified bool `gorm:"default:false" json:"phone_verified" example:"true"`
	// @example 2024-01-15T10:30:00Z
	PhoneVerifiedAt *time.Time `json:"phone_verified_at,omitempty" example:"2024-01-15T10:30:00Z"`
	// @example true
	EmailVerified bool `gorm:"default:false" json:"email_verified" example:"true"`

	// Location/Address Information
	// @example 123 Main St
	StreetAddress *string `json:"street_address,omitempty" example:"123 Main St"`
	// @example New York
	Locality *string `json:"locality,omitempty" example:"New York"`
	// @example NY
	Region *string `json:"region,omitempty" example:"NY"`
	// @example 10001
	PostalCode *string `json:"postal_code,omitempty" example:"10001"`
	// @example US
	CountryCode *string `json:"country_code,omitempty" example:"US"`
	// @example 123 Main St\nNew York, NY 10001\nUS
	FormattedAddress *string `json:"formatted_address,omitempty" example:"123 Main St\\nNew York, NY 10001\\nUS"`

	// Location references to existing models
	// @example 01HXYZ123456789ABCDEFGHIJK
	CountryID *string `gorm:"type:char(26)" json:"country_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`
	// @example 01HXYZ123456789ABCDEFGHIJK
	ProvinceID *string `gorm:"type:char(26)" json:"province_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`
	// @example 01HXYZ123456789ABCDEFGHIJK
	CityID *string `gorm:"type:char(26)" json:"city_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`
	// @example 01HXYZ123456789ABCDEFGHIJK
	DistrictID *string `gorm:"type:char(26)" json:"district_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Preferences
	// @example America/New_York
	Timezone string `gorm:"default:UTC" json:"timezone" example:"America/New_York"`
	// @example en-US
	Locale string `gorm:"default:en-US" json:"locale" example:"en-US"`
	// @example en
	Language string `gorm:"default:en" json:"language" example:"en"`
	// @example USD
	Currency string `gorm:"default:USD" json:"currency" example:"USD"`
	// @example Y-m-d
	DateFormat string `gorm:"default:Y-m-d" json:"date_format" example:"Y-m-d"`
	// @example H:i
	TimeFormat string `gorm:"default:H:i" json:"time_format" example:"H:i"`

	// Account Information
	// @example personal
	AccountType string `gorm:"default:personal" json:"account_type" example:"personal"`
	// @example user
	UserType string `gorm:"default:user" json:"user_type" example:"user"`
	// @example active
	Status string `gorm:"default:active" json:"status" example:"active"`

	// Social/Professional Information
	// @example Acme Corporation
	Company *string `json:"company,omitempty" example:"Acme Corporation"`
	// @example Senior Software Engineer
	JobTitle *string `json:"job_title,omitempty" example:"Senior Software Engineer"`
	// @example Engineering
	Department *string `json:"department,omitempty" example:"Engineering"`
	// @example EMP001
	EmployeeID *string `json:"employee_id,omitempty" example:"EMP001"`
	// @example 2024-01-15
	HireDate *time.Time `gorm:"type:date" json:"hire_date,omitempty" example:"2024-01-15"`

	// Additional Profile Data
	// @example {"interests":["technology","music"],"skills":["golang","javascript"]}
	ProfileData *string `gorm:"type:text" json:"profile_data,omitempty" example:"{\"interests\":[\"technology\",\"music\"],\"skills\":[\"golang\",\"javascript\"]}"`
	// @example {"theme":"dark","notifications":{"email":true,"push":false}}
	Preferences *string `gorm:"type:text" json:"preferences,omitempty" example:"{\"theme\":\"dark\",\"notifications\":{\"email\":true,\"push\":false}}"`
	// @example {"source":"google","last_sync":"2024-01-15T10:30:00Z"}
	Metadata *string `gorm:"type:text" json:"metadata,omitempty" example:"{\"source\":\"google\",\"last_sync\":\"2024-01-15T10:30:00Z\"}"`

	// Visibility/Privacy Settings
	// @example false
	ProfilePublic bool `gorm:"default:false" json:"profile_public" example:"false"`
	// @example false
	ShowEmail bool `gorm:"default:false" json:"show_email" example:"false"`
	// @example false
	ShowPhone bool `gorm:"default:false" json:"show_phone" example:"false"`
	// @example false
	ShowAddress bool `gorm:"default:false" json:"show_address" example:"false"`

	// Relationships
	// @Description User this profile belongs to
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
	// @Description Country information
	Country *Country `gorm:"foreignKey:CountryID" json:"country,omitempty"`
	// @Description Province/State information
	Province *Province `gorm:"foreignKey:ProvinceID" json:"province,omitempty"`
	// @Description City information
	City *City `gorm:"foreignKey:CityID" json:"city,omitempty"`
	// @Description District information
	District *District `gorm:"foreignKey:DistrictID" json:"district,omitempty"`
}

// TableName returns the table name for the model
func (UserProfile) TableName() string {
	return "user_profiles"
}

// GetFullName returns the user's full name
func (p *UserProfile) GetFullName() string {
	var parts []string
	if p.FirstName != nil && *p.FirstName != "" {
		parts = append(parts, *p.FirstName)
	}
	if p.MiddleName != nil && *p.MiddleName != "" {
		parts = append(parts, *p.MiddleName)
	}
	if p.LastName != nil && *p.LastName != "" {
		parts = append(parts, *p.LastName)
	}

	if len(parts) == 0 {
		return ""
	}

	fullName := ""
	for i, part := range parts {
		if i > 0 {
			fullName += " "
		}
		fullName += part
	}
	return fullName
}

// GetDisplayName returns the preferred display name or full name
func (p *UserProfile) GetDisplayName() string {
	if p.DisplayName != nil && *p.DisplayName != "" {
		return *p.DisplayName
	}
	return p.GetFullName()
}

// GetFormattedAddress returns a formatted address string
func (p *UserProfile) GetFormattedAddress() string {
	if p.FormattedAddress != nil && *p.FormattedAddress != "" {
		return *p.FormattedAddress
	}

	var parts []string
	if p.StreetAddress != nil && *p.StreetAddress != "" {
		parts = append(parts, *p.StreetAddress)
	}

	var cityState string
	if p.Locality != nil && *p.Locality != "" {
		cityState = *p.Locality
	}
	if p.Region != nil && *p.Region != "" {
		if cityState != "" {
			cityState += ", " + *p.Region
		} else {
			cityState = *p.Region
		}
	}
	if p.PostalCode != nil && *p.PostalCode != "" {
		if cityState != "" {
			cityState += " " + *p.PostalCode
		} else {
			cityState = *p.PostalCode
		}
	}
	if cityState != "" {
		parts = append(parts, cityState)
	}

	if p.CountryCode != nil && *p.CountryCode != "" {
		parts = append(parts, *p.CountryCode)
	}

	if len(parts) == 0 {
		return ""
	}

	formatted := ""
	for i, part := range parts {
		if i > 0 {
			formatted += "\n"
		}
		formatted += part
	}
	return formatted
}

// GetAddressMap returns address as a map for OAuth2 claims
func (p *UserProfile) GetAddressMap() map[string]interface{} {
	address := make(map[string]interface{})

	if p.StreetAddress != nil && *p.StreetAddress != "" {
		address["street_address"] = *p.StreetAddress
	}
	if p.Locality != nil && *p.Locality != "" {
		address["locality"] = *p.Locality
	}
	if p.Region != nil && *p.Region != "" {
		address["region"] = *p.Region
	}
	if p.PostalCode != nil && *p.PostalCode != "" {
		address["postal_code"] = *p.PostalCode
	}
	if p.CountryCode != nil && *p.CountryCode != "" {
		address["country"] = *p.CountryCode
	}

	formatted := p.GetFormattedAddress()
	if formatted != "" {
		address["formatted"] = formatted
	}

	if len(address) == 0 {
		return nil
	}

	return address
}

// GetProfileData returns the profile data as a map
func (p *UserProfile) GetProfileData() (map[string]interface{}, error) {
	var data map[string]interface{}
	if p.ProfileData == nil || *p.ProfileData == "" {
		return data, nil
	}
	err := json.Unmarshal([]byte(*p.ProfileData), &data)
	return data, err
}

// SetProfileData sets the profile data from a map
func (p *UserProfile) SetProfileData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonStr := string(jsonData)
	p.ProfileData = &jsonStr
	return nil
}

// GetPreferences returns the preferences as a map
func (p *UserProfile) GetPreferences() (map[string]interface{}, error) {
	var data map[string]interface{}
	if p.Preferences == nil || *p.Preferences == "" {
		return data, nil
	}
	err := json.Unmarshal([]byte(*p.Preferences), &data)
	return data, err
}

// SetPreferences sets the preferences from a map
func (p *UserProfile) SetPreferences(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonStr := string(jsonData)
	p.Preferences = &jsonStr
	return nil
}

// GetMetadata returns the metadata as a map
func (p *UserProfile) GetMetadata() (map[string]interface{}, error) {
	var data map[string]interface{}
	if p.Metadata == nil || *p.Metadata == "" {
		return data, nil
	}
	err := json.Unmarshal([]byte(*p.Metadata), &data)
	return data, err
}

// SetMetadata sets the metadata from a map
func (p *UserProfile) SetMetadata(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonStr := string(jsonData)
	p.Metadata = &jsonStr
	return nil
}

// GetBirthdateString returns birthdate in YYYY-MM-DD format for OAuth2
func (p *UserProfile) GetBirthdateString() string {
	if p.Birthdate == nil {
		return ""
	}
	return p.Birthdate.Format("2006-01-02")
}

// IsProfileComplete checks if the profile has basic required information
func (p *UserProfile) IsProfileComplete() bool {
	return p.FirstName != nil && *p.FirstName != "" &&
		p.LastName != nil && *p.LastName != ""
}

// IsAddressComplete checks if the address information is complete
func (p *UserProfile) IsAddressComplete() bool {
	return p.StreetAddress != nil && *p.StreetAddress != "" &&
		p.Locality != nil && *p.Locality != "" &&
		p.Region != nil && *p.Region != "" &&
		p.PostalCode != nil && *p.PostalCode != "" &&
		p.CountryCode != nil && *p.CountryCode != ""
}
