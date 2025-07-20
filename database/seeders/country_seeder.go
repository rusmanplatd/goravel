package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CountrySeeder struct {
}

// Signature The name and signature of the seeder.
func (s *CountrySeeder) Signature() string {
	return "CountrySeeder"
}

// Run executes the seeder logic.
func (s *CountrySeeder) Run() error {
	// Check if countries already exist
	var existingCountries []models.Country
	err := facades.Orm().Query().Limit(1).Find(&existingCountries)
	if err == nil && len(existingCountries) > 0 {
		facades.Log().Info("Countries already exist, skipping CountrySeeder")
		return nil
	}

	// Create countries
	countries := []models.Country{
		{
			Name:        "United States",
			Code:        "US",
			Code3:       "USA",
			NumericCode: "840",
			IsActive:    true,
		},
		{
			Name:        "Canada",
			Code:        "CA",
			Code3:       "CAN",
			NumericCode: "124",
			IsActive:    true,
		},
		{
			Name:        "United Kingdom",
			Code:        "GB",
			Code3:       "GBR",
			NumericCode: "826",
			IsActive:    true,
		},
		{
			Name:        "Germany",
			Code:        "DE",
			Code3:       "DEU",
			NumericCode: "276",
			IsActive:    true,
		},
		{
			Name:        "France",
			Code:        "FR",
			Code3:       "FRA",
			NumericCode: "250",
			IsActive:    true,
		},
		{
			Name:        "Japan",
			Code:        "JP",
			Code3:       "JPN",
			NumericCode: "392",
			IsActive:    true,
		},
		{
			Name:        "Australia",
			Code:        "AU",
			Code3:       "AUS",
			NumericCode: "036",
			IsActive:    true,
		},
		{
			Name:        "Brazil",
			Code:        "BR",
			Code3:       "BRA",
			NumericCode: "076",
			IsActive:    true,
		},
		{
			Name:        "India",
			Code:        "IN",
			Code3:       "IND",
			NumericCode: "356",
			IsActive:    true,
		},
		{
			Name:        "China",
			Code:        "CN",
			Code3:       "CHN",
			NumericCode: "156",
			IsActive:    true,
		},
	}

	// Create countries in database
	for _, country := range countries {
		err = facades.Orm().Query().Create(&country)
		if err != nil {
			facades.Log().Error("Failed to create country " + country.Name + ": " + err.Error())
			return err
		}
		facades.Log().Info("Created country: " + country.Name)
	}

	facades.Log().Info("Countries seeded successfully")
	return nil
}
