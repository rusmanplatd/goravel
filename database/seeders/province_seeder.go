package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProvinceSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *ProvinceSeeder) Signature() string {
	return "ProvinceSeeder"
}

// Run executes the seeder logic.
func (s *ProvinceSeeder) Run() error {
	// Check if provinces already exist
	var existingProvinces []models.Province
	err := facades.Orm().Query().Limit(1).Find(&existingProvinces)
	if err == nil && len(existingProvinces) > 0 {
		facades.Log().Info("Provinces already exist, skipping ProvinceSeeder")
		return nil
	}

	// Get countries first
	var countries []models.Country
	err = facades.Orm().Query().Find(&countries)
	if err != nil {
		facades.Log().Error("Failed to get countries: " + err.Error())
		return err
	}

	if len(countries) == 0 {
		facades.Log().Info("No countries found, skipping ProvinceSeeder")
		return nil
	}

	// Find specific countries
	var usCountry, canadaCountry, ukCountry models.Country
	for _, country := range countries {
		switch country.Code {
		case "US":
			usCountry = country
		case "CA":
			canadaCountry = country
		case "GB":
			ukCountry = country
		}
	}

	// Create provinces for United States
	var usProvinces []models.Province
	if usCountry.ID != "" {
		usProvinces = []models.Province{
			{
				Name:      "California",
				Code:      "CA",
				IsActive:  true,
				CountryID: usCountry.ID,
			},
			{
				Name:      "New York",
				Code:      "NY",
				IsActive:  true,
				CountryID: usCountry.ID,
			},
			{
				Name:      "Texas",
				Code:      "TX",
				IsActive:  true,
				CountryID: usCountry.ID,
			},
			{
				Name:      "Florida",
				Code:      "FL",
				IsActive:  true,
				CountryID: usCountry.ID,
			},
			{
				Name:      "Illinois",
				Code:      "IL",
				IsActive:  true,
				CountryID: usCountry.ID,
			},
		}
	}

	// Create provinces for Canada
	var canadaProvinces []models.Province
	if canadaCountry.ID != "" {
		canadaProvinces = []models.Province{
			{
				Name:      "Ontario",
				Code:      "ON",
				IsActive:  true,
				CountryID: canadaCountry.ID,
			},
			{
				Name:      "Quebec",
				Code:      "QC",
				IsActive:  true,
				CountryID: canadaCountry.ID,
			},
			{
				Name:      "British Columbia",
				Code:      "BC",
				IsActive:  true,
				CountryID: canadaCountry.ID,
			},
			{
				Name:      "Alberta",
				Code:      "AB",
				IsActive:  true,
				CountryID: canadaCountry.ID,
			},
		}
	}

	// Create provinces for United Kingdom
	var ukProvinces []models.Province
	if ukCountry.ID != "" {
		ukProvinces = []models.Province{
			{
				Name:      "England",
				Code:      "ENG",
				IsActive:  true,
				CountryID: ukCountry.ID,
			},
			{
				Name:      "Scotland",
				Code:      "SCT",
				IsActive:  true,
				CountryID: ukCountry.ID,
			},
			{
				Name:      "Wales",
				Code:      "WLS",
				IsActive:  true,
				CountryID: ukCountry.ID,
			},
			{
				Name:      "Northern Ireland",
				Code:      "NIR",
				IsActive:  true,
				CountryID: ukCountry.ID,
			},
		}
	}

	// Combine all provinces
	allProvinces := append(usProvinces, canadaProvinces...)
	allProvinces = append(allProvinces, ukProvinces...)

	// Create provinces in database
	seederID := models.USER_SEEDER_ULID
	for _, province := range allProvinces {
		province.BaseModel = models.BaseModel{
			CreatedBy: &seederID,
			UpdatedBy: &seederID,
			DeletedBy: nil,
		}
		err := facades.Orm().Query().Create(&province)
		if err != nil {
			facades.Log().Error("Failed to create province " + province.Name + ": " + err.Error())
			return err
		}
		facades.Log().Info("Created province: " + province.Name)
	}

	facades.Log().Info("Provinces seeded successfully")
	return nil
}
