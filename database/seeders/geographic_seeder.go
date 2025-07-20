package seeders

import (
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type GeographicSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *GeographicSeeder) Signature() string {
	return "GeographicSeeder"
}

// Run executes the seeder logic.
func (s *GeographicSeeder) Run() error {
	// Get existing countries for relationships
	var countries []models.Country
	err := facades.Orm().Query().Find(&countries)
	if err != nil {
		facades.Log().Error("Failed to get countries: " + err.Error())
		return err
	}

	if len(countries) == 0 {
		facades.Log().Info("No countries found, skipping GeographicSeeder")
		return nil
	}

	// Create provinces for United States
	usCountry := countries[0]
	usProvinces := []models.Province{
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
	}

	// Create provinces in database
	for _, province := range usProvinces {
		err := facades.Orm().Query().Create(&province)
		if err != nil {
			facades.Log().Error("Failed to create province " + province.Name + ": " + err.Error())
			return err
		}
	}

	// Create cities for California
	californiaProvince := usProvinces[0]
	californiaCities := []models.City{
		{
			Name:       "Los Angeles",
			Code:       "LA",
			IsActive:   true,
			ProvinceID: californiaProvince.ID,
		},
		{
			Name:       "San Francisco",
			Code:       "SF",
			IsActive:   true,
			ProvinceID: californiaProvince.ID,
		},
		{
			Name:       "San Diego",
			Code:       "SD",
			IsActive:   true,
			ProvinceID: californiaProvince.ID,
		},
	}

	// Create cities in database
	for _, city := range californiaCities {
		err := facades.Orm().Query().Create(&city)
		if err != nil {
			facades.Log().Error("Failed to create city " + city.Name + ": " + err.Error())
			return err
		}
	}

	// Create districts for Los Angeles
	losAngelesCity := californiaCities[0]
	losAngelesDistricts := []models.District{
		{
			Name:     "Downtown",
			Code:     "DT",
			IsActive: true,
			CityID:   losAngelesCity.ID,
		},
		{
			Name:     "Hollywood",
			Code:     "HW",
			IsActive: true,
			CityID:   losAngelesCity.ID,
		},
		{
			Name:     "Venice Beach",
			Code:     "VB",
			IsActive: true,
			CityID:   losAngelesCity.ID,
		},
	}

	// Create districts in database
	for _, district := range losAngelesDistricts {
		err := facades.Orm().Query().Create(&district)
		if err != nil {
			facades.Log().Error("Failed to create district " + district.Name + ": " + err.Error())
			return err
		}
	}

	// Create provinces for Canada
	canadaCountry := countries[1]
	canadaProvinces := []models.Province{
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
	}

	// Create Canadian provinces in database
	for _, province := range canadaProvinces {
		err := facades.Orm().Query().Create(&province)
		if err != nil {
			facades.Log().Error("Failed to create province " + province.Name + ": " + err.Error())
			return err
		}
	}

	// Create cities for Ontario
	ontarioProvince := canadaProvinces[0]
	ontarioCities := []models.City{
		{
			Name:       "Toronto",
			Code:       "TOR",
			IsActive:   true,
			ProvinceID: ontarioProvince.ID,
		},
		{
			Name:       "Ottawa",
			Code:       "OTT",
			IsActive:   true,
			ProvinceID: ontarioProvince.ID,
		},
	}

	// Create Ontario cities in database
	for _, city := range ontarioCities {
		err := facades.Orm().Query().Create(&city)
		if err != nil {
			facades.Log().Error("Failed to create city " + city.Name + ": " + err.Error())
			return err
		}
	}

	// Create districts for Toronto
	torontoCity := ontarioCities[0]
	torontoDistricts := []models.District{
		{
			Name:     "Downtown Toronto",
			Code:     "DT",
			IsActive: true,
			CityID:   torontoCity.ID,
		},
		{
			Name:     "North York",
			Code:     "NY",
			IsActive: true,
			CityID:   torontoCity.ID,
		},
	}

	// Create Toronto districts in database
	for _, district := range torontoDistricts {
		err := facades.Orm().Query().Create(&district)
		if err != nil {
			facades.Log().Error("Failed to create district " + district.Name + ": " + err.Error())
			return err
		}
	}

	facades.Log().Info("Geographic seeding completed successfully")
	return nil
}
