package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CitySeeder struct {
}

// Signature The name and signature of the seeder.
func (s *CitySeeder) Signature() string {
	return "CitySeeder"
}

// Run executes the seeder logic.
func (s *CitySeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Check if cities already exist
	var cities []models.City
	err := facades.Orm().Query().Limit(1).Find(&cities)
	if err == nil && len(cities) > 0 {
		facades.Log().Info("Cities already exist, skipping CitySeeder")
		return nil
	}

	// Get provinces first
	var provinces []models.Province
	err = facades.Orm().Query().Find(&provinces)
	if err != nil {
		facades.Log().Error("Failed to get provinces: " + err.Error())
		return err
	}

	if len(provinces) == 0 {
		facades.Log().Info("No provinces found, skipping CitySeeder")
		return nil
	}

	// Find specific provinces
	var californiaProvince, newYorkProvince, ontarioProvince, englandProvince models.Province
	for _, province := range provinces {
		switch province.Code {
		case "CA":
			californiaProvince = province
		case "NY":
			newYorkProvince = province
		case "ON":
			ontarioProvince = province
		case "ENG":
			englandProvince = province
		}
	}

	// Create cities for California
	var californiaCities []models.City
	if californiaProvince.ID != "" {
		californiaCities = []models.City{
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
			{
				Name:       "Sacramento",
				Code:       "SAC",
				IsActive:   true,
				ProvinceID: californiaProvince.ID,
			},
		}
	}

	// Create cities for New York
	var newYorkCities []models.City
	if newYorkProvince.ID != "" {
		newYorkCities = []models.City{
			{
				Name:       "New York City",
				Code:       "NYC",
				IsActive:   true,
				ProvinceID: newYorkProvince.ID,
			},
			{
				Name:       "Buffalo",
				Code:       "BUF",
				IsActive:   true,
				ProvinceID: newYorkProvince.ID,
			},
			{
				Name:       "Rochester",
				Code:       "ROC",
				IsActive:   true,
				ProvinceID: newYorkProvince.ID,
			},
		}
	}

	// Create cities for Ontario
	var ontarioCities []models.City
	if ontarioProvince.ID != "" {
		ontarioCities = []models.City{
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
			{
				Name:       "Hamilton",
				Code:       "HAM",
				IsActive:   true,
				ProvinceID: ontarioProvince.ID,
			},
			{
				Name:       "London",
				Code:       "LON",
				IsActive:   true,
				ProvinceID: ontarioProvince.ID,
			},
		}
	}

	// Create cities for England
	var englandCities []models.City
	if englandProvince.ID != "" {
		englandCities = []models.City{
			{
				Name:       "London",
				Code:       "LON",
				IsActive:   true,
				ProvinceID: englandProvince.ID,
			},
			{
				Name:       "Manchester",
				Code:       "MAN",
				IsActive:   true,
				ProvinceID: englandProvince.ID,
			},
			{
				Name:       "Birmingham",
				Code:       "BIR",
				IsActive:   true,
				ProvinceID: englandProvince.ID,
			},
			{
				Name:       "Liverpool",
				Code:       "LIV",
				IsActive:   true,
				ProvinceID: englandProvince.ID,
			},
		}
	}

	// Combine all cities
	allCities := append(californiaCities, newYorkCities...)
	allCities = append(allCities, ontarioCities...)
	allCities = append(allCities, englandCities...)

	// Create cities in database
	seederID := models.USER_SEEDER_ULID
	for _, city := range allCities {
		city.BaseModel = models.BaseModel{
			CreatedBy: &seederID,
			UpdatedBy: &seederID,
			DeletedBy: nil,
		}
		err := facades.Orm().Query().Create(&city)
		if err != nil {
			facades.Log().Error("Failed to create city " + city.Name + ": " + err.Error())
			return err
		}
		facades.Log().Info("Created city: " + city.Name)
	}

	facades.Log().Info("Cities seeded successfully")
	return nil
}
