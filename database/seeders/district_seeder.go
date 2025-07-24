package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type DistrictSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *DistrictSeeder) Signature() string {
	return "DistrictSeeder"
}

// Run executes the seeder logic.
func (s *DistrictSeeder) Run() error {
	// Check if districts already exist
	var existingDistricts []models.District
	err := facades.Orm().Query().Limit(1).Find(&existingDistricts)
	if err == nil && len(existingDistricts) > 0 {
		facades.Log().Info("Districts already exist, skipping DistrictSeeder")
		return nil
	}

	// Get cities first
	var cities []models.City
	err = facades.Orm().Query().Find(&cities)
	if err != nil {
		facades.Log().Error("Failed to get cities: " + err.Error())
		return err
	}

	if len(cities) == 0 {
		facades.Log().Info("No cities found, skipping DistrictSeeder")
		return nil
	}

	// Find specific cities
	var losAngelesCity, newYorkCity, torontoCity, londonCity models.City
	for _, city := range cities {
		switch city.Code {
		case "LA":
			losAngelesCity = city
		case "NYC":
			newYorkCity = city
		case "TOR":
			torontoCity = city
		case "LON":
			// Check if it's London, England (not London, Ontario)
			if city.Name == "London" {
				londonCity = city
			}
		}
	}

	// Create districts for Los Angeles
	var losAngelesDistricts []models.District
	if losAngelesCity.ID != "" {
		losAngelesDistricts = []models.District{
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
			{
				Name:     "Beverly Hills",
				Code:     "BH",
				IsActive: true,
				CityID:   losAngelesCity.ID,
			},
		}
	}

	// Create districts for New York City
	var newYorkDistricts []models.District
	if newYorkCity.ID != "" {
		newYorkDistricts = []models.District{
			{
				Name:     "Manhattan",
				Code:     "MAN",
				IsActive: true,
				CityID:   newYorkCity.ID,
			},
			{
				Name:     "Brooklyn",
				Code:     "BKL",
				IsActive: true,
				CityID:   newYorkCity.ID,
			},
			{
				Name:     "Queens",
				Code:     "QNS",
				IsActive: true,
				CityID:   newYorkCity.ID,
			},
			{
				Name:     "Bronx",
				Code:     "BRX",
				IsActive: true,
				CityID:   newYorkCity.ID,
			},
		}
	}

	// Create districts for Toronto
	var torontoDistricts []models.District
	if torontoCity.ID != "" {
		torontoDistricts = []models.District{
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
			{
				Name:     "Scarborough",
				Code:     "SCB",
				IsActive: true,
				CityID:   torontoCity.ID,
			},
			{
				Name:     "Etobicoke",
				Code:     "ETB",
				IsActive: true,
				CityID:   torontoCity.ID,
			},
		}
	}

	// Create districts for London, England
	var londonDistricts []models.District
	if londonCity.ID != "" {
		londonDistricts = []models.District{
			{
				Name:     "Westminster",
				Code:     "WST",
				IsActive: true,
				CityID:   londonCity.ID,
			},
			{
				Name:     "Camden",
				Code:     "CMD",
				IsActive: true,
				CityID:   londonCity.ID,
			},
			{
				Name:     "Greenwich",
				Code:     "GRW",
				IsActive: true,
				CityID:   londonCity.ID,
			},
			{
				Name:     "Hackney",
				Code:     "HCK",
				IsActive: true,
				CityID:   londonCity.ID,
			},
		}
	}

	// Combine all districts
	allDistricts := append(losAngelesDistricts, newYorkDistricts...)
	allDistricts = append(allDistricts, torontoDistricts...)
	allDistricts = append(allDistricts, londonDistricts...)

	// Create districts in database
	seederID := models.USER_SEEDER_ULID
	for _, district := range allDistricts {
		district.BaseModel = models.BaseModel{
			CreatedBy: &seederID,
			UpdatedBy: &seederID,
			DeletedBy: nil,
		}
		err := facades.Orm().Query().Create(&district)
		if err != nil {
			facades.Log().Error("Failed to create district " + district.Name + ": " + err.Error())
			return err
		}
		facades.Log().Info("Created district: " + district.Name)
	}

	facades.Log().Info("Districts seeded successfully")
	return nil
}
