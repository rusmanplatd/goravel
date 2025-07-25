package seeders

import (
	"fmt"
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
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
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
	var losAngelesCity, newYorkCity, torontoCity, londonCity, bandungCity, jakartaPusatCity, shahAlamCity, singaporeCity models.City
	for _, city := range cities {
		switch city.Code {
		case "LA":
			losAngelesCity = city
		case "NYC":
			newYorkCity = city
		case "TOR":
			torontoCity = city
		case "LON":
			if city.Name == "London" {
				londonCity = city
			}
		case "BDG":
			bandungCity = city
		case "JKT-PST":
			jakartaPusatCity = city
		case "SHA":
			shahAlamCity = city
		case "SGC":
			singaporeCity = city
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

	// Create districts for Bandung
	var bandungDistricts []models.District
	if bandungCity.ID != "" {
		bandungDistricts = []models.District{
			{Name: "Coblong", Code: "CBL", IsActive: true, CityID: bandungCity.ID},
			{Name: "Sukajadi", Code: "SKJ", IsActive: true, CityID: bandungCity.ID},
			{Name: "Cicendo", Code: "CCD", IsActive: true, CityID: bandungCity.ID},
		}
	}
	// Create districts for Jakarta Pusat
	var jakartaPusatDistricts []models.District
	if jakartaPusatCity.ID != "" {
		jakartaPusatDistricts = []models.District{
			{Name: "Gambir", Code: "GMB", IsActive: true, CityID: jakartaPusatCity.ID},
			{Name: "Menteng", Code: "MTG", IsActive: true, CityID: jakartaPusatCity.ID},
			{Name: "Tanah Abang", Code: "TNA", IsActive: true, CityID: jakartaPusatCity.ID},
		}
	}
	// Create districts for Shah Alam
	var shahAlamDistricts []models.District
	if shahAlamCity.ID != "" {
		shahAlamDistricts = []models.District{
			{Name: "Seksyen 2", Code: "S2", IsActive: true, CityID: shahAlamCity.ID},
			{Name: "Seksyen 7", Code: "S7", IsActive: true, CityID: shahAlamCity.ID},
			{Name: "Seksyen 13", Code: "S13", IsActive: true, CityID: shahAlamCity.ID},
		}
	}
	// Create districts for Singapore City
	var singaporeDistricts []models.District
	if singaporeCity.ID != "" {
		singaporeDistricts = []models.District{
			{Name: "Central Area", Code: "CA", IsActive: true, CityID: singaporeCity.ID},
			{Name: "Orchard", Code: "ORC", IsActive: true, CityID: singaporeCity.ID},
			{Name: "Marina South", Code: "MS", IsActive: true, CityID: singaporeCity.ID},
		}
	}

	// Find specific cities
	var jongnoCity, gangnamCity, bayanzurkhCity models.City
	for _, city := range cities {
		switch city.Code {
		case "JNG":
			jongnoCity = city
		case "GNM":
			gangnamCity = city
		case "BYZ":
			bayanzurkhCity = city
		}
	}
	// Create districts for Jongno-gu
	var jongnoDistricts []models.District
	if jongnoCity.ID != "" {
		jongnoDistricts = []models.District{
			{Name: "Gahoe-dong", Code: "GHD", IsActive: true, CityID: jongnoCity.ID},
			{Name: "Samcheong-dong", Code: "SCD", IsActive: true, CityID: jongnoCity.ID},
			{Name: "Buam-dong", Code: "BMD", IsActive: true, CityID: jongnoCity.ID},
		}
	}
	// Create districts for Gangnam-gu
	var gangnamDistricts []models.District
	if gangnamCity.ID != "" {
		gangnamDistricts = []models.District{
			{Name: "Yeoksam-dong", Code: "YSD", IsActive: true, CityID: gangnamCity.ID},
			{Name: "Nonhyeon-dong", Code: "NHD", IsActive: true, CityID: gangnamCity.ID},
			{Name: "Sinsa-dong", Code: "SSD", IsActive: true, CityID: gangnamCity.ID},
		}
	}
	// Create districts for Bayanzurkh
	var bayanzurkhDistricts []models.District
	if bayanzurkhCity.ID != "" {
		bayanzurkhDistricts = []models.District{
			{Name: "13th Khoroo", Code: "13K", IsActive: true, CityID: bayanzurkhCity.ID},
			{Name: "14th Khoroo", Code: "14K", IsActive: true, CityID: bayanzurkhCity.ID},
			{Name: "15th Khoroo", Code: "15K", IsActive: true, CityID: bayanzurkhCity.ID},
		}
	}
	// Find specific cities
	var milanCity, sevilleCity models.City
	for _, city := range cities {
		switch city.Code {
		case "MIL":
			milanCity = city
		case "SEV":
			sevilleCity = city
		}
	}
	// Create districts for Milan
	var milanDistricts []models.District
	if milanCity.ID != "" {
		milanDistricts = []models.District{
			{Name: "Centro Storico", Code: "CS", IsActive: true, CityID: milanCity.ID},
			{Name: "Navigli", Code: "NV", IsActive: true, CityID: milanCity.ID},
			{Name: "Brera", Code: "BR", IsActive: true, CityID: milanCity.ID},
		}
	}
	// Create districts for Seville
	var sevilleDistricts []models.District
	if sevilleCity.ID != "" {
		sevilleDistricts = []models.District{
			{Name: "Casco Antiguo", Code: "CA", IsActive: true, CityID: sevilleCity.ID},
			{Name: "Triana", Code: "TR", IsActive: true, CityID: sevilleCity.ID},
			{Name: "Nervión", Code: "NVN", IsActive: true, CityID: sevilleCity.ID},
		}
	}
	// Combine all districts
	allDistricts := append(losAngelesDistricts, newYorkDistricts...)
	allDistricts = append(allDistricts, torontoDistricts...)
	allDistricts = append(allDistricts, londonDistricts...)
	allDistricts = append(allDistricts, bandungDistricts...)
	allDistricts = append(allDistricts, jakartaPusatDistricts...)
	allDistricts = append(allDistricts, shahAlamDistricts...)
	allDistricts = append(allDistricts, singaporeDistricts...)
	allDistricts = append(allDistricts, jongnoDistricts...)
	allDistricts = append(allDistricts, gangnamDistricts...)
	allDistricts = append(allDistricts, bayanzurkhDistricts...)
	allDistricts = append(allDistricts, milanDistricts...)
	allDistricts = append(allDistricts, sevilleDistricts...)

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
