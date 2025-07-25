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
	var californiaProvince, newYorkProvince, ontarioProvince, englandProvince, jawaBaratProvince, dkiJakartaProvince, selangorProvince, centralRegionSGProvince models.Province
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
		case "JB":
			jawaBaratProvince = province
		case "JK":
			dkiJakartaProvince = province
		case "SGR":
			selangorProvince = province
		case "CR":
			centralRegionSGProvince = province
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

	// Create cities for Jawa Barat
	var jawaBaratCities []models.City
	if jawaBaratProvince.ID != "" {
		jawaBaratCities = []models.City{
			{Name: "Bandung", Code: "BDG", IsActive: true, ProvinceID: jawaBaratProvince.ID},
			{Name: "Bekasi", Code: "BKS", IsActive: true, ProvinceID: jawaBaratProvince.ID},
			{Name: "Bogor", Code: "BGR", IsActive: true, ProvinceID: jawaBaratProvince.ID},
		}
	}
	// Create cities for DKI Jakarta
	var dkiJakartaCities []models.City
	if dkiJakartaProvince.ID != "" {
		dkiJakartaCities = []models.City{
			{Name: "Jakarta Pusat", Code: "JKT-PST", IsActive: true, ProvinceID: dkiJakartaProvince.ID},
			{Name: "Jakarta Selatan", Code: "JKT-SLT", IsActive: true, ProvinceID: dkiJakartaProvince.ID},
			{Name: "Jakarta Barat", Code: "JKT-BRT", IsActive: true, ProvinceID: dkiJakartaProvince.ID},
		}
	}
	// Create cities for Selangor
	var selangorCities []models.City
	if selangorProvince.ID != "" {
		selangorCities = []models.City{
			{Name: "Shah Alam", Code: "SHA", IsActive: true, ProvinceID: selangorProvince.ID},
			{Name: "Petaling Jaya", Code: "PJ", IsActive: true, ProvinceID: selangorProvince.ID},
			{Name: "Klang", Code: "KLG", IsActive: true, ProvinceID: selangorProvince.ID},
		}
	}
	// Create cities for Central Region (Singapore)
	var centralRegionSGCities []models.City
	if centralRegionSGProvince.ID != "" {
		centralRegionSGCities = []models.City{
			{Name: "Singapore City", Code: "SGC", IsActive: true, ProvinceID: centralRegionSGProvince.ID},
		}
	}

	// Find specific provinces
	var seoulProvince, ulaanbaatarProvince models.Province
	for _, province := range provinces {
		switch province.Code {
		case "SEO":
			seoulProvince = province
		case "ULN":
			ulaanbaatarProvince = province
		}
	}
	// Create cities for Seoul
	var seoulCities []models.City
	if seoulProvince.ID != "" {
		seoulCities = []models.City{
			{Name: "Jongno-gu", Code: "JNG", IsActive: true, ProvinceID: seoulProvince.ID},
			{Name: "Gangnam-gu", Code: "GNM", IsActive: true, ProvinceID: seoulProvince.ID},
			{Name: "Songpa-gu", Code: "SGP", IsActive: true, ProvinceID: seoulProvince.ID},
		}
	}
	// Create cities for Ulaanbaatar
	var ulaanbaatarCities []models.City
	if ulaanbaatarProvince.ID != "" {
		ulaanbaatarCities = []models.City{
			{Name: "Bayanzurkh", Code: "BYZ", IsActive: true, ProvinceID: ulaanbaatarProvince.ID},
			{Name: "Sukhbaatar", Code: "SKB", IsActive: true, ProvinceID: ulaanbaatarProvince.ID},
			{Name: "Chingeltei", Code: "CHG", IsActive: true, ProvinceID: ulaanbaatarProvince.ID},
		}
	}

	// Find specific provinces
	var lombardyProvince, andalusiaProvince models.Province
	for _, province := range provinces {
		switch province.Code {
		case "LOM":
			lombardyProvince = province
		case "AND":
			andalusiaProvince = province
		}
	}
	// Create cities for Lombardy
	var lombardyCities []models.City
	if lombardyProvince.ID != "" {
		lombardyCities = []models.City{
			{Name: "Milan", Code: "MIL", IsActive: true, ProvinceID: lombardyProvince.ID},
			{Name: "Bergamo", Code: "BG", IsActive: true, ProvinceID: lombardyProvince.ID},
			{Name: "Brescia", Code: "BS", IsActive: true, ProvinceID: lombardyProvince.ID},
		}
	}
	// Create cities for Andalusia
	var andalusiaCities []models.City
	if andalusiaProvince.ID != "" {
		andalusiaCities = []models.City{
			{Name: "Seville", Code: "SEV", IsActive: true, ProvinceID: andalusiaProvince.ID},
			{Name: "Malaga", Code: "MLG", IsActive: true, ProvinceID: andalusiaProvince.ID},
			{Name: "Granada", Code: "GRN", IsActive: true, ProvinceID: andalusiaProvince.ID},
		}
	}

	// Map of Indonesian province codes to their major cities (at least capital, up to 3-4 major cities)
	indonesiaCities := map[string][]struct {
		Name string
		Code string
	}{
		"JK": {
			{Name: "Jakarta Pusat", Code: "JKT-PST"},
			{Name: "Jakarta Selatan", Code: "JKT-SLT"},
			{Name: "Jakarta Barat", Code: "JKT-BRT"},
			{Name: "Jakarta Timur", Code: "JKT-TMR"},
			{Name: "Jakarta Utara", Code: "JKT-UTR"},
		},
		"JB": {
			{Name: "Bandung", Code: "BDG"},
			{Name: "Bekasi", Code: "BKS"},
			{Name: "Bogor", Code: "BGR"},
			{Name: "Depok", Code: "DPK"},
			{Name: "Cimahi", Code: "CMH"},
			{Name: "Sukabumi", Code: "SKB"},
			{Name: "Tasikmalaya", Code: "TSM"},
			{Name: "Banjar", Code: "BNJ"},
		},
		"JT": {
			{Name: "Semarang", Code: "SMG"},
			{Name: "Surakarta", Code: "SKA"},
			{Name: "Magelang", Code: "MGL"},
			{Name: "Pekalongan", Code: "PKL"},
			{Name: "Salatiga", Code: "SLG"},
			{Name: "Tegal", Code: "TGL"},
		},
		"JI": {
			{Name: "Surabaya", Code: "SBY"},
			{Name: "Malang", Code: "MLG"},
			{Name: "Kediri", Code: "KDR"},
			{Name: "Madiun", Code: "MDN"},
			{Name: "Mojokerto", Code: "MJK"},
			{Name: "Pasuruan", Code: "PSR"},
			{Name: "Probolinggo", Code: "PBL"},
			{Name: "Batu", Code: "BAT"},
		},
		"BT": {
			{Name: "Serang", Code: "SRG"},
			{Name: "Tangerang", Code: "TGR"},
			{Name: "Cilegon", Code: "CLG"},
			{Name: "South Tangerang", Code: "TGR-SLT"},
		},
		"YO": {
			{Name: "Yogyakarta", Code: "YOG"},
		},
		"AC": {
			{Name: "Banda Aceh", Code: "BNA"},
			{Name: "Lhokseumawe", Code: "LKS"},
			{Name: "Langsa", Code: "LGS"},
			{Name: "Subulussalam", Code: "SBL"},
			{Name: "Sabang", Code: "SBG"},
		},
		"SU": {
			{Name: "Medan", Code: "MDN"},
			{Name: "Binjai", Code: "BNJ"},
			{Name: "Pematangsiantar", Code: "PMS"},
			{Name: "Tebing Tinggi", Code: "TBT"},
			{Name: "Padang Sidempuan", Code: "PSP"},
			{Name: "Sibolga", Code: "SBL"},
			{Name: "Tanjungbalai", Code: "TJB"},
			{Name: "Gunungsitoli", Code: "GST"},
		},
		"SB": {
			{Name: "Padang", Code: "PDG"},
			{Name: "Bukittinggi", Code: "BKT"},
			{Name: "Payakumbuh", Code: "PYK"},
			{Name: "Sawahlunto", Code: "SWL"},
			{Name: "Solok", Code: "SLK"},
			{Name: "Pariaman", Code: "PRM"},
			{Name: "Padang Panjang", Code: "PDP"},
		},
		"RI": {
			{Name: "Pekanbaru", Code: "PKU"},
			{Name: "Dumai", Code: "DMI"},
		},
		"KR": {
			{Name: "Batam", Code: "BTM"},
			{Name: "Tanjungpinang", Code: "TJP"},
		},
		"JA": {
			{Name: "Jambi", Code: "JBI"},
			{Name: "Sungai Penuh", Code: "SGP"},
		},
		"SS": {
			{Name: "Palembang", Code: "PLB"},
			{Name: "Lubuklinggau", Code: "LBG"},
			{Name: "Pagar Alam", Code: "PGA"},
			{Name: "Prabumulih", Code: "PRB"},
		},
		"BE": {
			{Name: "Bengkulu", Code: "BKL"},
		},
		"LA": {
			{Name: "Bandar Lampung", Code: "BDL"},
			{Name: "Metro", Code: "MTR"},
		},
		"BB": {
			{Name: "Pangkalpinang", Code: "PGK"},
		},
		"KB": {
			{Name: "Pontianak", Code: "PTK"},
			{Name: "Singkawang", Code: "SKW"},
		},
		"KT": {
			{Name: "Palangka Raya", Code: "PKY"},
		},
		"KS": {
			{Name: "Banjarmasin", Code: "BJM"},
			{Name: "Banjarbaru", Code: "BJB"},
		},
		"KI": {
			{Name: "Samarinda", Code: "SMD"},
			{Name: "Balikpapan", Code: "BPN"},
			{Name: "Bontang", Code: "BTG"},
		},
		"KU": {
			{Name: "Tarakan", Code: "TRK"},
		},
		"SA": {
			{Name: "Manado", Code: "MDO"},
			{Name: "Bitung", Code: "BTG"},
			{Name: "Tomohon", Code: "TMH"},
			{Name: "Kotamobagu", Code: "KTB"},
		},
		"GO": {
			{Name: "Gorontalo", Code: "GTO"},
		},
		"ST": {
			{Name: "Palu", Code: "PLU"},
		},
		"SR": {
			{Name: "Mamuju", Code: "MMJ"},
		},
		"SN": {
			{Name: "Makassar", Code: "MKS"},
			{Name: "Palopo", Code: "PLP"},
			{Name: "Parepare", Code: "PPR"},
		},
		"SG": {
			{Name: "Kendari", Code: "KDI"},
			{Name: "Baubau", Code: "BBU"},
		},
		"MA": {
			{Name: "Ambon", Code: "AMB"},
			{Name: "Tual", Code: "TUL"},
		},
		"MU": {
			{Name: "Ternate", Code: "TRN"},
			{Name: "Tidore", Code: "TDR"},
		},
		"PA": {
			{Name: "Jayapura", Code: "JYP"},
		},
		"PB": {
			{Name: "Manokwari", Code: "MNK"},
			{Name: "Sorong", Code: "SRG"},
		},
		"BA": {
			{Name: "Denpasar", Code: "DPS"},
		},
		"NB": {
			{Name: "Mataram", Code: "MTR"},
			{Name: "Bima", Code: "BMA"},
		},
		"NT": {
			{Name: "Kupang", Code: "KPG"},
		},
	}

	// Map province code to province struct for quick lookup
	provinceMap := make(map[string]models.Province)
	for _, province := range provinces {
		provinceMap[province.Code] = province
	}

	var indonesianCities []models.City
	for code, cities := range indonesiaCities {
		province, ok := provinceMap[code]
		if !ok || province.ID == "" {
			continue
		}
		for _, city := range cities {
			indonesianCities = append(indonesianCities, models.City{
				Name:       city.Name,
				Code:       city.Code,
				IsActive:   true,
				ProvinceID: province.ID,
			})
		}
	}

	// Combine all cities
	allCities := append(californiaCities, newYorkCities...)
	allCities = append(allCities, ontarioCities...)
	allCities = append(allCities, englandCities...)
	allCities = append(allCities, jawaBaratCities...)
	allCities = append(allCities, dkiJakartaCities...)
	allCities = append(allCities, selangorCities...)
	allCities = append(allCities, centralRegionSGCities...)
	allCities = append(allCities, seoulCities...)
	allCities = append(allCities, ulaanbaatarCities...)
	allCities = append(allCities, lombardyCities...)
	allCities = append(allCities, andalusiaCities...)
	allCities = append(allCities, indonesianCities...)

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
