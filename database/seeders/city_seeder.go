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

	// Map of Indonesian province codes to their major cities (comprehensive list)
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
			{Name: "Kepulauan Seribu", Code: "JKT-KPS"},
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
			{Name: "Cirebon", Code: "CRB"},
			{Name: "Indramayu", Code: "IDM"},
			{Name: "Kuningan", Code: "KNG"},
			{Name: "Majalengka", Code: "MJL"},
			{Name: "Sumedang", Code: "SMD"},
			{Name: "Garut", Code: "GRT"},
			{Name: "Cianjur", Code: "CNJ"},
			{Name: "Purwakarta", Code: "PWK"},
			{Name: "Karawang", Code: "KRW"},
			{Name: "Subang", Code: "SBG"},
			{Name: "Pangandaran", Code: "PGD"},
			{Name: "Ciamis", Code: "CMS"},
			{Name: "Tasikmalaya", Code: "TSM"},
			{Name: "Banjar", Code: "BNJ"},
			{Name: "Cirebon", Code: "CRB"},
			{Name: "Indramayu", Code: "IDM"},
			{Name: "Kuningan", Code: "KNG"},
			{Name: "Majalengka", Code: "MJL"},
			{Name: "Sumedang", Code: "SMD"},
			{Name: "Garut", Code: "GRT"},
			{Name: "Cianjur", Code: "CNJ"},
			{Name: "Purwakarta", Code: "PWK"},
			{Name: "Karawang", Code: "KRW"},
			{Name: "Subang", Code: "SBG"},
			{Name: "Pangandaran", Code: "PGD"},
			{Name: "Ciamis", Code: "CMS"},
		},
		"JT": {
			{Name: "Semarang", Code: "SMG"},
			{Name: "Surakarta", Code: "SKA"},
			{Name: "Magelang", Code: "MGL"},
			{Name: "Pekalongan", Code: "PKL"},
			{Name: "Salatiga", Code: "SLG"},
			{Name: "Tegal", Code: "TGL"},
			{Name: "Kudus", Code: "KDS"},
			{Name: "Jepara", Code: "JPR"},
			{Name: "Demak", Code: "DMK"},
			{Name: "Grobogan", Code: "GBG"},
			{Name: "Blora", Code: "BLA"},
			{Name: "Rembang", Code: "RMB"},
			{Name: "Pati", Code: "PTI"},
			{Name: "Kendal", Code: "KDL"},
			{Name: "Temanggung", Code: "TMG"},
			{Name: "Wonogiri", Code: "WNG"},
			{Name: "Sragen", Code: "SGN"},
			{Name: "Karanganyar", Code: "KRY"},
			{Name: "Boyolali", Code: "BYL"},
			{Name: "Klaten", Code: "KLN"},
			{Name: "Sukoharjo", Code: "SKH"},
			{Name: "Wonosobo", Code: "WNS"},
			{Name: "Banjarnegara", Code: "BJR"},
			{Name: "Purbalingga", Code: "PBL"},
			{Name: "Banyumas", Code: "BMS"},
			{Name: "Cilacap", Code: "CLC"},
			{Name: "Brebes", Code: "BRS"},
			{Name: "Batang", Code: "BTG"},
			{Name: "Pemalang", Code: "PML"},
			{Name: "Banjarnegara", Code: "BJR"},
			{Name: "Kebumen", Code: "KBM"},
			{Name: "Purworejo", Code: "PWR"},
			{Name: "Wonogiri", Code: "WNG"},
			{Name: "Sragen", Code: "SGN"},
			{Name: "Karanganyar", Code: "KRY"},
			{Name: "Boyolali", Code: "BYL"},
			{Name: "Klaten", Code: "KLN"},
			{Name: "Sukoharjo", Code: "SKH"},
			{Name: "Wonosobo", Code: "WNS"},
			{Name: "Banjarnegara", Code: "BJR"},
			{Name: "Purbalingga", Code: "PBL"},
			{Name: "Banyumas", Code: "BMS"},
			{Name: "Cilacap", Code: "CLC"},
			{Name: "Brebes", Code: "BRS"},
			{Name: "Batang", Code: "BTG"},
			{Name: "Pemalang", Code: "PML"},
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
			{Name: "Blitar", Code: "BLT"},
			{Name: "Tulungagung", Code: "TLG"},
			{Name: "Trenggalek", Code: "TRG"},
			{Name: "Ponorogo", Code: "PNG"},
			{Name: "Pacitan", Code: "PCT"},
			{Name: "Ngawi", Code: "NGW"},
			{Name: "Magetan", Code: "MGT"},
			{Name: "Nganjuk", Code: "NNK"},
			{Name: "Jombang", Code: "JBG"},
			{Name: "Sidoarjo", Code: "SDR"},
			{Name: "Gresik", Code: "GRS"},
			{Name: "Lamongan", Code: "LMG"},
			{Name: "Tuban", Code: "TBN"},
			{Name: "Bojonegoro", Code: "BJG"},
			{Name: "Tuban", Code: "TBN"},
			{Name: "Lamongan", Code: "LMG"},
			{Name: "Gresik", Code: "GRS"},
			{Name: "Sidoarjo", Code: "SDR"},
			{Name: "Jombang", Code: "JBG"},
			{Name: "Nganjuk", Code: "NNK"},
			{Name: "Magetan", Code: "MGT"},
			{Name: "Ngawi", Code: "NGW"},
			{Name: "Pacitan", Code: "PCT"},
			{Name: "Ponorogo", Code: "PNG"},
			{Name: "Trenggalek", Code: "TRG"},
			{Name: "Tulungagung", Code: "TLG"},
			{Name: "Blitar", Code: "BLT"},
		},
		"BT": {
			{Name: "Serang", Code: "SRG"},
			{Name: "Tangerang", Code: "TGR"},
			{Name: "Cilegon", Code: "CLG"},
			{Name: "South Tangerang", Code: "TGR-SLT"},
		},
		"YO": {
			{Name: "Yogyakarta", Code: "YOG"},
			{Name: "Sleman", Code: "SLM"},
			{Name: "Bantul", Code: "BTL"},
			{Name: "Kulon Progo", Code: "KLP"},
			{Name: "Gunungkidul", Code: "GNK"},
		},
		"AC": {
			{Name: "Banda Aceh", Code: "BNA"},
			{Name: "Lhokseumawe", Code: "LKS"},
			{Name: "Langsa", Code: "LGS"},
			{Name: "Subulussalam", Code: "SBL"},
			{Name: "Sabang", Code: "SBG"},
			{Name: "Aceh Besar", Code: "ACB"},
			{Name: "Pidie", Code: "PDE"},
			{Name: "Pidie Jaya", Code: "PDJ"},
			{Name: "Bireuen", Code: "BRN"},
			{Name: "Aceh Utara", Code: "ACU"},
			{Name: "Aceh Timur", Code: "ACT"},
			{Name: "Aceh Tengah", Code: "ACT"},
			{Name: "Aceh Tenggara", Code: "ACT"},
			{Name: "Aceh Selatan", Code: "ACS"},
			{Name: "Aceh Barat", Code: "ACB"},
			{Name: "Aceh Barat Daya", Code: "ABD"},
			{Name: "Gayo Lues", Code: "GYL"},
			{Name: "Aceh Jaya", Code: "ACJ"},
			{Name: "Nagan Raya", Code: "NGR"},
			{Name: "Aceh Tamiang", Code: "ACT"},
			{Name: "Bener Meriah", Code: "BNM"},
			{Name: "Simeulue", Code: "SML"},
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
			{Name: "Tanjung Morawa", Code: "TJM"},
			{Name: "Lubuk Pakam", Code: "LBP"},
			{Name: "Stabat", Code: "STB"},
			{Name: "Kisaran", Code: "KSR"},
			{Name: "Rantau Prapat", Code: "RTP"},
			{Name: "Pangkalan Brandan", Code: "PKB"},
			{Name: "Tanjung Pura", Code: "TJP"},
			{Name: "Sei Rampah", Code: "SRP"},
			{Name: "Perbaungan", Code: "PBN"},
			{Name: "Pancur Batu", Code: "PCB"},
			{Name: "Deli Tua", Code: "DLT"},
		},
		"SB": {
			{Name: "Padang", Code: "PDG"},
			{Name: "Bukittinggi", Code: "BKT"},
			{Name: "Payakumbuh", Code: "PYK"},
			{Name: "Sawahlunto", Code: "SWL"},
			{Name: "Solok", Code: "SLK"},
			{Name: "Pariaman", Code: "PRM"},
			{Name: "Padang Panjang", Code: "PDP"},
			{Name: "Lubuk Sikaping", Code: "LBS"},
			{Name: "Painan", Code: "PNN"},
			{Name: "Muara Sijunjung", Code: "MRS"},
			{Name: "Simpang Ampek", Code: "SPA"},
			{Name: "Lubuk Basung", Code: "LBB"},
			{Name: "Arosuka", Code: "ARS"},
			{Name: "Batusangkar", Code: "BTS"},
			{Name: "Padang Aro", Code: "PDA"},
			{Name: "Tuapejat", Code: "TPJ"},
			{Name: "Sungai Penuh", Code: "SGP"},
		},
		"RI": {
			{Name: "Pekanbaru", Code: "PKU"},
			{Name: "Dumai", Code: "DMI"},
			{Name: "Siak Sri Indrapura", Code: "SSI"},
			{Name: "Ujung Tanjung", Code: "UJT"},
			{Name: "Teluk Kuantan", Code: "TLK"},
			{Name: "Rengat", Code: "RGT"},
			{Name: "Tembilahan", Code: "TMB"},
			{Name: "Bengkalis", Code: "BKL"},
			{Name: "Selat Panjang", Code: "SLP"},
			{Name: "Bagansiapiapi", Code: "BGS"},
			{Name: "Pasir Pengaraian", Code: "PSP"},
			{Name: "Bangkinang", Code: "BNK"},
		},
		"KR": {
			{Name: "Batam", Code: "BTM"},
			{Name: "Tanjungpinang", Code: "TJP"},
			{Name: "Tanjung Balai Karimun", Code: "TBK"},
			{Name: "Ranai", Code: "RNI"},
			{Name: "Daik", Code: "DAK"},
			{Name: "Tarempa", Code: "TRP"},
			{Name: "Letung", Code: "LTG"},
		},
		"JA": {
			{Name: "Jambi", Code: "JBI"},
			{Name: "Sungai Penuh", Code: "SGP"},
			{Name: "Muara Bulian", Code: "MRB"},
			{Name: "Muara Tebo", Code: "MRT"},
			{Name: "Bangko", Code: "BNK"},
			{Name: "Muara Bungo", Code: "MRB"},
			{Name: "Sarolangun", Code: "SRL"},
			{Name: "Kuala Tungkal", Code: "KLT"},
			{Name: "Sengeti", Code: "SNG"},
		},
		"SS": {
			{Name: "Palembang", Code: "PLB"},
			{Name: "Lubuklinggau", Code: "LBG"},
			{Name: "Pagar Alam", Code: "PGA"},
			{Name: "Prabumulih", Code: "PRB"},
			{Name: "Sekayu", Code: "SKY"},
			{Name: "Muara Enim", Code: "MRE"},
			{Name: "Lahat", Code: "LHT"},
			{Name: "Baturaja", Code: "BTR"},
			{Name: "Kayuagung", Code: "KYG"},
			{Name: "Indralaya", Code: "IDL"},
			{Name: "Tanjung Raja", Code: "TJR"},
			{Name: "Pangkalan Lampam", Code: "PKL"},
			{Name: "Muaradua", Code: "MRD"},
			{Name: "Martapura", Code: "MTP"},
		},
		"BE": {
			{Name: "Bengkulu", Code: "BKL"},
			{Name: "Curup", Code: "CRP"},
			{Name: "Manna", Code: "MNA"},
			{Name: "Tais", Code: "TAS"},
			{Name: "Argamakmur", Code: "AGM"},
			{Name: "Bintuhan", Code: "BNT"},
			{Name: "Kepahiang", Code: "KPH"},
			{Name: "Mukomuko", Code: "MKM"},
		},
		"LA": {
			{Name: "Bandar Lampung", Code: "BDL"},
			{Name: "Metro", Code: "MTR"},
			{Name: "Kalianda", Code: "KLD"},
			{Name: "Gunung Sugih", Code: "GNS"},
			{Name: "Kotabumi", Code: "KTB"},
			{Name: "Menggala", Code: "MGL"},
			{Name: "Blambangan Umpu", Code: "BLB"},
			{Name: "Liwa", Code: "LWA"},
			{Name: "Krui", Code: "KRI"},
			{Name: "Sukadana", Code: "SKD"},
			{Name: "Tulang Bawang Tengah", Code: "TBT"},
		},
		"BB": {
			{Name: "Pangkalpinang", Code: "PGK"},
			{Name: "Tanjung Pandan", Code: "TJP"},
			{Name: "Manggar", Code: "MGR"},
			{Name: "Toboali", Code: "TBL"},
			{Name: "Koba", Code: "KBA"},
			{Name: "Sungai Liat", Code: "SGL"},
		},
		"KB": {
			{Name: "Pontianak", Code: "PTK"},
			{Name: "Singkawang", Code: "SKW"},
			{Name: "Ketapang", Code: "KTP"},
			{Name: "Sukadana", Code: "SKD"},
			{Name: "Mempawah", Code: "MPW"},
			{Name: "Sambas", Code: "SMB"},
			{Name: "Bengkayang", Code: "BKY"},
			{Name: "Sanggau", Code: "SGG"},
			{Name: "Sintang", Code: "STG"},
			{Name: "Putussibau", Code: "PTS"},
			{Name: "Nanga Pinoh", Code: "NGP"},
			{Name: "Kuala Kapuas", Code: "KLK"},
		},
		"KT": {
			{Name: "Palangka Raya", Code: "PKY"},
			{Name: "Kuala Kurun", Code: "KLK"},
			{Name: "Kuala Pembuang", Code: "KLP"},
			{Name: "Muara Teweh", Code: "MRT"},
			{Name: "Puruk Cahu", Code: "PRC"},
			{Name: "Buntok", Code: "BTK"},
			{Name: "Tamiang Layang", Code: "TML"},
			{Name: "Kuala Kapuas", Code: "KLK"},
			{Name: "Pulang Pisau", Code: "PLP"},
			{Name: "Kuala Kurun", Code: "KLK"},
		},
		"KS": {
			{Name: "Banjarmasin", Code: "BJM"},
			{Name: "Banjarbaru", Code: "BJB"},
			{Name: "Martapura", Code: "MTP"},
			{Name: "Rantau", Code: "RTA"},
			{Name: "Kandangan", Code: "KDG"},
			{Name: "Barabai", Code: "BRB"},
			{Name: "Paringin", Code: "PRG"},
			{Name: "Amuntai", Code: "AMT"},
			{Name: "Tanjung", Code: "TJG"},
			{Name: "Kotabaru", Code: "KTB"},
			{Name: "Pleihari", Code: "PLH"},
			{Name: "Batulicin", Code: "BTL"},
		},
		"KI": {
			{Name: "Samarinda", Code: "SMD"},
			{Name: "Balikpapan", Code: "BPN"},
			{Name: "Bontang", Code: "BTG"},
			{Name: "Tenggarong", Code: "TGR"},
			{Name: "Muara Muntai", Code: "MRM"},
			{Name: "Long Iram", Code: "LGI"},
			{Name: "Melak", Code: "MLK"},
			{Name: "Sendawar", Code: "SDW"},
			{Name: "Muara Wahau", Code: "MRW"},
			{Name: "Sangatta", Code: "SGT"},
			{Name: "Bontang", Code: "BTG"},
			{Name: "Sangasanga", Code: "SGS"},
		},
		"KU": {
			{Name: "Tarakan", Code: "TRK"},
			{Name: "Tanjung Selor", Code: "TJS"},
			{Name: "Malinau", Code: "MLN"},
			{Name: "Nunukan", Code: "NNK"},
			{Name: "Long Bawan", Code: "LGB"},
		},
		"SA": {
			{Name: "Manado", Code: "MDO"},
			{Name: "Bitung", Code: "BTG"},
			{Name: "Tomohon", Code: "TMH"},
			{Name: "Kotamobagu", Code: "KTB"},
			{Name: "Tahuna", Code: "THN"},
			{Name: "Melonguane", Code: "MLG"},
			{Name: "Ondong Siau", Code: "ODS"},
			{Name: "Boroko", Code: "BRK"},
			{Name: "Lolak", Code: "LLK"},
			{Name: "Airmadidi", Code: "AMD"},
			{Name: "Tondano", Code: "TND"},
			{Name: "Amurang", Code: "AMR"},
		},
		"GO": {
			{Name: "Gorontalo", Code: "GTO"},
			{Name: "Limboto", Code: "LBT"},
			{Name: "Tilamuta", Code: "TLM"},
			{Name: "Suwawa", Code: "SWW"},
			{Name: "Marisa", Code: "MRS"},
			{Name: "Kwandang", Code: "KWD"},
		},
		"ST": {
			{Name: "Palu", Code: "PLU"},
			{Name: "Poso", Code: "PSO"},
			{Name: "Tentena", Code: "TTN"},
			{Name: "Ampana", Code: "AMN"},
			{Name: "Kolonedale", Code: "KLD"},
			{Name: "Bungku", Code: "BGK"},
			{Name: "Luwuk", Code: "LWK"},
			{Name: "Salakan", Code: "SLK"},
			{Name: "Toli-Toli", Code: "TLT"},
			{Name: "Donggala", Code: "DGL"},
			{Name: "Parigi", Code: "PRG"},
			{Name: "Sigi Biromaru", Code: "SGB"},
		},
		"SR": {
			{Name: "Mamuju", Code: "MMJ"},
			{Name: "Mamasa", Code: "MMS"},
			{Name: "Pasangkayu", Code: "PSK"},
			{Name: "Majene", Code: "MJN"},
			{Name: "Polewali", Code: "PLW"},
			{Name: "Mamuju Tengah", Code: "MMT"},
		},
		"SN": {
			{Name: "Makassar", Code: "MKS"},
			{Name: "Palopo", Code: "PLP"},
			{Name: "Parepare", Code: "PPR"},
			{Name: "Watampone", Code: "WTP"},
			{Name: "Sengkang", Code: "SNG"},
			{Name: "Soppeng", Code: "SPG"},
			{Name: "Barru", Code: "BRR"},
			{Name: "Pangkajene", Code: "PKJ"},
			{Name: "Maros", Code: "MRS"},
			{Name: "Gowa", Code: "GWA"},
			{Name: "Takalar", Code: "TKL"},
			{Name: "Jeneponto", Code: "JNP"},
			{Name: "Bantaeng", Code: "BTG"},
			{Name: "Bulukumba", Code: "BLK"},
			{Name: "Sinjai", Code: "SNJ"},
			{Name: "Bone", Code: "BNE"},
			{Name: "Wajo", Code: "WJO"},
			{Name: "Sidrap", Code: "SDR"},
			{Name: "Pinrang", Code: "PNR"},
			{Name: "Enrekang", Code: "ENK"},
			{Name: "Tana Toraja", Code: "TTR"},
		},
		"SG": {
			{Name: "Kendari", Code: "KDI"},
			{Name: "Baubau", Code: "BBU"},
			{Name: "Raha", Code: "RHA"},
			{Name: "Kolaka", Code: "KLK"},
			{Name: "Unaaha", Code: "UNH"},
			{Name: "Andoolo", Code: "AND"},
			{Name: "Lasusua", Code: "LSS"},
			{Name: "Wanggudu", Code: "WGD"},
			{Name: "Rumbia", Code: "RMB"},
			{Name: "Pasarwajo", Code: "PSW"},
			{Name: "Bau-Bau", Code: "BBU"},
		},
		"MA": {
			{Name: "Ambon", Code: "AMB"},
			{Name: "Tual", Code: "TUL"},
			{Name: "Masohi", Code: "MSH"},
			{Name: "Bula", Code: "BLA"},
			{Name: "Dobo", Code: "DBO"},
			{Name: "Saumlaki", Code: "SML"},
			{Name: "Langgur", Code: "LGR"},
			{Name: "Tiakur", Code: "TKR"},
		},
		"MU": {
			{Name: "Ternate", Code: "TRN"},
			{Name: "Tidore", Code: "TDR"},
			{Name: "Sofifi", Code: "SFF"},
			{Name: "Labuha", Code: "LBH"},
			{Name: "Sanana", Code: "SNN"},
			{Name: "Jailolo", Code: "JLL"},
			{Name: "Weda", Code: "WDA"},
			{Name: "Maba", Code: "MBA"},
		},
		"PA": {
			{Name: "Jayapura", Code: "JYP"},
			{Name: "Merauke", Code: "MRK"},
			{Name: "Wamena", Code: "WMN"},
			{Name: "Biak", Code: "BIA"},
			{Name: "Serui", Code: "SRY"},
			{Name: "Timika", Code: "TMK"},
			{Name: "Agats", Code: "AGT"},
			{Name: "Kaimana", Code: "KMN"},
			{Name: "Fakfak", Code: "FKF"},
			{Name: "Manokwari", Code: "MNK"},
			{Name: "Sorong", Code: "SRG"},
		},
		"PB": {
			{Name: "Manokwari", Code: "MNK"},
			{Name: "Sorong", Code: "SRG"},
			{Name: "Fakfak", Code: "FKF"},
			{Name: "Kaimana", Code: "KMN"},
			{Name: "Bintuni", Code: "BTN"},
			{Name: "Ransiki", Code: "RSK"},
			{Name: "Teminabuan", Code: "TMN"},
			{Name: "Aimas", Code: "AMS"},
		},
		"BA": {
			{Name: "Denpasar", Code: "DPS"},
			{Name: "Singaraja", Code: "SGR"},
			{Name: "Amlapura", Code: "AML"},
			{Name: "Bangli", Code: "BGL"},
			{Name: "Gianyar", Code: "GNY"},
			{Name: "Tabanan", Code: "TBN"},
			{Name: "Negara", Code: "NGR"},
			{Name: "Mengwi", Code: "MNG"},
			{Name: "Ubud", Code: "UBD"},
			{Name: "Kuta", Code: "KTA"},
			{Name: "Sanur", Code: "SNR"},
			{Name: "Nusa Dua", Code: "NSD"},
		},
		"NB": {
			{Name: "Mataram", Code: "MTR"},
			{Name: "Bima", Code: "BMA"},
			{Name: "Praya", Code: "PRY"},
			{Name: "Selong", Code: "SLG"},
			{Name: "Sumbawa Besar", Code: "SMB"},
			{Name: "Dompu", Code: "DMP"},
			{Name: "Raba", Code: "RBA"},
			{Name: "Taliwang", Code: "TLW"},
			{Name: "Sekotong", Code: "SKT"},
			{Name: "Gerung", Code: "GRG"},
			{Name: "Kediri", Code: "KDR"},
			{Name: "Narmada", Code: "NRM"},
		},
		"NT": {
			{Name: "Kupang", Code: "KPG"},
			{Name: "Atambua", Code: "ATB"},
			{Name: "Kefamenanu", Code: "KFM"},
			{Name: "Soe", Code: "SOE"},
			{Name: "Oelamasi", Code: "OEL"},
			{Name: "Kalabahi", Code: "KLB"},
			{Name: "Larantuka", Code: "LRT"},
			{Name: "Maumere", Code: "MMR"},
			{Name: "Ende", Code: "END"},
			{Name: "Bajawa", Code: "BJW"},
			{Name: "Ruteng", Code: "RTG"},
			{Name: "Labuan Bajo", Code: "LBJ"},
			{Name: "Waingapu", Code: "WGP"},
			{Name: "Waikabubak", Code: "WKB"},
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
