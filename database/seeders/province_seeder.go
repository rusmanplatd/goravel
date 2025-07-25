package seeders

import (
	"fmt"
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
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
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
	var usCountry, canadaCountry, italyCountry, spainCountry, mongoliaCountry, nepalCountry, bangladeshCountry, sriLankaCountry, pakistanCountry, afghanistanCountry, bhutanCountry, maldivesCountry, papuaNewGuineaCountry, fijiCountry, solomonIslandsCountry, samoaCountry, tongaCountry, vanuatuCountry, micronesiaCountry, palauCountry, nauruCountry, tuvaluCountry, marshallIslandsCountry, kiribatiCountry, franceCountry, germanyCountry, ukCountry, japanCountry, australiaCountry, brazilCountry, indiaCountry, chinaCountry, indonesiaCountry, singaporeCountry, malaysiaCountry, philippinesCountry, thailandCountry, vietnamCountry, bruneiCountry, cambodiaCountry, laosCountry, myanmarCountry, timorLesteCountry, southKoreaCountry, russiaCountry, ukraineCountry, belarusCountry, moldovaCountry, romaniaCountry, bulgariaCountry, serbiaCountry, croatiaCountry, sloveniaCountry, slovakiaCountry, estoniaCountry, latviaCountry, lithuaniaCountry, albaniaCountry, northMacedoniaCountry, kosovoCountry, montenegroCountry, bosniaHerzegovinaCountry, portugalCountry, netherlandsCountry, belgiumCountry, switzerlandCountry, austriaCountry, swedenCountry, norwayCountry, denmarkCountry, finlandCountry, polandCountry, czechRepublicCountry, hungaryCountry, greeceCountry, turkeyCountry, egyptCountry, southAfricaCountry, nigeriaCountry, kenyaCountry, ghanaCountry, moroccoCountry, algeriaCountry, tunisiaCountry, ethiopiaCountry, argentinaCountry, chileCountry, colombiaCountry, peruCountry, venezuelaCountry, mexicoCountry, newZealandCountry, saudiArabiaCountry, uaeCountry, qatarCountry, israelCountry, jordanCountry, lebanonCountry, iraqCountry, iranCountry, syriaCountry, yemenCountry, omanCountry, kuwaitCountry, bahrainCountry, cyprusCountry, georgiaCountry, armeniaCountry, azerbaijanCountry, kazakhstanCountry, uzbekistanCountry, turkmenistanCountry, kyrgyzstanCountry, tajikistanCountry, northKoreaCountry, taiwanCountry, hongKongCountry, macauCountry, palestineCountry models.Country
	for _, country := range countries {
		switch country.Code {
		case "US":
			usCountry = country
		case "CA":
			canadaCountry = country
		case "IT":
			italyCountry = country
		case "ES":
			spainCountry = country
		case "MN":
			mongoliaCountry = country
		case "NP":
			nepalCountry = country
		case "BD":
			bangladeshCountry = country
		case "LK":
			sriLankaCountry = country
		case "PK":
			pakistanCountry = country
		case "AF":
			afghanistanCountry = country
		case "BT":
			bhutanCountry = country
		case "MV":
			maldivesCountry = country
		case "PG":
			papuaNewGuineaCountry = country
		case "FJ":
			fijiCountry = country
		case "SB":
			solomonIslandsCountry = country
		case "WS":
			samoaCountry = country
		case "TO":
			tongaCountry = country
		case "VU":
			vanuatuCountry = country
		case "FM":
			micronesiaCountry = country
		case "PW":
			palauCountry = country
		case "NR":
			nauruCountry = country
		case "TV":
			tuvaluCountry = country
		case "MH":
			marshallIslandsCountry = country
		case "KI":
			kiribatiCountry = country
		case "FR":
			franceCountry = country
		case "DE":
			germanyCountry = country
		case "GB":
			ukCountry = country
		case "JP":
			japanCountry = country
		case "AU":
			australiaCountry = country
		case "BR":
			brazilCountry = country
		case "IN":
			indiaCountry = country
		case "CN":
			chinaCountry = country
		case "ID":
			indonesiaCountry = country
		case "SG":
			singaporeCountry = country
		case "MY":
			malaysiaCountry = country
		case "PH":
			philippinesCountry = country
		case "TH":
			thailandCountry = country
		case "VN":
			vietnamCountry = country
		case "BN":
			bruneiCountry = country
		case "KH":
			cambodiaCountry = country
		case "LA":
			laosCountry = country
		case "MM":
			myanmarCountry = country
		case "TL":
			timorLesteCountry = country
		case "KR":
			southKoreaCountry = country
		case "RU":
			russiaCountry = country
		case "UA":
			ukraineCountry = country
		case "BY":
			belarusCountry = country
		case "MD":
			moldovaCountry = country
		case "RO":
			romaniaCountry = country
		case "BG":
			bulgariaCountry = country
		case "RS":
			serbiaCountry = country
		case "HR":
			croatiaCountry = country
		case "SI":
			sloveniaCountry = country
		case "SK":
			slovakiaCountry = country
		case "EE":
			estoniaCountry = country
		case "LV":
			latviaCountry = country
		case "LT":
			lithuaniaCountry = country
		case "AL":
			albaniaCountry = country
		case "MK":
			northMacedoniaCountry = country
		case "XK":
			kosovoCountry = country
		case "ME":
			montenegroCountry = country
		case "BA":
			bosniaHerzegovinaCountry = country
		case "PT":
			portugalCountry = country
		case "NL":
			netherlandsCountry = country
		case "BE":
			belgiumCountry = country
		case "CH":
			switzerlandCountry = country
		case "AT":
			austriaCountry = country
		case "SE":
			swedenCountry = country
		case "NO":
			norwayCountry = country
		case "DK":
			denmarkCountry = country
		case "FI":
			finlandCountry = country
		case "PL":
			polandCountry = country
		case "CZ":
			czechRepublicCountry = country
		case "HU":
			hungaryCountry = country
		case "GR":
			greeceCountry = country
		case "TR":
			turkeyCountry = country
		case "EG":
			egyptCountry = country
		case "ZA":
			southAfricaCountry = country
		case "NG":
			nigeriaCountry = country
		case "KE":
			kenyaCountry = country
		case "GH":
			ghanaCountry = country
		case "MA":
			moroccoCountry = country
		case "DZ":
			algeriaCountry = country
		case "TN":
			tunisiaCountry = country
		case "ET":
			ethiopiaCountry = country
		case "AR":
			argentinaCountry = country
		case "CL":
			chileCountry = country
		case "CO":
			colombiaCountry = country
		case "PE":
			peruCountry = country
		case "VE":
			venezuelaCountry = country
		case "MX":
			mexicoCountry = country
		case "NZ":
			newZealandCountry = country
		case "SA":
			saudiArabiaCountry = country
		case "AE":
			uaeCountry = country
		case "QA":
			qatarCountry = country
		case "IL":
			israelCountry = country
		case "JO":
			jordanCountry = country
		case "LB":
			lebanonCountry = country
		case "IQ":
			iraqCountry = country
		case "IR":
			iranCountry = country
		case "SY":
			syriaCountry = country
		case "YE":
			yemenCountry = country
		case "OM":
			omanCountry = country
		case "KW":
			kuwaitCountry = country
		case "BH":
			bahrainCountry = country
		case "CY":
			cyprusCountry = country
		case "GE":
			georgiaCountry = country
		case "AM":
			armeniaCountry = country
		case "AZ":
			azerbaijanCountry = country
		case "KZ":
			kazakhstanCountry = country
		case "UZ":
			uzbekistanCountry = country
		case "TM":
			turkmenistanCountry = country
		case "KG":
			kyrgyzstanCountry = country
		case "TJ":
			tajikistanCountry = country
		case "KP":
			northKoreaCountry = country
		case "TW":
			taiwanCountry = country
		case "HK":
			hongKongCountry = country
		case "MO":
			macauCountry = country
		case "PS":
			palestineCountry = country
		}
	}
	// Create provinces for Italy
	var italyProvinces []models.Province
	if italyCountry.ID != "" {
		italyProvinces = []models.Province{
			{Name: "Lombardy", Code: "LOM", NumericCode: 1, IsActive: true, CountryID: italyCountry.ID},
			{Name: "Lazio", Code: "LAZ", NumericCode: 2, IsActive: true, CountryID: italyCountry.ID},
			{Name: "Sicily", Code: "SIC", NumericCode: 3, IsActive: true, CountryID: italyCountry.ID},
		}
	}
	// Create provinces for Spain
	var spainProvinces []models.Province
	if spainCountry.ID != "" {
		spainProvinces = []models.Province{
			{Name: "Andalusia", Code: "AND", NumericCode: 1, IsActive: true, CountryID: spainCountry.ID},
			{Name: "Catalonia", Code: "CAT", NumericCode: 2, IsActive: true, CountryID: spainCountry.ID},
			{Name: "Madrid", Code: "MAD", NumericCode: 3, IsActive: true, CountryID: spainCountry.ID},
		}
	}
	// Create provinces for Mongolia
	var mongoliaProvinces []models.Province
	if mongoliaCountry.ID != "" {
		mongoliaProvinces = []models.Province{
			{Name: "Ulaanbaatar", Code: "ULN", NumericCode: 1, IsActive: true, CountryID: mongoliaCountry.ID},
			{Name: "Darkhan-Uul", Code: "DRK", NumericCode: 2, IsActive: true, CountryID: mongoliaCountry.ID},
			{Name: "Orkhon", Code: "ORK", NumericCode: 3, IsActive: true, CountryID: mongoliaCountry.ID},
			{Name: "Selenge", Code: "SLG", NumericCode: 4, IsActive: true, CountryID: mongoliaCountry.ID},
			{Name: "Khovd", Code: "KVD", NumericCode: 5, IsActive: true, CountryID: mongoliaCountry.ID},
		}
	}
	// Create provinces for Nepal
	var nepalProvinces []models.Province
	if nepalCountry.ID != "" {
		nepalProvinces = []models.Province{
			{Name: "Kathmandu", Code: "KTM", NumericCode: 1, IsActive: true, CountryID: nepalCountry.ID},
			{Name: "Pokhara", Code: "PKR", NumericCode: 2, IsActive: true, CountryID: nepalCountry.ID},
			{Name: "Lalitpur", Code: "LTP", NumericCode: 3, IsActive: true, CountryID: nepalCountry.ID},
			{Name: "Bhaktapur", Code: "BKT", NumericCode: 4, IsActive: true, CountryID: nepalCountry.ID},
			{Name: "Dharan", Code: "DHR", NumericCode: 5, IsActive: true, CountryID: nepalCountry.ID},
		}
	}
	// Create provinces for Bangladesh
	var bangladeshProvinces []models.Province
	if bangladeshCountry.ID != "" {
		bangladeshProvinces = []models.Province{
			{Name: "Dhaka", Code: "DAC", NumericCode: 1, IsActive: true, CountryID: bangladeshCountry.ID},
			{Name: "Chittagong", Code: "CTG", NumericCode: 2, IsActive: true, CountryID: bangladeshCountry.ID},
			{Name: "Khulna", Code: "KHL", NumericCode: 3, IsActive: true, CountryID: bangladeshCountry.ID},
			{Name: "Rajshahi", Code: "RAJ", NumericCode: 4, IsActive: true, CountryID: bangladeshCountry.ID},
			{Name: "Sylhet", Code: "SYL", NumericCode: 5, IsActive: true, CountryID: bangladeshCountry.ID},
		}
	}
	// Create provinces for Sri Lanka
	var sriLankaProvinces []models.Province
	if sriLankaCountry.ID != "" {
		sriLankaProvinces = []models.Province{
			{Name: "Colombo", Code: "CMB", NumericCode: 1, IsActive: true, CountryID: sriLankaCountry.ID},
			{Name: "Kandy", Code: "KAN", NumericCode: 2, IsActive: true, CountryID: sriLankaCountry.ID},
			{Name: "Galle", Code: "GAL", NumericCode: 3, IsActive: true, CountryID: sriLankaCountry.ID},
			{Name: "Jaffna", Code: "JAF", NumericCode: 4, IsActive: true, CountryID: sriLankaCountry.ID},
			{Name: "Negombo", Code: "NEG", NumericCode: 5, IsActive: true, CountryID: sriLankaCountry.ID},
		}
	}
	// Create provinces for Pakistan
	var pakistanProvinces []models.Province
	if pakistanCountry.ID != "" {
		pakistanProvinces = []models.Province{
			{Name: "Islamabad", Code: "ISB", NumericCode: 1, IsActive: true, CountryID: pakistanCountry.ID},
			{Name: "Karachi", Code: "KAR", NumericCode: 2, IsActive: true, CountryID: pakistanCountry.ID},
			{Name: "Lahore", Code: "LAH", NumericCode: 3, IsActive: true, CountryID: pakistanCountry.ID},
			{Name: "Peshawar", Code: "PES", NumericCode: 4, IsActive: true, CountryID: pakistanCountry.ID},
			{Name: "Quetta", Code: "QTA", NumericCode: 5, IsActive: true, CountryID: pakistanCountry.ID},
		}
	}
	// Create provinces for Afghanistan
	var afghanistanProvinces []models.Province
	if afghanistanCountry.ID != "" {
		afghanistanProvinces = []models.Province{
			{Name: "Kabul", Code: "KAB", NumericCode: 1, IsActive: true, CountryID: afghanistanCountry.ID},
			{Name: "Herat", Code: "HER", NumericCode: 2, IsActive: true, CountryID: afghanistanCountry.ID},
			{Name: "Mazar-e-Sharif", Code: "MZR", NumericCode: 3, IsActive: true, CountryID: afghanistanCountry.ID},
			{Name: "Kandahar", Code: "KAN", NumericCode: 4, IsActive: true, CountryID: afghanistanCountry.ID},
			{Name: "Balkh", Code: "BAL", NumericCode: 5, IsActive: true, CountryID: afghanistanCountry.ID},
		}
	}
	// Create provinces for Bhutan
	var bhutanProvinces []models.Province
	if bhutanCountry.ID != "" {
		bhutanProvinces = []models.Province{
			{Name: "Thimphu", Code: "THI", NumericCode: 1, IsActive: true, CountryID: bhutanCountry.ID},
			{Name: "Paro", Code: "PAR", NumericCode: 2, IsActive: true, CountryID: bhutanCountry.ID},
			{Name: "Punakha", Code: "PUN", NumericCode: 3, IsActive: true, CountryID: bhutanCountry.ID},
			{Name: "Bhutan Dzong", Code: "BDO", NumericCode: 4, IsActive: true, CountryID: bhutanCountry.ID},
			{Name: "Trongsa", Code: "TRG", NumericCode: 5, IsActive: true, CountryID: bhutanCountry.ID},
		}
	}
	// Create provinces for Maldives
	var maldivesProvinces []models.Province
	if maldivesCountry.ID != "" {
		maldivesProvinces = []models.Province{
			{Name: "Male", Code: "MLE", NumericCode: 1, IsActive: true, CountryID: maldivesCountry.ID},
			{Name: "Hulhule", Code: "HLH", NumericCode: 2, IsActive: true, CountryID: maldivesCountry.ID},
			{Name: "Thoddoo", Code: "THD", NumericCode: 3, IsActive: true, CountryID: maldivesCountry.ID},
			{Name: "Fonadhoo", Code: "FON", NumericCode: 4, IsActive: true, CountryID: maldivesCountry.ID},
			{Name: "Gan", Code: "GAN", NumericCode: 5, IsActive: true, CountryID: maldivesCountry.ID},
		}
	}
	// Create provinces for Papua New Guinea
	var papuaNewGuineaProvinces []models.Province
	if papuaNewGuineaCountry.ID != "" {
		papuaNewGuineaProvinces = []models.Province{
			{Name: "Port Moresby", Code: "POM", NumericCode: 1, IsActive: true, CountryID: papuaNewGuineaCountry.ID},
			{Name: "Lae", Code: "LAE", NumericCode: 2, IsActive: true, CountryID: papuaNewGuineaCountry.ID},
			{Name: "Wewak", Code: "WEW", NumericCode: 3, IsActive: true, CountryID: papuaNewGuineaCountry.ID},
			{Name: "Madang", Code: "MAG", NumericCode: 4, IsActive: true, CountryID: papuaNewGuineaCountry.ID},
			{Name: "Mendi", Code: "MDI", NumericCode: 5, IsActive: true, CountryID: papuaNewGuineaCountry.ID},
		}
	}
	// Create provinces for Fiji
	var fijiProvinces []models.Province
	if fijiCountry.ID != "" {
		fijiProvinces = []models.Province{
			{Name: "Suva", Code: "SUV", NumericCode: 1, IsActive: true, CountryID: fijiCountry.ID},
			{Name: "Nadi", Code: "NAD", NumericCode: 2, IsActive: true, CountryID: fijiCountry.ID},
			{Name: "Lautoka", Code: "LAU", NumericCode: 3, IsActive: true, CountryID: fijiCountry.ID},
			{Name: "Nausori", Code: "NAU", NumericCode: 4, IsActive: true, CountryID: fijiCountry.ID},
			{Name: "Lami", Code: "LMI", NumericCode: 5, IsActive: true, CountryID: fijiCountry.ID},
		}
	}
	// Create provinces for Solomon Islands
	var solomonIslandsProvinces []models.Province
	if solomonIslandsCountry.ID != "" {
		solomonIslandsProvinces = []models.Province{
			{Name: "Honiara", Code: "HIR", NumericCode: 1, IsActive: true, CountryID: solomonIslandsCountry.ID},
			{Name: "Gizo", Code: "GZO", NumericCode: 2, IsActive: true, CountryID: solomonIslandsCountry.ID},
			{Name: "Munda", Code: "MUA", NumericCode: 3, IsActive: true, CountryID: solomonIslandsCountry.ID},
			{Name: "Lata", Code: "LTA", NumericCode: 4, IsActive: true, CountryID: solomonIslandsCountry.ID},
			{Name: "Tulagi", Code: "TUL", NumericCode: 5, IsActive: true, CountryID: solomonIslandsCountry.ID},
		}
	}
	// Create provinces for Samoa
	var samoaProvinces []models.Province
	if samoaCountry.ID != "" {
		samoaProvinces = []models.Province{
			{Name: "Apia", Code: "APIA", NumericCode: 1, IsActive: true, CountryID: samoaCountry.ID},
			{Name: "Faleasao", Code: "FALE", NumericCode: 2, IsActive: true, CountryID: samoaCountry.ID},
			{Name: "Leulumoega", Code: "LEU", NumericCode: 3, IsActive: true, CountryID: samoaCountry.ID},
			{Name: "Tuanaimato", Code: "TUA", NumericCode: 4, IsActive: true, CountryID: samoaCountry.ID},
			{Name: "Savai'i", Code: "SAV", NumericCode: 5, IsActive: true, CountryID: samoaCountry.ID},
		}
	}
	// Create provinces for Tonga
	var tongaProvinces []models.Province
	if tongaCountry.ID != "" {
		tongaProvinces = []models.Province{
			{Name: "Nuku'alofa", Code: "NUK", NumericCode: 1, IsActive: true, CountryID: tongaCountry.ID},
			{Name: "Vava'u", Code: "VAV", NumericCode: 2, IsActive: true, CountryID: tongaCountry.ID},
			{Name: "Ha'apai", Code: "HAA", NumericCode: 3, IsActive: true, CountryID: tongaCountry.ID},
			{Name: "Tongatapu", Code: "TGA", NumericCode: 4, IsActive: true, CountryID: tongaCountry.ID},
			{Name: "Kao", Code: "KAO", NumericCode: 5, IsActive: true, CountryID: tongaCountry.ID},
		}
	}
	// Create provinces for Vanuatu
	var vanuatuProvinces []models.Province
	if vanuatuCountry.ID != "" {
		vanuatuProvinces = []models.Province{
			{Name: "Port Vila", Code: "PRV", NumericCode: 1, IsActive: true, CountryID: vanuatuCountry.ID},
			{Name: "Lohuru", Code: "LOH", NumericCode: 2, IsActive: true, CountryID: vanuatuCountry.ID},
			{Name: "Sola", Code: "SOA", NumericCode: 3, IsActive: true, CountryID: vanuatuCountry.ID},
			{Name: "Tongoa", Code: "TGA", NumericCode: 4, IsActive: true, CountryID: vanuatuCountry.ID},
			{Name: "Efate", Code: "EFA", NumericCode: 5, IsActive: true, CountryID: vanuatuCountry.ID},
		}
	}
	// Create provinces for Micronesia
	var micronesiaProvinces []models.Province
	if micronesiaCountry.ID != "" {
		micronesiaProvinces = []models.Province{
			{Name: "Pohnpei", Code: "PNI", NumericCode: 1, IsActive: true, CountryID: micronesiaCountry.ID},
			{Name: "Yap", Code: "YAP", NumericCode: 2, IsActive: true, CountryID: micronesiaCountry.ID},
			{Name: "Kosrae", Code: "KSA", NumericCode: 3, IsActive: true, CountryID: micronesiaCountry.ID},
			{Name: "Chuuk", Code: "TUK", NumericCode: 4, IsActive: true, CountryID: micronesiaCountry.ID},
			{Name: "Pulap", Code: "PUL", NumericCode: 5, IsActive: true, CountryID: micronesiaCountry.ID},
		}
	}
	// Create provinces for Palau
	var palauProvinces []models.Province
	if palauCountry.ID != "" {
		palauProvinces = []models.Province{
			{Name: "Ngerulmud", Code: "NGE", NumericCode: 1, IsActive: true, CountryID: palauCountry.ID},
			{Name: "Melekeok", Code: "MEK", NumericCode: 2, IsActive: true, CountryID: palauCountry.ID},
			{Name: "Angaur", Code: "ANG", NumericCode: 3, IsActive: true, CountryID: palauCountry.ID},
			{Name: "Ngatpang", Code: "NGT", NumericCode: 4, IsActive: true, CountryID: palauCountry.ID},
			{Name: "Ngchesar", Code: "NCH", NumericCode: 5, IsActive: true, CountryID: palauCountry.ID},
		}
	}
	// Create provinces for Nauru
	var nauruProvinces []models.Province
	if nauruCountry.ID != "" {
		nauruProvinces = []models.Province{
			{Name: "Yaren", Code: "YAR", NumericCode: 1, IsActive: true, CountryID: nauruCountry.ID},
			{Name: "Baiti", Code: "BAI", NumericCode: 2, IsActive: true, CountryID: nauruCountry.ID},
			{Name: "Denigomodu", Code: "DEN", NumericCode: 3, IsActive: true, CountryID: nauruCountry.ID},
			{Name: "Uaboe", Code: "UAB", NumericCode: 4, IsActive: true, CountryID: nauruCountry.ID},
			{Name: "Anabar", Code: "ANA", NumericCode: 5, IsActive: true, CountryID: nauruCountry.ID},
		}
	}
	// Create provinces for Tuvalu
	var tuvaluProvinces []models.Province
	if tuvaluCountry.ID != "" {
		tuvaluProvinces = []models.Province{
			{Name: "Funafuti", Code: "FUN", NumericCode: 1, IsActive: true, CountryID: tuvaluCountry.ID},
			{Name: "Nukufetau", Code: "NUK", NumericCode: 2, IsActive: true, CountryID: tuvaluCountry.ID},
			{Name: "Nukulaelae", Code: "NUL", NumericCode: 3, IsActive: true, CountryID: tuvaluCountry.ID},
			{Name: "Nanumanga", Code: "NAN", NumericCode: 4, IsActive: true, CountryID: tuvaluCountry.ID},
			{Name: "Nanumea", Code: "NME", NumericCode: 5, IsActive: true, CountryID: tuvaluCountry.ID},
		}
	}
	// Create provinces for Marshall Islands
	var marshallIslandsProvinces []models.Province
	if marshallIslandsCountry.ID != "" {
		marshallIslandsProvinces = []models.Province{
			{Name: "Majuro", Code: "MAJ", NumericCode: 1, IsActive: true, CountryID: marshallIslandsCountry.ID},
			{Name: "Ebeye", Code: "EBE", NumericCode: 2, IsActive: true, CountryID: marshallIslandsCountry.ID},
			{Name: "Kwajalein", Code: "KWA", NumericCode: 3, IsActive: true, CountryID: marshallIslandsCountry.ID},
			{Name: "Rongelap", Code: "RON", NumericCode: 4, IsActive: true, CountryID: marshallIslandsCountry.ID},
			{Name: "Utrik", Code: "UTI", NumericCode: 5, IsActive: true, CountryID: marshallIslandsCountry.ID},
		}
	}
	// Create provinces for Kiribati
	var kiribatiProvinces []models.Province
	if kiribatiCountry.ID != "" {
		kiribatiProvinces = []models.Province{
			{Name: "Tarawa", Code: "TRW", NumericCode: 1, IsActive: true, CountryID: kiribatiCountry.ID},
			{Name: "Buariki", Code: "BRI", NumericCode: 2, IsActive: true, CountryID: kiribatiCountry.ID},
			{Name: "Kiritimati", Code: "KIR", NumericCode: 3, IsActive: true, CountryID: kiribatiCountry.ID},
			{Name: "Tabiteuea", Code: "TAB", NumericCode: 4, IsActive: true, CountryID: kiribatiCountry.ID},
			{Name: "Makin", Code: "MAK", NumericCode: 5, IsActive: true, CountryID: kiribatiCountry.ID},
		}
	}
	// Create provinces for France
	var franceProvinces []models.Province
	if franceCountry.ID != "" {
		franceProvinces = []models.Province{
			{Name: "Île-de-France", Code: "IDF", NumericCode: 1, IsActive: true, CountryID: franceCountry.ID},
			{Name: "Provence-Alpes-Côte d'Azur", Code: "PACA", NumericCode: 2, IsActive: true, CountryID: franceCountry.ID},
			{Name: "Nouvelle-Aquitaine", Code: "NAQ", NumericCode: 3, IsActive: true, CountryID: franceCountry.ID},
		}
	}
	// Create provinces for Germany
	var germanyProvinces []models.Province
	if germanyCountry.ID != "" {
		germanyProvinces = []models.Province{
			{Name: "Bavaria", Code: "BY", NumericCode: 1, IsActive: true, CountryID: germanyCountry.ID},
			{Name: "North Rhine-Westphalia", Code: "NW", NumericCode: 2, IsActive: true, CountryID: germanyCountry.ID},
			{Name: "Baden-Württemberg", Code: "BW", NumericCode: 3, IsActive: true, CountryID: germanyCountry.ID},
		}
	}
	// Create provinces for United Kingdom
	var ukProvinces []models.Province
	if ukCountry.ID != "" {
		ukProvinces = []models.Province{
			{Name: "England", Code: "ENG", NumericCode: 1, IsActive: true, CountryID: ukCountry.ID},
			{Name: "Scotland", Code: "SCT", NumericCode: 2, IsActive: true, CountryID: ukCountry.ID},
			{Name: "Wales", Code: "WLS", NumericCode: 3, IsActive: true, CountryID: ukCountry.ID},
			{Name: "Northern Ireland", Code: "NIR", NumericCode: 4, IsActive: true, CountryID: ukCountry.ID},
		}
	}

	// Create provinces for United States
	var usProvinces []models.Province
	if usCountry.ID != "" {
		usProvinces = []models.Province{
			{Name: "California", Code: "CA", NumericCode: 1, IsActive: true, CountryID: usCountry.ID},
			{Name: "Texas", Code: "TX", NumericCode: 2, IsActive: true, CountryID: usCountry.ID},
			{Name: "Florida", Code: "FL", NumericCode: 3, IsActive: true, CountryID: usCountry.ID},
			{Name: "New York", Code: "NY", NumericCode: 4, IsActive: true, CountryID: usCountry.ID},
			{Name: "Illinois", Code: "IL", NumericCode: 5, IsActive: true, CountryID: usCountry.ID},
			{Name: "Pennsylvania", Code: "PA", NumericCode: 6, IsActive: true, CountryID: usCountry.ID},
			{Name: "Ohio", Code: "OH", NumericCode: 7, IsActive: true, CountryID: usCountry.ID},
			{Name: "Georgia", Code: "GA", NumericCode: 8, IsActive: true, CountryID: usCountry.ID},
			{Name: "North Carolina", Code: "NC", NumericCode: 9, IsActive: true, CountryID: usCountry.ID},
			{Name: "Michigan", Code: "MI", NumericCode: 10, IsActive: true, CountryID: usCountry.ID},
		}
	}

	// Create provinces for Canada
	var canadaProvinces []models.Province
	if canadaCountry.ID != "" {
		canadaProvinces = []models.Province{
			{Name: "Ontario", Code: "ON", NumericCode: 1, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Quebec", Code: "QC", NumericCode: 2, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "British Columbia", Code: "BC", NumericCode: 3, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Alberta", Code: "AB", NumericCode: 4, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Manitoba", Code: "MB", NumericCode: 5, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Saskatchewan", Code: "SK", NumericCode: 6, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Nova Scotia", Code: "NS", NumericCode: 7, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "New Brunswick", Code: "NB", NumericCode: 8, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Newfoundland and Labrador", Code: "NL", NumericCode: 9, IsActive: true, CountryID: canadaCountry.ID},
			{Name: "Prince Edward Island", Code: "PE", NumericCode: 10, IsActive: true, CountryID: canadaCountry.ID},
		}
	}

	// Create provinces for Japan
	var japanProvinces []models.Province
	if japanCountry.ID != "" {
		japanProvinces = []models.Province{
			// Hokkaido Region
			{Name: "Hokkaido", Code: "HKD", NumericCode: 1, IsActive: true, CountryID: japanCountry.ID},

			// Tohoku Region
			{Name: "Aomori", Code: "AOM", NumericCode: 2, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Iwate", Code: "IWA", NumericCode: 3, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Miyagi", Code: "MIY", NumericCode: 4, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Akita", Code: "AKI", NumericCode: 5, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Yamagata", Code: "YAM", NumericCode: 6, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Fukushima", Code: "FUK", NumericCode: 7, IsActive: true, CountryID: japanCountry.ID},

			// Kanto Region
			{Name: "Ibaraki", Code: "IBA", NumericCode: 8, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Tochigi", Code: "TOC", NumericCode: 9, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Gunma", Code: "GUN", NumericCode: 10, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Saitama", Code: "SAI", NumericCode: 11, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Chiba", Code: "CHI", NumericCode: 12, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Tokyo", Code: "TOK", NumericCode: 13, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kanagawa", Code: "KAN", NumericCode: 14, IsActive: true, CountryID: japanCountry.ID},

			// Chubu Region
			{Name: "Niigata", Code: "NII", NumericCode: 15, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Toyama", Code: "TOY", NumericCode: 16, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Ishikawa", Code: "ISH", NumericCode: 17, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Fukui", Code: "FUK", NumericCode: 18, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Yamanashi", Code: "YAM", NumericCode: 19, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Nagano", Code: "NAG", NumericCode: 20, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Gifu", Code: "GIF", NumericCode: 21, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Shizuoka", Code: "SHI", NumericCode: 22, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Aichi", Code: "AIC", NumericCode: 23, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Mie", Code: "MIE", NumericCode: 24, IsActive: true, CountryID: japanCountry.ID},

			// Kansai Region
			{Name: "Shiga", Code: "SHI", NumericCode: 25, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kyoto", Code: "KYO", NumericCode: 26, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Osaka", Code: "OSA", NumericCode: 27, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Hyogo", Code: "HYO", NumericCode: 28, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Nara", Code: "NAR", NumericCode: 29, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Wakayama", Code: "WAK", NumericCode: 30, IsActive: true, CountryID: japanCountry.ID},

			// Chugoku Region
			{Name: "Tottori", Code: "TOT", NumericCode: 31, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Shimane", Code: "SHI", NumericCode: 32, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Okayama", Code: "OKA", NumericCode: 33, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Hiroshima", Code: "HIR", NumericCode: 34, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Yamaguchi", Code: "YAM", NumericCode: 35, IsActive: true, CountryID: japanCountry.ID},

			// Shikoku Region
			{Name: "Tokushima", Code: "TOK", NumericCode: 36, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kagawa", Code: "KAG", NumericCode: 37, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Ehime", Code: "EHI", NumericCode: 38, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kochi", Code: "KOC", NumericCode: 39, IsActive: true, CountryID: japanCountry.ID},

			// Kyushu Region
			{Name: "Fukuoka", Code: "FUK", NumericCode: 40, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Saga", Code: "SAG", NumericCode: 41, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Nagasaki", Code: "NAG", NumericCode: 42, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kumamoto", Code: "KUM", NumericCode: 43, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Oita", Code: "OIT", NumericCode: 44, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Miyazaki", Code: "MIY", NumericCode: 45, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Kagoshima", Code: "KAG", NumericCode: 46, IsActive: true, CountryID: japanCountry.ID},
			{Name: "Okinawa", Code: "OKI", NumericCode: 47, IsActive: true, CountryID: japanCountry.ID},
		}
	}

	// Create provinces for Australia
	var australiaProvinces []models.Province
	if australiaCountry.ID != "" {
		australiaProvinces = []models.Province{
			{Name: "New South Wales", Code: "NSW", NumericCode: 1, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Victoria", Code: "VIC", NumericCode: 2, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Queensland", Code: "QLD", NumericCode: 3, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Western Australia", Code: "WA", NumericCode: 4, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "South Australia", Code: "SA", NumericCode: 5, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Tasmania", Code: "TAS", NumericCode: 6, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Australian Capital Territory", Code: "ACT", NumericCode: 7, IsActive: true, CountryID: australiaCountry.ID},
			{Name: "Northern Territory", Code: "NT", NumericCode: 8, IsActive: true, CountryID: australiaCountry.ID},
		}
	}

	// Create provinces for Brazil
	var brazilProvinces []models.Province
	if brazilCountry.ID != "" {
		brazilProvinces = []models.Province{
			{Name: "São Paulo", Code: "SP", NumericCode: 1, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Minas Gerais", Code: "MG", NumericCode: 2, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Rio de Janeiro", Code: "RJ", NumericCode: 3, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Bahia", Code: "BA", NumericCode: 4, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Paraná", Code: "PR", NumericCode: 5, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Rio Grande do Sul", Code: "RS", NumericCode: 6, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Pernambuco", Code: "PE", NumericCode: 7, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Ceará", Code: "CE", NumericCode: 8, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Pará", Code: "PA", NumericCode: 9, IsActive: true, CountryID: brazilCountry.ID},
			{Name: "Santa Catarina", Code: "SC", NumericCode: 10, IsActive: true, CountryID: brazilCountry.ID},
		}
	}

	// Create provinces for India
	var indiaProvinces []models.Province
	if indiaCountry.ID != "" {
		indiaProvinces = []models.Province{
			// Northern India
			{Name: "Jammu and Kashmir", Code: "JK", NumericCode: 1, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Himachal Pradesh", Code: "HP", NumericCode: 2, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Punjab", Code: "PB", NumericCode: 3, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Chandigarh", Code: "CH", NumericCode: 4, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Uttarakhand", Code: "UK", NumericCode: 5, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Haryana", Code: "HR", NumericCode: 6, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Delhi", Code: "DL", NumericCode: 7, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Rajasthan", Code: "RJ", NumericCode: 8, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Uttar Pradesh", Code: "UP", NumericCode: 9, IsActive: true, CountryID: indiaCountry.ID},

			// Central India
			{Name: "Madhya Pradesh", Code: "MP", NumericCode: 10, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Chhattisgarh", Code: "CT", NumericCode: 11, IsActive: true, CountryID: indiaCountry.ID},

			// Western India
			{Name: "Gujarat", Code: "GJ", NumericCode: 12, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Maharashtra", Code: "MH", NumericCode: 13, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Goa", Code: "GA", NumericCode: 14, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Dadra and Nagar Haveli", Code: "DN", NumericCode: 15, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Daman and Diu", Code: "DD", NumericCode: 16, IsActive: true, CountryID: indiaCountry.ID},

			// Eastern India
			{Name: "Bihar", Code: "BR", NumericCode: 17, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Jharkhand", Code: "JH", NumericCode: 18, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Odisha", Code: "OR", NumericCode: 19, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "West Bengal", Code: "WB", NumericCode: 20, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Sikkim", Code: "SK", NumericCode: 21, IsActive: true, CountryID: indiaCountry.ID},

			// Southern India
			{Name: "Andhra Pradesh", Code: "AP", NumericCode: 22, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Telangana", Code: "TG", NumericCode: 23, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Karnataka", Code: "KA", NumericCode: 24, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Tamil Nadu", Code: "TN", NumericCode: 25, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Kerala", Code: "KL", NumericCode: 26, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Puducherry", Code: "PY", NumericCode: 27, IsActive: true, CountryID: indiaCountry.ID},

			// Northeastern India
			{Name: "Arunachal Pradesh", Code: "AR", NumericCode: 28, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Assam", Code: "AS", NumericCode: 29, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Manipur", Code: "MN", NumericCode: 30, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Meghalaya", Code: "ML", NumericCode: 31, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Mizoram", Code: "MZ", NumericCode: 32, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Nagaland", Code: "NL", NumericCode: 33, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Tripura", Code: "TR", NumericCode: 34, IsActive: true, CountryID: indiaCountry.ID},

			// Island Territories
			{Name: "Andaman and Nicobar Islands", Code: "AN", NumericCode: 35, IsActive: true, CountryID: indiaCountry.ID},
			{Name: "Lakshadweep", Code: "LD", NumericCode: 36, IsActive: true, CountryID: indiaCountry.ID},
		}
	}

	// Create provinces for China
	var chinaProvinces []models.Province
	if chinaCountry.ID != "" {
		chinaProvinces = []models.Province{
			// Municipalities
			{Name: "Beijing", Code: "BJ", NumericCode: 1, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Shanghai", Code: "SH", NumericCode: 2, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Tianjin", Code: "TJ", NumericCode: 3, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Chongqing", Code: "CQ", NumericCode: 4, IsActive: true, CountryID: chinaCountry.ID},

			// Provinces
			{Name: "Hebei", Code: "HE", NumericCode: 5, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Shanxi", Code: "SX", NumericCode: 6, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Liaoning", Code: "LN", NumericCode: 7, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Jilin", Code: "JL", NumericCode: 8, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Heilongjiang", Code: "HL", NumericCode: 9, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Jiangsu", Code: "JS", NumericCode: 10, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Zhejiang", Code: "ZJ", NumericCode: 11, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Anhui", Code: "AH", NumericCode: 12, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Fujian", Code: "FJ", NumericCode: 13, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Jiangxi", Code: "JX", NumericCode: 14, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Shandong", Code: "SD", NumericCode: 15, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Henan", Code: "HA", NumericCode: 16, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Hubei", Code: "HB", NumericCode: 17, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Hunan", Code: "HN", NumericCode: 18, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Guangdong", Code: "GD", NumericCode: 19, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Guangxi", Code: "GX", NumericCode: 20, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Hainan", Code: "HI", NumericCode: 21, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Sichuan", Code: "SC", NumericCode: 22, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Guizhou", Code: "GZ", NumericCode: 23, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Yunnan", Code: "YN", NumericCode: 24, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Tibet", Code: "XZ", NumericCode: 25, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Shaanxi", Code: "SN", NumericCode: 26, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Gansu", Code: "GS", NumericCode: 27, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Qinghai", Code: "QH", NumericCode: 28, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Ningxia", Code: "NX", NumericCode: 29, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Xinjiang", Code: "XJ", NumericCode: 30, IsActive: true, CountryID: chinaCountry.ID},

			// Special Administrative Regions
			{Name: "Hong Kong", Code: "HK", NumericCode: 31, IsActive: true, CountryID: chinaCountry.ID},
			{Name: "Macau", Code: "MO", NumericCode: 32, IsActive: true, CountryID: chinaCountry.ID},
		}
	}

	// Create provinces for Indonesia
	var indonesiaProvinces []models.Province
	if indonesiaCountry.ID != "" {
		indonesiaProvinces = []models.Province{
			// Java Island
			{Name: "Jakarta Special Capital Region", Code: "JK", NumericCode: 1, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "West Java", Code: "JB", NumericCode: 2, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Central Java", Code: "JT", NumericCode: 3, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "East Java", Code: "JI", NumericCode: 4, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Banten", Code: "BT", NumericCode: 5, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Yogyakarta Special Region", Code: "YO", NumericCode: 6, IsActive: true, CountryID: indonesiaCountry.ID},

			// Sumatra Island
			{Name: "Aceh", Code: "AC", NumericCode: 7, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "North Sumatra", Code: "SU", NumericCode: 8, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "West Sumatra", Code: "SB", NumericCode: 9, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Riau", Code: "RI", NumericCode: 10, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Riau Islands", Code: "KR", NumericCode: 11, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Jambi", Code: "JA", NumericCode: 12, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "South Sumatra", Code: "SS", NumericCode: 13, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Bengkulu", Code: "BE", NumericCode: 14, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Lampung", Code: "LA", NumericCode: 15, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Bangka Belitung Islands", Code: "BB", NumericCode: 16, IsActive: true, CountryID: indonesiaCountry.ID},

			// Kalimantan Island
			{Name: "West Kalimantan", Code: "KB", NumericCode: 17, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Central Kalimantan", Code: "KT", NumericCode: 18, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "South Kalimantan", Code: "KS", NumericCode: 19, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "East Kalimantan", Code: "KI", NumericCode: 20, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "North Kalimantan", Code: "KU", NumericCode: 21, IsActive: true, CountryID: indonesiaCountry.ID},

			// Sulawesi Island
			{Name: "North Sulawesi", Code: "SA", NumericCode: 22, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Gorontalo", Code: "GO", NumericCode: 23, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Central Sulawesi", Code: "ST", NumericCode: 24, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "West Sulawesi", Code: "SR", NumericCode: 25, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "South Sulawesi", Code: "SN", NumericCode: 26, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "Southeast Sulawesi", Code: "SG", NumericCode: 27, IsActive: true, CountryID: indonesiaCountry.ID},

			// Maluku Islands
			{Name: "Maluku", Code: "MA", NumericCode: 28, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "North Maluku", Code: "MU", NumericCode: 29, IsActive: true, CountryID: indonesiaCountry.ID},

			// Papua Island
			{Name: "Papua", Code: "PA", NumericCode: 30, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "West Papua", Code: "PB", NumericCode: 31, IsActive: true, CountryID: indonesiaCountry.ID},

			// Lesser Sunda Islands
			{Name: "Bali", Code: "BA", NumericCode: 32, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "West Nusa Tenggara", Code: "NB", NumericCode: 33, IsActive: true, CountryID: indonesiaCountry.ID},
			{Name: "East Nusa Tenggara", Code: "NT", NumericCode: 34, IsActive: true, CountryID: indonesiaCountry.ID},
		}
	}

	// Create provinces for Singapore
	var singaporeProvinces []models.Province
	if singaporeCountry.ID != "" {
		singaporeProvinces = []models.Province{
			{Name: "Central Region", Code: "CR", NumericCode: 1, IsActive: true, CountryID: singaporeCountry.ID},
			{Name: "East Region", Code: "ER", NumericCode: 2, IsActive: true, CountryID: singaporeCountry.ID},
			{Name: "North Region", Code: "NR", NumericCode: 3, IsActive: true, CountryID: singaporeCountry.ID},
			{Name: "North-East Region", Code: "NER", NumericCode: 4, IsActive: true, CountryID: singaporeCountry.ID},
			{Name: "West Region", Code: "WR", NumericCode: 5, IsActive: true, CountryID: singaporeCountry.ID},
		}
	}

	// Create provinces for Malaysia
	var malaysiaProvinces []models.Province
	if malaysiaCountry.ID != "" {
		malaysiaProvinces = []models.Province{
			// Peninsular Malaysia
			{Name: "Johor", Code: "JHR", NumericCode: 1, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Kedah", Code: "KDH", NumericCode: 2, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Kelantan", Code: "KTN", NumericCode: 3, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Melaka", Code: "MLK", NumericCode: 4, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Negeri Sembilan", Code: "NSL", NumericCode: 5, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Pahang", Code: "PHG", NumericCode: 6, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Perak", Code: "PRK", NumericCode: 7, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Perlis", Code: "PLS", NumericCode: 8, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Pulau Pinang", Code: "PNG", NumericCode: 9, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Selangor", Code: "SGR", NumericCode: 10, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Terengganu", Code: "TRG", NumericCode: 11, IsActive: true, CountryID: malaysiaCountry.ID},

			// Federal Territories
			{Name: "Kuala Lumpur", Code: "KUL", NumericCode: 12, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Labuan", Code: "LBN", NumericCode: 13, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Putrajaya", Code: "PJY", NumericCode: 14, IsActive: true, CountryID: malaysiaCountry.ID},

			// East Malaysia
			{Name: "Sabah", Code: "SBH", NumericCode: 15, IsActive: true, CountryID: malaysiaCountry.ID},
			{Name: "Sarawak", Code: "SWK", NumericCode: 16, IsActive: true, CountryID: malaysiaCountry.ID},
		}
	}

	// Create provinces for Philippines
	var philippinesProvinces []models.Province
	if philippinesCountry.ID != "" {
		philippinesProvinces = []models.Province{
			// Luzon
			{Name: "Metro Manila", Code: "MM", NumericCode: 1, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Ilocos Region", Code: "ILO", NumericCode: 2, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Cagayan Valley", Code: "CV", NumericCode: 3, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Central Luzon", Code: "CL", NumericCode: 4, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Calabarzon", Code: "CAL", NumericCode: 5, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Mimaropa", Code: "MIM", NumericCode: 6, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Bicol", Code: "BIC", NumericCode: 7, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Cordillera Administrative Region", Code: "CAR", NumericCode: 8, IsActive: true, CountryID: philippinesCountry.ID},

			// Visayas
			{Name: "Western Visayas", Code: "WV", NumericCode: 9, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Central Visayas", Code: "CVS", NumericCode: 10, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Eastern Visayas", Code: "EV", NumericCode: 11, IsActive: true, CountryID: philippinesCountry.ID},

			// Mindanao
			{Name: "Zamboanga Peninsula", Code: "ZAM", NumericCode: 12, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Northern Mindanao", Code: "NOM", NumericCode: 13, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Davao", Code: "DAV", NumericCode: 14, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Soccsksargen", Code: "SOC", NumericCode: 15, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Caraga", Code: "CAR", NumericCode: 16, IsActive: true, CountryID: philippinesCountry.ID},
			{Name: "Bangsamoro", Code: "BAR", NumericCode: 17, IsActive: true, CountryID: philippinesCountry.ID},
		}
	}

	// Create provinces for Thailand
	var thailandProvinces []models.Province
	if thailandCountry.ID != "" {
		thailandProvinces = []models.Province{
			// Central Thailand
			{Name: "Bangkok", Code: "BKK", NumericCode: 1, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nonthaburi", Code: "NON", NumericCode: 2, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Pathum Thani", Code: "PTT", NumericCode: 3, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Samut Prakan", Code: "SPK", NumericCode: 4, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Samut Sakhon", Code: "SSK", NumericCode: 5, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nakhon Pathom", Code: "NPT", NumericCode: 6, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Chonburi", Code: "CBR", NumericCode: 7, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Rayong", Code: "RYG", NumericCode: 8, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Chanthaburi", Code: "CTB", NumericCode: 9, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Trat", Code: "TRT", NumericCode: 10, IsActive: true, CountryID: thailandCountry.ID},

			// Northern Thailand
			{Name: "Chiang Mai", Code: "CMI", NumericCode: 11, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Chiang Rai", Code: "CRI", NumericCode: 12, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Lampang", Code: "LPG", NumericCode: 13, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Lamphun", Code: "LPH", NumericCode: 14, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Mae Hong Son", Code: "MHS", NumericCode: 15, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nan", Code: "NAN", NumericCode: 16, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Phayao", Code: "PYO", NumericCode: 17, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Phrae", Code: "PRE", NumericCode: 18, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Uttaradit", Code: "UTT", NumericCode: 19, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Tak", Code: "TAK", NumericCode: 20, IsActive: true, CountryID: thailandCountry.ID},

			// Northeastern Thailand
			{Name: "Nakhon Ratchasima", Code: "NKR", NumericCode: 21, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Khon Kaen", Code: "KKN", NumericCode: 22, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Udon Thani", Code: "UDT", NumericCode: 23, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Ubon Ratchathani", Code: "UBR", NumericCode: 24, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nakhon Phanom", Code: "NPM", NumericCode: 25, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Sakon Nakhon", Code: "SNK", NumericCode: 26, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nong Khai", Code: "NKI", NumericCode: 27, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Loei", Code: "LOE", NumericCode: 28, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Nong Bua Lamphu", Code: "NBL", NumericCode: 29, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Bueng Kan", Code: "BKN", NumericCode: 30, IsActive: true, CountryID: thailandCountry.ID},

			// Southern Thailand
			{Name: "Nakhon Si Thammarat", Code: "NST", NumericCode: 31, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Songkhla", Code: "SGL", NumericCode: 32, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Surat Thani", Code: "SRT", NumericCode: 33, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Phuket", Code: "PHK", NumericCode: 34, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Krabi", Code: "KBI", NumericCode: 35, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Phang Nga", Code: "PNG", NumericCode: 36, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Ranong", Code: "RNG", NumericCode: 37, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Chumphon", Code: "CPN", NumericCode: 38, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Pattani", Code: "PTN", NumericCode: 39, IsActive: true, CountryID: thailandCountry.ID},
			{Name: "Yala", Code: "YLA", NumericCode: 40, IsActive: true, CountryID: thailandCountry.ID},
		}
	}

	// Create provinces for Vietnam
	var vietnamProvinces []models.Province
	if vietnamCountry.ID != "" {
		vietnamProvinces = []models.Province{
			// Municipalities
			{Name: "Ho Chi Minh City", Code: "HCM", NumericCode: 1, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hanoi", Code: "HAN", NumericCode: 2, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Da Nang", Code: "DNG", NumericCode: 3, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Can Tho", Code: "CTH", NumericCode: 4, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hai Phong", Code: "HPH", NumericCode: 5, IsActive: true, CountryID: vietnamCountry.ID},

			// Northern Vietnam
			{Name: "Ha Giang", Code: "HAG", NumericCode: 6, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Cao Bang", Code: "CAB", NumericCode: 7, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Lao Cai", Code: "LCA", NumericCode: 8, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Tuyen Quang", Code: "TUQ", NumericCode: 9, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Lang Son", Code: "LAS", NumericCode: 10, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Bac Kan", Code: "BAK", NumericCode: 11, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Thai Nguyen", Code: "THN", NumericCode: 12, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Yen Bai", Code: "YEB", NumericCode: 13, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Son La", Code: "SOL", NumericCode: 14, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Phu Tho", Code: "PHT", NumericCode: 15, IsActive: true, CountryID: vietnamCountry.ID},

			// Red River Delta
			{Name: "Vinh Phuc", Code: "VIP", NumericCode: 16, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Bac Ninh", Code: "BAN", NumericCode: 17, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Quang Ninh", Code: "QUN", NumericCode: 18, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hai Duong", Code: "HAD", NumericCode: 19, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hung Yen", Code: "HUY", NumericCode: 20, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hoa Binh", Code: "HOB", NumericCode: 21, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ha Nam", Code: "HAN", NumericCode: 22, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Nam Dinh", Code: "NAD", NumericCode: 23, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Thai Binh", Code: "THB", NumericCode: 24, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ninh Binh", Code: "NIB", NumericCode: 25, IsActive: true, CountryID: vietnamCountry.ID},

			// Central Vietnam
			{Name: "Thanh Hoa", Code: "THH", NumericCode: 26, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Nghe An", Code: "NGA", NumericCode: 27, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ha Tinh", Code: "HAT", NumericCode: 28, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Quang Binh", Code: "QUB", NumericCode: 29, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Quang Tri", Code: "QUT", NumericCode: 30, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Thua Thien Hue", Code: "TTH", NumericCode: 31, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Quang Nam", Code: "QUA", NumericCode: 32, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Quang Ngai", Code: "QUN", NumericCode: 33, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Binh Dinh", Code: "BID", NumericCode: 34, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Phu Yen", Code: "PHY", NumericCode: 35, IsActive: true, CountryID: vietnamCountry.ID},

			// Central Highlands
			{Name: "Kon Tum", Code: "KOT", NumericCode: 36, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Gia Lai", Code: "GIL", NumericCode: 37, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Dak Lak", Code: "DAL", NumericCode: 38, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Dak Nong", Code: "DAN", NumericCode: 39, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Lam Dong", Code: "LAD", NumericCode: 40, IsActive: true, CountryID: vietnamCountry.ID},

			// Southeast Vietnam
			{Name: "Dong Nai", Code: "DON", NumericCode: 41, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Binh Duong", Code: "BID", NumericCode: 42, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Binh Phuoc", Code: "BIP", NumericCode: 43, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Tay Ninh", Code: "TAY", NumericCode: 44, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Binh Thuan", Code: "BIT", NumericCode: 45, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ninh Thuan", Code: "NIT", NumericCode: 46, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ba Ria - Vung Tau", Code: "BRV", NumericCode: 47, IsActive: true, CountryID: vietnamCountry.ID},

			// Mekong Delta
			{Name: "Long An", Code: "LOA", NumericCode: 48, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Tien Giang", Code: "TIG", NumericCode: 49, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ben Tre", Code: "BET", NumericCode: 50, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Tra Vinh", Code: "TRV", NumericCode: 51, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Vinh Long", Code: "VIL", NumericCode: 52, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Dong Thap", Code: "DOT", NumericCode: 53, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "An Giang", Code: "ANG", NumericCode: 54, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Kien Giang", Code: "KIG", NumericCode: 55, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Ca Mau", Code: "CAM", NumericCode: 56, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Bac Lieu", Code: "BAL", NumericCode: 57, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Soc Trang", Code: "SOT", NumericCode: 58, IsActive: true, CountryID: vietnamCountry.ID},
			{Name: "Hau Giang", Code: "HAG", NumericCode: 59, IsActive: true, CountryID: vietnamCountry.ID},
		}
	}

	// Create provinces for South Korea
	var southKoreaProvinces []models.Province
	if southKoreaCountry.ID != "" {
		southKoreaProvinces = []models.Province{
			// Metropolitan Cities
			{Name: "Seoul", Code: "SEL", NumericCode: 1, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Busan", Code: "BUS", NumericCode: 2, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Incheon", Code: "INC", NumericCode: 3, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Daegu", Code: "DGU", NumericCode: 4, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Daejeon", Code: "DJN", NumericCode: 5, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Gwangju", Code: "GWJ", NumericCode: 6, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Ulsan", Code: "ULS", NumericCode: 7, IsActive: true, CountryID: southKoreaCountry.ID},

			// Provinces
			{Name: "Gyeonggi", Code: "GG", NumericCode: 8, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Gangwon", Code: "GW", NumericCode: 9, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "North Chungcheong", Code: "CB", NumericCode: 10, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "South Chungcheong", Code: "CN", NumericCode: 11, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "North Jeolla", Code: "JB", NumericCode: 12, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "South Jeolla", Code: "JN", NumericCode: 13, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "North Gyeongsang", Code: "GB", NumericCode: 14, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "South Gyeongsang", Code: "GN", NumericCode: 15, IsActive: true, CountryID: southKoreaCountry.ID},
			{Name: "Jeju", Code: "JJ", NumericCode: 16, IsActive: true, CountryID: southKoreaCountry.ID},
		}
	}

	// Create provinces for Russia
	var russiaProvinces []models.Province
	if russiaCountry.ID != "" {
		russiaProvinces = []models.Province{
			{Name: "Moscow", Code: "MOW", NumericCode: 1, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Saint Petersburg", Code: "SPB", NumericCode: 2, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Novosibirsk", Code: "NVS", NumericCode: 3, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Yekaterinburg", Code: "SVE", NumericCode: 4, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Kazan", Code: "TA", NumericCode: 5, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Nizhny Novgorod", Code: "NIZ", NumericCode: 6, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Chelyabinsk", Code: "CHE", NumericCode: 7, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Samara", Code: "SAM", NumericCode: 8, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Omsk", Code: "OMS", NumericCode: 9, IsActive: true, CountryID: russiaCountry.ID},
			{Name: "Rostov", Code: "ROS", NumericCode: 10, IsActive: true, CountryID: russiaCountry.ID},
		}
	}

	// Create provinces for Mexico
	var mexicoProvinces []models.Province
	if mexicoCountry.ID != "" {
		mexicoProvinces = []models.Province{
			{Name: "Mexico City", Code: "CDMX", NumericCode: 1, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Jalisco", Code: "JAL", NumericCode: 2, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Veracruz", Code: "VER", NumericCode: 3, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Puebla", Code: "PUE", NumericCode: 4, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Guanajuato", Code: "GUA", NumericCode: 5, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Nuevo León", Code: "NLE", NumericCode: 6, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Michoacán", Code: "MIC", NumericCode: 7, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Chiapas", Code: "CHP", NumericCode: 8, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Oaxaca", Code: "OAX", NumericCode: 9, IsActive: true, CountryID: mexicoCountry.ID},
			{Name: "Chihuahua", Code: "CHH", NumericCode: 10, IsActive: true, CountryID: mexicoCountry.ID},
		}
	}

	// Create provinces for New Zealand
	var newZealandProvinces []models.Province
	if newZealandCountry.ID != "" {
		newZealandProvinces = []models.Province{
			{Name: "Auckland", Code: "AUK", NumericCode: 1, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Wellington", Code: "WGN", NumericCode: 2, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Canterbury", Code: "CAN", NumericCode: 3, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Waikato", Code: "WKO", NumericCode: 4, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Bay of Plenty", Code: "BOP", NumericCode: 5, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Manawatu-Wanganui", Code: "MWT", NumericCode: 6, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Otago", Code: "OTA", NumericCode: 7, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Hawke's Bay", Code: "HKB", NumericCode: 8, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Taranaki", Code: "TKI", NumericCode: 9, IsActive: true, CountryID: newZealandCountry.ID},
			{Name: "Northland", Code: "NTL", NumericCode: 10, IsActive: true, CountryID: newZealandCountry.ID},
		}
	}

	// Create provinces for Brunei
	var bruneiProvinces []models.Province
	if bruneiCountry.ID != "" {
		bruneiProvinces = []models.Province{
			{Name: "Brunei-Muara", Code: "BM", NumericCode: 1, IsActive: true, CountryID: bruneiCountry.ID},
			{Name: "Belait", Code: "BL", NumericCode: 2, IsActive: true, CountryID: bruneiCountry.ID},
			{Name: "Tutong", Code: "TU", NumericCode: 3, IsActive: true, CountryID: bruneiCountry.ID},
			{Name: "Temburong", Code: "TE", NumericCode: 4, IsActive: true, CountryID: bruneiCountry.ID},
		}
	}

	// Create provinces for Cambodia
	var cambodiaProvinces []models.Province
	if cambodiaCountry.ID != "" {
		cambodiaProvinces = []models.Province{
			{Name: "Phnom Penh", Code: "PP", NumericCode: 1, IsActive: true, CountryID: cambodiaCountry.ID},
			{Name: "Battambang", Code: "BTB", NumericCode: 2, IsActive: true, CountryID: cambodiaCountry.ID},
			{Name: "Siem Reap", Code: "SRP", NumericCode: 3, IsActive: true, CountryID: cambodiaCountry.ID},
			{Name: "Kampong Cham", Code: "KPC", NumericCode: 4, IsActive: true, CountryID: cambodiaCountry.ID},
			{Name: "Prey Veng", Code: "PVG", NumericCode: 5, IsActive: true, CountryID: cambodiaCountry.ID},
		}
	}

	// Create provinces for Laos
	var laosProvinces []models.Province
	if laosCountry.ID != "" {
		laosProvinces = []models.Province{
			{Name: "Vientiane", Code: "VTN", NumericCode: 1, IsActive: true, CountryID: laosCountry.ID},
			{Name: "Savannakhet", Code: "SVK", NumericCode: 2, IsActive: true, CountryID: laosCountry.ID},
			{Name: "Luang Prabang", Code: "LPB", NumericCode: 3, IsActive: true, CountryID: laosCountry.ID},
			{Name: "Champasak", Code: "CPS", NumericCode: 4, IsActive: true, CountryID: laosCountry.ID},
			{Name: "Oudomxay", Code: "ODX", NumericCode: 5, IsActive: true, CountryID: laosCountry.ID},
		}
	}

	// Create provinces for Myanmar
	var myanmarProvinces []models.Province
	if myanmarCountry.ID != "" {
		myanmarProvinces = []models.Province{
			{Name: "Yangon", Code: "YGN", NumericCode: 1, IsActive: true, CountryID: myanmarCountry.ID},
			{Name: "Mandalay", Code: "MDY", NumericCode: 2, IsActive: true, CountryID: myanmarCountry.ID},
			{Name: "Sagaing", Code: "SGG", NumericCode: 3, IsActive: true, CountryID: myanmarCountry.ID},
			{Name: "Bago", Code: "BGO", NumericCode: 4, IsActive: true, CountryID: myanmarCountry.ID},
			{Name: "Magway", Code: "MGW", NumericCode: 5, IsActive: true, CountryID: myanmarCountry.ID},
		}
	}

	// Create provinces for Timor-Leste
	var timorLesteProvinces []models.Province
	if timorLesteCountry.ID != "" {
		timorLesteProvinces = []models.Province{
			{Name: "Dili", Code: "DIL", NumericCode: 1, IsActive: true, CountryID: timorLesteCountry.ID},
			{Name: "Baucau", Code: "BAU", NumericCode: 2, IsActive: true, CountryID: timorLesteCountry.ID},
			{Name: "Lautem", Code: "LAU", NumericCode: 3, IsActive: true, CountryID: timorLesteCountry.ID},
			{Name: "Bobonaro", Code: "BOB", NumericCode: 4, IsActive: true, CountryID: timorLesteCountry.ID},
			{Name: "Ermera", Code: "ERM", NumericCode: 5, IsActive: true, CountryID: timorLesteCountry.ID},
		}
	}

	// Create provinces for Ukraine
	var ukraineProvinces []models.Province
	if ukraineCountry.ID != "" {
		ukraineProvinces = []models.Province{
			{Name: "Kyiv", Code: "KIV", NumericCode: 1, IsActive: true, CountryID: ukraineCountry.ID},
			{Name: "Kharkiv", Code: "KHK", NumericCode: 2, IsActive: true, CountryID: ukraineCountry.ID},
			{Name: "Odesa", Code: "ODS", NumericCode: 3, IsActive: true, CountryID: ukraineCountry.ID},
			{Name: "Dnipro", Code: "DNP", NumericCode: 4, IsActive: true, CountryID: ukraineCountry.ID},
			{Name: "Donetsk", Code: "DNT", NumericCode: 5, IsActive: true, CountryID: ukraineCountry.ID},
		}
	}

	// Create provinces for Belarus
	var belarusProvinces []models.Province
	if belarusCountry.ID != "" {
		belarusProvinces = []models.Province{
			{Name: "Minsk", Code: "MNS", NumericCode: 1, IsActive: true, CountryID: belarusCountry.ID},
			{Name: "Gomel", Code: "GML", NumericCode: 2, IsActive: true, CountryID: belarusCountry.ID},
			{Name: "Mogilev", Code: "MGL", NumericCode: 3, IsActive: true, CountryID: belarusCountry.ID},
			{Name: "Vitebsk", Code: "VTB", NumericCode: 4, IsActive: true, CountryID: belarusCountry.ID},
			{Name: "Grodno", Code: "GRD", NumericCode: 5, IsActive: true, CountryID: belarusCountry.ID},
		}
	}

	// Create provinces for Moldova
	var moldovaProvinces []models.Province
	if moldovaCountry.ID != "" {
		moldovaProvinces = []models.Province{
			{Name: "Chișinău", Code: "CHI", NumericCode: 1, IsActive: true, CountryID: moldovaCountry.ID},
			{Name: "Tiraspol", Code: "TIR", NumericCode: 2, IsActive: true, CountryID: moldovaCountry.ID},
			{Name: "Bălți", Code: "BLT", NumericCode: 3, IsActive: true, CountryID: moldovaCountry.ID},
			{Name: "Bender", Code: "BND", NumericCode: 4, IsActive: true, CountryID: moldovaCountry.ID},
			{Name: "Rîbnița", Code: "RBN", NumericCode: 5, IsActive: true, CountryID: moldovaCountry.ID},
		}
	}

	// Create provinces for Romania
	var romaniaProvinces []models.Province
	if romaniaCountry.ID != "" {
		romaniaProvinces = []models.Province{
			{Name: "București", Code: "BUC", NumericCode: 1, IsActive: true, CountryID: romaniaCountry.ID},
			{Name: "Cluj", Code: "CLJ", NumericCode: 2, IsActive: true, CountryID: romaniaCountry.ID},
			{Name: "Timiș", Code: "TMS", NumericCode: 3, IsActive: true, CountryID: romaniaCountry.ID},
			{Name: "Iași", Code: "IAS", NumericCode: 4, IsActive: true, CountryID: romaniaCountry.ID},
			{Name: "Constanța", Code: "CST", NumericCode: 5, IsActive: true, CountryID: romaniaCountry.ID},
		}
	}

	// Create provinces for Bulgaria
	var bulgariaProvinces []models.Province
	if bulgariaCountry.ID != "" {
		bulgariaProvinces = []models.Province{
			{Name: "Sofia", Code: "SOF", NumericCode: 1, IsActive: true, CountryID: bulgariaCountry.ID},
			{Name: "Plovdiv", Code: "PLV", NumericCode: 2, IsActive: true, CountryID: bulgariaCountry.ID},
			{Name: "Varna", Code: "VRN", NumericCode: 3, IsActive: true, CountryID: bulgariaCountry.ID},
			{Name: "Burgas", Code: "BGS", NumericCode: 4, IsActive: true, CountryID: bulgariaCountry.ID},
			{Name: "Ruse", Code: "RSE", NumericCode: 5, IsActive: true, CountryID: bulgariaCountry.ID},
		}
	}

	// Create provinces for Serbia
	var serbiaProvinces []models.Province
	if serbiaCountry.ID != "" {
		serbiaProvinces = []models.Province{
			{Name: "Belgrade", Code: "BEG", NumericCode: 1, IsActive: true, CountryID: serbiaCountry.ID},
			{Name: "Novi Sad", Code: "NSD", NumericCode: 2, IsActive: true, CountryID: serbiaCountry.ID},
			{Name: "Niš", Code: "NIS", NumericCode: 3, IsActive: true, CountryID: serbiaCountry.ID},
			{Name: "Kragujevac", Code: "KRG", NumericCode: 4, IsActive: true, CountryID: serbiaCountry.ID},
			{Name: "Subotica", Code: "SBT", NumericCode: 5, IsActive: true, CountryID: serbiaCountry.ID},
		}
	}

	// Create provinces for Croatia
	var croatiaProvinces []models.Province
	if croatiaCountry.ID != "" {
		croatiaProvinces = []models.Province{
			{Name: "Zagreb", Code: "ZGB", NumericCode: 1, IsActive: true, CountryID: croatiaCountry.ID},
			{Name: "Split", Code: "SPL", NumericCode: 2, IsActive: true, CountryID: croatiaCountry.ID},
			{Name: "Rijeka", Code: "RJK", NumericCode: 3, IsActive: true, CountryID: croatiaCountry.ID},
			{Name: "Osijek", Code: "OSJ", NumericCode: 4, IsActive: true, CountryID: croatiaCountry.ID},
			{Name: "Zadar", Code: "ZDR", NumericCode: 5, IsActive: true, CountryID: croatiaCountry.ID},
		}
	}

	// Create provinces for Slovenia
	var sloveniaProvinces []models.Province
	if sloveniaCountry.ID != "" {
		sloveniaProvinces = []models.Province{
			{Name: "Ljubljana", Code: "LJU", NumericCode: 1, IsActive: true, CountryID: sloveniaCountry.ID},
			{Name: "Maribor", Code: "MRB", NumericCode: 2, IsActive: true, CountryID: sloveniaCountry.ID},
			{Name: "Celje", Code: "CLJ", NumericCode: 3, IsActive: true, CountryID: sloveniaCountry.ID},
			{Name: "Kranj", Code: "KRJ", NumericCode: 4, IsActive: true, CountryID: sloveniaCountry.ID},
			{Name: "Koper", Code: "KPR", NumericCode: 5, IsActive: true, CountryID: sloveniaCountry.ID},
		}
	}

	// Create provinces for Slovakia
	var slovakiaProvinces []models.Province
	if slovakiaCountry.ID != "" {
		slovakiaProvinces = []models.Province{
			{Name: "Bratislava", Code: "BTS", NumericCode: 1, IsActive: true, CountryID: slovakiaCountry.ID},
			{Name: "Košice", Code: "KSC", NumericCode: 2, IsActive: true, CountryID: slovakiaCountry.ID},
			{Name: "Žilina", Code: "ZLN", NumericCode: 3, IsActive: true, CountryID: slovakiaCountry.ID},
			{Name: "Nitra", Code: "NTR", NumericCode: 4, IsActive: true, CountryID: slovakiaCountry.ID},
			{Name: "Banská Bystrica", Code: "BBY", NumericCode: 5, IsActive: true, CountryID: slovakiaCountry.ID},
		}
	}

	// Create provinces for Estonia
	var estoniaProvinces []models.Province
	if estoniaCountry.ID != "" {
		estoniaProvinces = []models.Province{
			{Name: "Tallinn", Code: "TLN", NumericCode: 1, IsActive: true, CountryID: estoniaCountry.ID},
			{Name: "Tartu", Code: "TRT", NumericCode: 2, IsActive: true, CountryID: estoniaCountry.ID},
			{Name: "Narva", Code: "NRV", NumericCode: 3, IsActive: true, CountryID: estoniaCountry.ID},
			{Name: "Pärnu", Code: "PRN", NumericCode: 4, IsActive: true, CountryID: estoniaCountry.ID},
			{Name: "Kohtla-Järve", Code: "KTJ", NumericCode: 5, IsActive: true, CountryID: estoniaCountry.ID},
		}
	}

	// Create provinces for Latvia
	var latviaProvinces []models.Province
	if latviaCountry.ID != "" {
		latviaProvinces = []models.Province{
			{Name: "Riga", Code: "RGA", NumericCode: 1, IsActive: true, CountryID: latviaCountry.ID},
			{Name: "Daugavpils", Code: "DGP", NumericCode: 2, IsActive: true, CountryID: latviaCountry.ID},
			{Name: "Liepāja", Code: "LPJ", NumericCode: 3, IsActive: true, CountryID: latviaCountry.ID},
			{Name: "Jelgava", Code: "JLG", NumericCode: 4, IsActive: true, CountryID: latviaCountry.ID},
			{Name: "Jūrmala", Code: "JRM", NumericCode: 5, IsActive: true, CountryID: latviaCountry.ID},
		}
	}

	// Create provinces for Lithuania
	var lithuaniaProvinces []models.Province
	if lithuaniaCountry.ID != "" {
		lithuaniaProvinces = []models.Province{
			{Name: "Vilnius", Code: "VLN", NumericCode: 1, IsActive: true, CountryID: lithuaniaCountry.ID},
			{Name: "Kaunas", Code: "KNS", NumericCode: 2, IsActive: true, CountryID: lithuaniaCountry.ID},
			{Name: "Klaipėda", Code: "KLP", NumericCode: 3, IsActive: true, CountryID: lithuaniaCountry.ID},
			{Name: "Šiauliai", Code: "SIA", NumericCode: 4, IsActive: true, CountryID: lithuaniaCountry.ID},
			{Name: "Panevėžys", Code: "PNV", NumericCode: 5, IsActive: true, CountryID: lithuaniaCountry.ID},
		}
	}

	// Create provinces for Albania
	var albaniaProvinces []models.Province
	if albaniaCountry.ID != "" {
		albaniaProvinces = []models.Province{
			{Name: "Tirana", Code: "TIR", NumericCode: 1, IsActive: true, CountryID: albaniaCountry.ID},
			{Name: "Durrës", Code: "DRS", NumericCode: 2, IsActive: true, CountryID: albaniaCountry.ID},
			{Name: "Vlorë", Code: "VLR", NumericCode: 3, IsActive: true, CountryID: albaniaCountry.ID},
			{Name: "Elbasan", Code: "ELB", NumericCode: 4, IsActive: true, CountryID: albaniaCountry.ID},
			{Name: "Shkodër", Code: "SKD", NumericCode: 5, IsActive: true, CountryID: albaniaCountry.ID},
		}
	}

	// Create provinces for North Macedonia
	var northMacedoniaProvinces []models.Province
	if northMacedoniaCountry.ID != "" {
		northMacedoniaProvinces = []models.Province{
			{Name: "Skopje", Code: "SKP", NumericCode: 1, IsActive: true, CountryID: northMacedoniaCountry.ID},
			{Name: "Bitola", Code: "BTL", NumericCode: 2, IsActive: true, CountryID: northMacedoniaCountry.ID},
			{Name: "Kumanovo", Code: "KMN", NumericCode: 3, IsActive: true, CountryID: northMacedoniaCountry.ID},
			{Name: "Prilep", Code: "PRL", NumericCode: 4, IsActive: true, CountryID: northMacedoniaCountry.ID},
			{Name: "Tetovo", Code: "TTV", NumericCode: 5, IsActive: true, CountryID: northMacedoniaCountry.ID},
		}
	}

	// Create provinces for Kosovo
	var kosovoProvinces []models.Province
	if kosovoCountry.ID != "" {
		kosovoProvinces = []models.Province{
			{Name: "Pristina", Code: "PRS", NumericCode: 1, IsActive: true, CountryID: kosovoCountry.ID},
			{Name: "Prizren", Code: "PRZ", NumericCode: 2, IsActive: true, CountryID: kosovoCountry.ID},
			{Name: "Peja", Code: "PEJ", NumericCode: 3, IsActive: true, CountryID: kosovoCountry.ID},
			{Name: "Gjakova", Code: "GJK", NumericCode: 4, IsActive: true, CountryID: kosovoCountry.ID},
			{Name: "Gjilan", Code: "GJL", NumericCode: 5, IsActive: true, CountryID: kosovoCountry.ID},
		}
	}

	// Create provinces for Montenegro
	var montenegroProvinces []models.Province
	if montenegroCountry.ID != "" {
		montenegroProvinces = []models.Province{
			{Name: "Podgorica", Code: "PDG", NumericCode: 1, IsActive: true, CountryID: montenegroCountry.ID},
			{Name: "Nikšić", Code: "NKS", NumericCode: 2, IsActive: true, CountryID: montenegroCountry.ID},
			{Name: "Herceg Novi", Code: "HNV", NumericCode: 3, IsActive: true, CountryID: montenegroCountry.ID},
			{Name: "Bar", Code: "BAR", NumericCode: 4, IsActive: true, CountryID: montenegroCountry.ID},
			{Name: "Bijelo Polje", Code: "BJP", NumericCode: 5, IsActive: true, CountryID: montenegroCountry.ID},
		}
	}

	// Create provinces for Bosnia and Herzegovina
	var bosniaHerzegovinaProvinces []models.Province
	if bosniaHerzegovinaCountry.ID != "" {
		bosniaHerzegovinaProvinces = []models.Province{
			{Name: "Sarajevo", Code: "SRJ", NumericCode: 1, IsActive: true, CountryID: bosniaHerzegovinaCountry.ID},
			{Name: "Banja Luka", Code: "BJL", NumericCode: 2, IsActive: true, CountryID: bosniaHerzegovinaCountry.ID},
			{Name: "Tuzla", Code: "TZL", NumericCode: 3, IsActive: true, CountryID: bosniaHerzegovinaCountry.ID},
			{Name: "Zenica", Code: "ZNC", NumericCode: 4, IsActive: true, CountryID: bosniaHerzegovinaCountry.ID},
			{Name: "Mostar", Code: "MST", NumericCode: 5, IsActive: true, CountryID: bosniaHerzegovinaCountry.ID},
		}
	}

	// Create provinces for Portugal
	var portugalProvinces []models.Province
	if portugalCountry.ID != "" {
		portugalProvinces = []models.Province{
			{Name: "Lisboa", Code: "LIS", NumericCode: 1, IsActive: true, CountryID: portugalCountry.ID},
			{Name: "Porto", Code: "PRT", NumericCode: 2, IsActive: true, CountryID: portugalCountry.ID},
			{Name: "Braga", Code: "BRG", NumericCode: 3, IsActive: true, CountryID: portugalCountry.ID},
			{Name: "Setúbal", Code: "STB", NumericCode: 4, IsActive: true, CountryID: portugalCountry.ID},
			{Name: "Coimbra", Code: "CMB", NumericCode: 5, IsActive: true, CountryID: portugalCountry.ID},
		}
	}

	// Create provinces for Netherlands
	var netherlandsProvinces []models.Province
	if netherlandsCountry.ID != "" {
		netherlandsProvinces = []models.Province{
			{Name: "North Holland", Code: "NH", NumericCode: 1, IsActive: true, CountryID: netherlandsCountry.ID},
			{Name: "South Holland", Code: "SH", NumericCode: 2, IsActive: true, CountryID: netherlandsCountry.ID},
			{Name: "North Brabant", Code: "NB", NumericCode: 3, IsActive: true, CountryID: netherlandsCountry.ID},
			{Name: "Gelderland", Code: "GL", NumericCode: 4, IsActive: true, CountryID: netherlandsCountry.ID},
			{Name: "Utrecht", Code: "UT", NumericCode: 5, IsActive: true, CountryID: netherlandsCountry.ID},
		}
	}

	// Create provinces for Belgium
	var belgiumProvinces []models.Province
	if belgiumCountry.ID != "" {
		belgiumProvinces = []models.Province{
			{Name: "Antwerp", Code: "ANT", NumericCode: 1, IsActive: true, CountryID: belgiumCountry.ID},
			{Name: "East Flanders", Code: "OVL", NumericCode: 2, IsActive: true, CountryID: belgiumCountry.ID},
			{Name: "Flemish Brabant", Code: "VBR", NumericCode: 3, IsActive: true, CountryID: belgiumCountry.ID},
			{Name: "West Flanders", Code: "WVL", NumericCode: 4, IsActive: true, CountryID: belgiumCountry.ID},
			{Name: "Hainaut", Code: "HAI", NumericCode: 5, IsActive: true, CountryID: belgiumCountry.ID},
		}
	}

	// Create provinces for Switzerland
	var switzerlandProvinces []models.Province
	if switzerlandCountry.ID != "" {
		switzerlandProvinces = []models.Province{
			{Name: "Zurich", Code: "ZH", NumericCode: 1, IsActive: true, CountryID: switzerlandCountry.ID},
			{Name: "Bern", Code: "BE", NumericCode: 2, IsActive: true, CountryID: switzerlandCountry.ID},
			{Name: "Vaud", Code: "VD", NumericCode: 3, IsActive: true, CountryID: switzerlandCountry.ID},
			{Name: "Aargau", Code: "AG", NumericCode: 4, IsActive: true, CountryID: switzerlandCountry.ID},
			{Name: "Geneva", Code: "GE", NumericCode: 5, IsActive: true, CountryID: switzerlandCountry.ID},
		}
	}

	// Create provinces for Austria
	var austriaProvinces []models.Province
	if austriaCountry.ID != "" {
		austriaProvinces = []models.Province{
			{Name: "Vienna", Code: "VIE", NumericCode: 1, IsActive: true, CountryID: austriaCountry.ID},
			{Name: "Upper Austria", Code: "UAU", NumericCode: 2, IsActive: true, CountryID: austriaCountry.ID},
			{Name: "Lower Austria", Code: "LAU", NumericCode: 3, IsActive: true, CountryID: austriaCountry.ID},
			{Name: "Styria", Code: "STY", NumericCode: 4, IsActive: true, CountryID: austriaCountry.ID},
			{Name: "Tyrol", Code: "TYR", NumericCode: 5, IsActive: true, CountryID: austriaCountry.ID},
		}
	}

	// Create provinces for Sweden
	var swedenProvinces []models.Province
	if swedenCountry.ID != "" {
		swedenProvinces = []models.Province{
			{Name: "Stockholm", Code: "STK", NumericCode: 1, IsActive: true, CountryID: swedenCountry.ID},
			{Name: "Västra Götaland", Code: "VGL", NumericCode: 2, IsActive: true, CountryID: swedenCountry.ID},
			{Name: "Skåne", Code: "SKN", NumericCode: 3, IsActive: true, CountryID: swedenCountry.ID},
			{Name: "Östergötland", Code: "OGL", NumericCode: 4, IsActive: true, CountryID: swedenCountry.ID},
			{Name: "Uppsala", Code: "UPP", NumericCode: 5, IsActive: true, CountryID: swedenCountry.ID},
		}
	}

	// Create provinces for Norway
	var norwayProvinces []models.Province
	if norwayCountry.ID != "" {
		norwayProvinces = []models.Province{
			{Name: "Oslo", Code: "OSL", NumericCode: 1, IsActive: true, CountryID: norwayCountry.ID},
			{Name: "Viken", Code: "VIK", NumericCode: 2, IsActive: true, CountryID: norwayCountry.ID},
			{Name: "Vestland", Code: "VST", NumericCode: 3, IsActive: true, CountryID: norwayCountry.ID},
			{Name: "Innlandet", Code: "INN", NumericCode: 4, IsActive: true, CountryID: norwayCountry.ID},
			{Name: "Vestfold og Telemark", Code: "VTF", NumericCode: 5, IsActive: true, CountryID: norwayCountry.ID},
		}
	}

	// Create provinces for Denmark
	var denmarkProvinces []models.Province
	if denmarkCountry.ID != "" {
		denmarkProvinces = []models.Province{
			{Name: "Capital Region", Code: "CAP", NumericCode: 1, IsActive: true, CountryID: denmarkCountry.ID},
			{Name: "Central Jutland", Code: "CJL", NumericCode: 2, IsActive: true, CountryID: denmarkCountry.ID},
			{Name: "North Jutland", Code: "NJL", NumericCode: 3, IsActive: true, CountryID: denmarkCountry.ID},
			{Name: "Region Zealand", Code: "RZL", NumericCode: 4, IsActive: true, CountryID: denmarkCountry.ID},
			{Name: "Region of Southern Denmark", Code: "RSD", NumericCode: 5, IsActive: true, CountryID: denmarkCountry.ID},
		}
	}

	// Create provinces for Finland
	var finlandProvinces []models.Province
	if finlandCountry.ID != "" {
		finlandProvinces = []models.Province{
			{Name: "Uusimaa", Code: "UUS", NumericCode: 1, IsActive: true, CountryID: finlandCountry.ID},
			{Name: "Pirkanmaa", Code: "PIR", NumericCode: 2, IsActive: true, CountryID: finlandCountry.ID},
			{Name: "Varsinais-Suomi", Code: "VSS", NumericCode: 3, IsActive: true, CountryID: finlandCountry.ID},
			{Name: "Päijät-Häme", Code: "PAH", NumericCode: 4, IsActive: true, CountryID: finlandCountry.ID},
			{Name: "Kanta-Häme", Code: "KAH", NumericCode: 5, IsActive: true, CountryID: finlandCountry.ID},
		}
	}

	// Create provinces for Poland
	var polandProvinces []models.Province
	if polandCountry.ID != "" {
		polandProvinces = []models.Province{
			{Name: "Mazowieckie", Code: "MAZ", NumericCode: 1, IsActive: true, CountryID: polandCountry.ID},
			{Name: "Śląskie", Code: "SLA", NumericCode: 2, IsActive: true, CountryID: polandCountry.ID},
			{Name: "Wielkopolskie", Code: "WIE", NumericCode: 3, IsActive: true, CountryID: polandCountry.ID},
			{Name: "Małopolskie", Code: "MAL", NumericCode: 4, IsActive: true, CountryID: polandCountry.ID},
			{Name: "Dolnośląskie", Code: "DOL", NumericCode: 5, IsActive: true, CountryID: polandCountry.ID},
		}
	}

	// Create provinces for Czech Republic
	var czechRepublicProvinces []models.Province
	if czechRepublicCountry.ID != "" {
		czechRepublicProvinces = []models.Province{
			{Name: "Prague", Code: "PRA", NumericCode: 1, IsActive: true, CountryID: czechRepublicCountry.ID},
			{Name: "South Moravian", Code: "SMO", NumericCode: 2, IsActive: true, CountryID: czechRepublicCountry.ID},
			{Name: "Moravian-Silesian", Code: "MSO", NumericCode: 3, IsActive: true, CountryID: czechRepublicCountry.ID},
			{Name: "Central Bohemian", Code: "CBO", NumericCode: 4, IsActive: true, CountryID: czechRepublicCountry.ID},
			{Name: "Ústí nad Labem", Code: "UNL", NumericCode: 5, IsActive: true, CountryID: czechRepublicCountry.ID},
		}
	}

	// Create provinces for Hungary
	var hungaryProvinces []models.Province
	if hungaryCountry.ID != "" {
		hungaryProvinces = []models.Province{
			{Name: "Budapest", Code: "BUD", NumericCode: 1, IsActive: true, CountryID: hungaryCountry.ID},
			{Name: "Pest", Code: "PES", NumericCode: 2, IsActive: true, CountryID: hungaryCountry.ID},
			{Name: "Borsod-Abaúj-Zemplén", Code: "BAZ", NumericCode: 3, IsActive: true, CountryID: hungaryCountry.ID},
			{Name: "Szabolcs-Szatmár-Bereg", Code: "SSB", NumericCode: 4, IsActive: true, CountryID: hungaryCountry.ID},
			{Name: "Hajdú-Bihar", Code: "HAB", NumericCode: 5, IsActive: true, CountryID: hungaryCountry.ID},
		}
	}

	// Create provinces for Greece
	var greeceProvinces []models.Province
	if greeceCountry.ID != "" {
		greeceProvinces = []models.Province{
			{Name: "Attica", Code: "ATT", NumericCode: 1, IsActive: true, CountryID: greeceCountry.ID},
			{Name: "Central Macedonia", Code: "CMK", NumericCode: 2, IsActive: true, CountryID: greeceCountry.ID},
			{Name: "Thessaly", Code: "THS", NumericCode: 3, IsActive: true, CountryID: greeceCountry.ID},
			{Name: "Western Greece", Code: "WGR", NumericCode: 4, IsActive: true, CountryID: greeceCountry.ID},
			{Name: "Crete", Code: "CRT", NumericCode: 5, IsActive: true, CountryID: greeceCountry.ID},
		}
	}

	// Create provinces for Turkey
	var turkeyProvinces []models.Province
	if turkeyCountry.ID != "" {
		turkeyProvinces = []models.Province{
			{Name: "Istanbul", Code: "IST", NumericCode: 1, IsActive: true, CountryID: turkeyCountry.ID},
			{Name: "Ankara", Code: "ANK", NumericCode: 2, IsActive: true, CountryID: turkeyCountry.ID},
			{Name: "İzmir", Code: "IZM", NumericCode: 3, IsActive: true, CountryID: turkeyCountry.ID},
			{Name: "Bursa", Code: "BRS", NumericCode: 4, IsActive: true, CountryID: turkeyCountry.ID},
			{Name: "Antalya", Code: "ANT", NumericCode: 5, IsActive: true, CountryID: turkeyCountry.ID},
		}
	}

	// Create provinces for Egypt
	var egyptProvinces []models.Province
	if egyptCountry.ID != "" {
		egyptProvinces = []models.Province{
			{Name: "Cairo", Code: "CAI", NumericCode: 1, IsActive: true, CountryID: egyptCountry.ID},
			{Name: "Giza", Code: "GIZ", NumericCode: 2, IsActive: true, CountryID: egyptCountry.ID},
			{Name: "Alexandria", Code: "ALX", NumericCode: 3, IsActive: true, CountryID: egyptCountry.ID},
			{Name: "Qalyubia", Code: "QLY", NumericCode: 4, IsActive: true, CountryID: egyptCountry.ID},
			{Name: "Sharqia", Code: "SHR", NumericCode: 5, IsActive: true, CountryID: egyptCountry.ID},
		}
	}

	// Create provinces for South Africa
	var southAfricaProvinces []models.Province
	if southAfricaCountry.ID != "" {
		southAfricaProvinces = []models.Province{
			{Name: "Gauteng", Code: "GAU", NumericCode: 1, IsActive: true, CountryID: southAfricaCountry.ID},
			{Name: "KwaZulu-Natal", Code: "KZN", NumericCode: 2, IsActive: true, CountryID: southAfricaCountry.ID},
			{Name: "Western Cape", Code: "WCP", NumericCode: 3, IsActive: true, CountryID: southAfricaCountry.ID},
			{Name: "Eastern Cape", Code: "ECP", NumericCode: 4, IsActive: true, CountryID: southAfricaCountry.ID},
			{Name: "Free State", Code: "FST", NumericCode: 5, IsActive: true, CountryID: southAfricaCountry.ID},
		}
	}

	// Create provinces for Nigeria
	var nigeriaProvinces []models.Province
	if nigeriaCountry.ID != "" {
		nigeriaProvinces = []models.Province{
			{Name: "Lagos", Code: "LAG", NumericCode: 1, IsActive: true, CountryID: nigeriaCountry.ID},
			{Name: "Kano", Code: "KAN", NumericCode: 2, IsActive: true, CountryID: nigeriaCountry.ID},
			{Name: "Kaduna", Code: "KAD", NumericCode: 3, IsActive: true, CountryID: nigeriaCountry.ID},
			{Name: "Katsina", Code: "KAT", NumericCode: 4, IsActive: true, CountryID: nigeriaCountry.ID},
			{Name: "Oyo", Code: "OYO", NumericCode: 5, IsActive: true, CountryID: nigeriaCountry.ID},
		}
	}

	// Create provinces for Kenya
	var kenyaProvinces []models.Province
	if kenyaCountry.ID != "" {
		kenyaProvinces = []models.Province{
			{Name: "Nairobi", Code: "NBI", NumericCode: 1, IsActive: true, CountryID: kenyaCountry.ID},
			{Name: "Mombasa", Code: "MBS", NumericCode: 2, IsActive: true, CountryID: kenyaCountry.ID},
			{Name: "Kisumu", Code: "KSM", NumericCode: 3, IsActive: true, CountryID: kenyaCountry.ID},
			{Name: "Nakuru", Code: "NKR", NumericCode: 4, IsActive: true, CountryID: kenyaCountry.ID},
			{Name: "Eldoret", Code: "ELD", NumericCode: 5, IsActive: true, CountryID: kenyaCountry.ID},
		}
	}

	// Create provinces for Ghana
	var ghanaProvinces []models.Province
	if ghanaCountry.ID != "" {
		ghanaProvinces = []models.Province{
			{Name: "Greater Accra", Code: "GAC", NumericCode: 1, IsActive: true, CountryID: ghanaCountry.ID},
			{Name: "Ashanti", Code: "ASH", NumericCode: 2, IsActive: true, CountryID: ghanaCountry.ID},
			{Name: "Western", Code: "WST", NumericCode: 3, IsActive: true, CountryID: ghanaCountry.ID},
			{Name: "Eastern", Code: "EST", NumericCode: 4, IsActive: true, CountryID: ghanaCountry.ID},
			{Name: "Central", Code: "CTR", NumericCode: 5, IsActive: true, CountryID: ghanaCountry.ID},
		}
	}

	// Create provinces for Morocco
	var moroccoProvinces []models.Province
	if moroccoCountry.ID != "" {
		moroccoProvinces = []models.Province{
			{Name: "Casablanca-Settat", Code: "CST", NumericCode: 1, IsActive: true, CountryID: moroccoCountry.ID},
			{Name: "Rabat-Salé-Kénitra", Code: "RSK", NumericCode: 2, IsActive: true, CountryID: moroccoCountry.ID},
			{Name: "Marrakech-Safi", Code: "MSF", NumericCode: 3, IsActive: true, CountryID: moroccoCountry.ID},
			{Name: "Fès-Meknès", Code: "FMK", NumericCode: 4, IsActive: true, CountryID: moroccoCountry.ID},
			{Name: "Tanger-Tétouan-Al Hoceïma", Code: "TTH", NumericCode: 5, IsActive: true, CountryID: moroccoCountry.ID},
		}
	}

	// Create provinces for Algeria
	var algeriaProvinces []models.Province
	if algeriaCountry.ID != "" {
		algeriaProvinces = []models.Province{
			{Name: "Algiers", Code: "ALG", NumericCode: 1, IsActive: true, CountryID: algeriaCountry.ID},
			{Name: "Oran", Code: "ORN", NumericCode: 2, IsActive: true, CountryID: algeriaCountry.ID},
			{Name: "Constantine", Code: "CST", NumericCode: 3, IsActive: true, CountryID: algeriaCountry.ID},
			{Name: "Annaba", Code: "ANB", NumericCode: 4, IsActive: true, CountryID: algeriaCountry.ID},
			{Name: "Batna", Code: "BTN", NumericCode: 5, IsActive: true, CountryID: algeriaCountry.ID},
		}
	}

	// Create provinces for Tunisia
	var tunisiaProvinces []models.Province
	if tunisiaCountry.ID != "" {
		tunisiaProvinces = []models.Province{
			{Name: "Tunis", Code: "TNS", NumericCode: 1, IsActive: true, CountryID: tunisiaCountry.ID},
			{Name: "Sfax", Code: "SFX", NumericCode: 2, IsActive: true, CountryID: tunisiaCountry.ID},
			{Name: "Sousse", Code: "SSE", NumericCode: 3, IsActive: true, CountryID: tunisiaCountry.ID},
			{Name: "Monastir", Code: "MNS", NumericCode: 4, IsActive: true, CountryID: tunisiaCountry.ID},
			{Name: "Gabès", Code: "GBS", NumericCode: 5, IsActive: true, CountryID: tunisiaCountry.ID},
		}
	}

	// Create provinces for Ethiopia
	var ethiopiaProvinces []models.Province
	if ethiopiaCountry.ID != "" {
		ethiopiaProvinces = []models.Province{
			{Name: "Addis Ababa", Code: "AAB", NumericCode: 1, IsActive: true, CountryID: ethiopiaCountry.ID},
			{Name: "Oromia", Code: "ORM", NumericCode: 2, IsActive: true, CountryID: ethiopiaCountry.ID},
			{Name: "Amhara", Code: "AMH", NumericCode: 3, IsActive: true, CountryID: ethiopiaCountry.ID},
			{Name: "Tigray", Code: "TGR", NumericCode: 4, IsActive: true, CountryID: ethiopiaCountry.ID},
			{Name: "Southern Nations", Code: "SNN", NumericCode: 5, IsActive: true, CountryID: ethiopiaCountry.ID},
		}
	}

	// Create provinces for Argentina
	var argentinaProvinces []models.Province
	if argentinaCountry.ID != "" {
		argentinaProvinces = []models.Province{
			{Name: "Buenos Aires", Code: "BUE", NumericCode: 1, IsActive: true, CountryID: argentinaCountry.ID},
			{Name: "Córdoba", Code: "COR", NumericCode: 2, IsActive: true, CountryID: argentinaCountry.ID},
			{Name: "Santa Fe", Code: "SFE", NumericCode: 3, IsActive: true, CountryID: argentinaCountry.ID},
			{Name: "Mendoza", Code: "MEN", NumericCode: 4, IsActive: true, CountryID: argentinaCountry.ID},
			{Name: "Tucumán", Code: "TUC", NumericCode: 5, IsActive: true, CountryID: argentinaCountry.ID},
		}
	}

	// Create provinces for Chile
	var chileProvinces []models.Province
	if chileCountry.ID != "" {
		chileProvinces = []models.Province{
			{Name: "Santiago", Code: "STG", NumericCode: 1, IsActive: true, CountryID: chileCountry.ID},
			{Name: "Valparaíso", Code: "VLP", NumericCode: 2, IsActive: true, CountryID: chileCountry.ID},
			{Name: "Biobío", Code: "BIO", NumericCode: 3, IsActive: true, CountryID: chileCountry.ID},
			{Name: "La Araucanía", Code: "LAR", NumericCode: 4, IsActive: true, CountryID: chileCountry.ID},
			{Name: "Los Lagos", Code: "LLG", NumericCode: 5, IsActive: true, CountryID: chileCountry.ID},
		}
	}

	// Create provinces for Colombia
	var colombiaProvinces []models.Province
	if colombiaCountry.ID != "" {
		colombiaProvinces = []models.Province{
			{Name: "Antioquia", Code: "ANT", NumericCode: 1, IsActive: true, CountryID: colombiaCountry.ID},
			{Name: "Cundinamarca", Code: "CUN", NumericCode: 2, IsActive: true, CountryID: colombiaCountry.ID},
			{Name: "Valle del Cauca", Code: "VDC", NumericCode: 3, IsActive: true, CountryID: colombiaCountry.ID},
			{Name: "Atlántico", Code: "ATL", NumericCode: 4, IsActive: true, CountryID: colombiaCountry.ID},
			{Name: "Santander", Code: "SAN", NumericCode: 5, IsActive: true, CountryID: colombiaCountry.ID},
		}
	}

	// Create provinces for Peru
	var peruProvinces []models.Province
	if peruCountry.ID != "" {
		peruProvinces = []models.Province{
			{Name: "Lima", Code: "LIM", NumericCode: 1, IsActive: true, CountryID: peruCountry.ID},
			{Name: "Arequipa", Code: "ARE", NumericCode: 2, IsActive: true, CountryID: peruCountry.ID},
			{Name: "La Libertad", Code: "LLB", NumericCode: 3, IsActive: true, CountryID: peruCountry.ID},
			{Name: "Piura", Code: "PIU", NumericCode: 4, IsActive: true, CountryID: peruCountry.ID},
			{Name: "Lambayeque", Code: "LAM", NumericCode: 5, IsActive: true, CountryID: peruCountry.ID},
		}
	}

	// Create provinces for Venezuela
	var venezuelaProvinces []models.Province
	if venezuelaCountry.ID != "" {
		venezuelaProvinces = []models.Province{
			{Name: "Miranda", Code: "MIR", NumericCode: 1, IsActive: true, CountryID: venezuelaCountry.ID},
			{Name: "Zulia", Code: "ZUL", NumericCode: 2, IsActive: true, CountryID: venezuelaCountry.ID},
			{Name: "Carabobo", Code: "CAR", NumericCode: 3, IsActive: true, CountryID: venezuelaCountry.ID},
			{Name: "Aragua", Code: "ARA", NumericCode: 4, IsActive: true, CountryID: venezuelaCountry.ID},
			{Name: "Bolívar", Code: "BOL", NumericCode: 5, IsActive: true, CountryID: venezuelaCountry.ID},
		}
	}

	// Create provinces for Saudi Arabia
	var saudiArabiaProvinces []models.Province
	if saudiArabiaCountry.ID != "" {
		saudiArabiaProvinces = []models.Province{
			{Name: "Riyadh", Code: "RYD", NumericCode: 1, IsActive: true, CountryID: saudiArabiaCountry.ID},
			{Name: "Makkah", Code: "MKK", NumericCode: 2, IsActive: true, CountryID: saudiArabiaCountry.ID},
			{Name: "Eastern Province", Code: "EPR", NumericCode: 3, IsActive: true, CountryID: saudiArabiaCountry.ID},
			{Name: "Asir", Code: "ASR", NumericCode: 4, IsActive: true, CountryID: saudiArabiaCountry.ID},
			{Name: "Qassim", Code: "QSM", NumericCode: 5, IsActive: true, CountryID: saudiArabiaCountry.ID},
		}
	}

	// Create provinces for UAE
	var uaeProvinces []models.Province
	if uaeCountry.ID != "" {
		uaeProvinces = []models.Province{
			{Name: "Dubai", Code: "DUB", NumericCode: 1, IsActive: true, CountryID: uaeCountry.ID},
			{Name: "Abu Dhabi", Code: "ABD", NumericCode: 2, IsActive: true, CountryID: uaeCountry.ID},
			{Name: "Sharjah", Code: "SHJ", NumericCode: 3, IsActive: true, CountryID: uaeCountry.ID},
			{Name: "Ajman", Code: "AJM", NumericCode: 4, IsActive: true, CountryID: uaeCountry.ID},
			{Name: "Ras Al Khaimah", Code: "RAK", NumericCode: 5, IsActive: true, CountryID: uaeCountry.ID},
		}
	}

	// Create provinces for Qatar
	var qatarProvinces []models.Province
	if qatarCountry.ID != "" {
		qatarProvinces = []models.Province{
			{Name: "Doha", Code: "DOH", NumericCode: 1, IsActive: true, CountryID: qatarCountry.ID},
			{Name: "Al Wakrah", Code: "AWK", NumericCode: 2, IsActive: true, CountryID: qatarCountry.ID},
			{Name: "Al Khor", Code: "AKH", NumericCode: 3, IsActive: true, CountryID: qatarCountry.ID},
			{Name: "Al Rayyan", Code: "ARY", NumericCode: 4, IsActive: true, CountryID: qatarCountry.ID},
			{Name: "Umm Salal", Code: "UMS", NumericCode: 5, IsActive: true, CountryID: qatarCountry.ID},
		}
	}

	// Create provinces for Israel
	var israelProvinces []models.Province
	if israelCountry.ID != "" {
		israelProvinces = []models.Province{
			{Name: "Tel Aviv", Code: "TEL", NumericCode: 1, IsActive: true, CountryID: israelCountry.ID},
			{Name: "Jerusalem", Code: "JRS", NumericCode: 2, IsActive: true, CountryID: israelCountry.ID},
			{Name: "Haifa", Code: "HAI", NumericCode: 3, IsActive: true, CountryID: israelCountry.ID},
			{Name: "Central", Code: "CTR", NumericCode: 4, IsActive: true, CountryID: israelCountry.ID},
			{Name: "Southern", Code: "SUT", NumericCode: 5, IsActive: true, CountryID: israelCountry.ID},
		}
	}

	// Create provinces for Jordan
	var jordanProvinces []models.Province
	if jordanCountry.ID != "" {
		jordanProvinces = []models.Province{
			{Name: "Amman", Code: "AMM", NumericCode: 1, IsActive: true, CountryID: jordanCountry.ID},
			{Name: "Irbid", Code: "IRB", NumericCode: 2, IsActive: true, CountryID: jordanCountry.ID},
			{Name: "Zarqa", Code: "ZAR", NumericCode: 3, IsActive: true, CountryID: jordanCountry.ID},
			{Name: "Balqa", Code: "BLQ", NumericCode: 4, IsActive: true, CountryID: jordanCountry.ID},
			{Name: "Mafraq", Code: "MFR", NumericCode: 5, IsActive: true, CountryID: jordanCountry.ID},
		}
	}

	// Create provinces for Lebanon
	var lebanonProvinces []models.Province
	if lebanonCountry.ID != "" {
		lebanonProvinces = []models.Province{
			{Name: "Beirut", Code: "BEI", NumericCode: 1, IsActive: true, CountryID: lebanonCountry.ID},
			{Name: "Mount Lebanon", Code: "MTL", NumericCode: 2, IsActive: true, CountryID: lebanonCountry.ID},
			{Name: "North Lebanon", Code: "NRL", NumericCode: 3, IsActive: true, CountryID: lebanonCountry.ID},
			{Name: "South Lebanon", Code: "SRL", NumericCode: 4, IsActive: true, CountryID: lebanonCountry.ID},
			{Name: "Bekaa", Code: "BEK", NumericCode: 5, IsActive: true, CountryID: lebanonCountry.ID},
		}
	}

	// Create provinces for Iraq
	var iraqProvinces []models.Province
	if iraqCountry.ID != "" {
		iraqProvinces = []models.Province{
			{Name: "Baghdad", Code: "BGD", NumericCode: 1, IsActive: true, CountryID: iraqCountry.ID},
			{Name: "Basra", Code: "BSR", NumericCode: 2, IsActive: true, CountryID: iraqCountry.ID},
			{Name: "Nineveh", Code: "NIN", NumericCode: 3, IsActive: true, CountryID: iraqCountry.ID},
			{Name: "Sulaymaniyah", Code: "SUL", NumericCode: 4, IsActive: true, CountryID: iraqCountry.ID},
			{Name: "Erbil", Code: "ERB", NumericCode: 5, IsActive: true, CountryID: iraqCountry.ID},
		}
	}

	// Create provinces for Iran
	var iranProvinces []models.Province
	if iranCountry.ID != "" {
		iranProvinces = []models.Province{
			{Name: "Tehran", Code: "THR", NumericCode: 1, IsActive: true, CountryID: iranCountry.ID},
			{Name: "Isfahan", Code: "ISF", NumericCode: 2, IsActive: true, CountryID: iranCountry.ID},
			{Name: "Fars", Code: "FRS", NumericCode: 3, IsActive: true, CountryID: iranCountry.ID},
			{Name: "Khorasan", Code: "KHR", NumericCode: 4, IsActive: true, CountryID: iranCountry.ID},
			{Name: "East Azerbaijan", Code: "EAZ", NumericCode: 5, IsActive: true, CountryID: iranCountry.ID},
		}
	}

	// Create provinces for Syria
	var syriaProvinces []models.Province
	if syriaCountry.ID != "" {
		syriaProvinces = []models.Province{
			{Name: "Damascus", Code: "DAM", NumericCode: 1, IsActive: true, CountryID: syriaCountry.ID},
			{Name: "Aleppo", Code: "ALP", NumericCode: 2, IsActive: true, CountryID: syriaCountry.ID},
			{Name: "Homs", Code: "HMS", NumericCode: 3, IsActive: true, CountryID: syriaCountry.ID},
			{Name: "Hama", Code: "HMA", NumericCode: 4, IsActive: true, CountryID: syriaCountry.ID},
			{Name: "Latakia", Code: "LTK", NumericCode: 5, IsActive: true, CountryID: syriaCountry.ID},
		}
	}

	// Create provinces for Yemen
	var yemenProvinces []models.Province
	if yemenCountry.ID != "" {
		yemenProvinces = []models.Province{
			{Name: "Sana'a", Code: "SNA", NumericCode: 1, IsActive: true, CountryID: yemenCountry.ID},
			{Name: "Aden", Code: "ADN", NumericCode: 2, IsActive: true, CountryID: yemenCountry.ID},
			{Name: "Taiz", Code: "TAZ", NumericCode: 3, IsActive: true, CountryID: yemenCountry.ID},
			{Name: "Hodeidah", Code: "HDH", NumericCode: 4, IsActive: true, CountryID: yemenCountry.ID},
			{Name: "Ibb", Code: "IBB", NumericCode: 5, IsActive: true, CountryID: yemenCountry.ID},
		}
	}

	// Create provinces for Oman
	var omanProvinces []models.Province
	if omanCountry.ID != "" {
		omanProvinces = []models.Province{
			{Name: "Muscat", Code: "MSC", NumericCode: 1, IsActive: true, CountryID: omanCountry.ID},
			{Name: "Dhofar", Code: "DHF", NumericCode: 2, IsActive: true, CountryID: omanCountry.ID},
			{Name: "Musandam", Code: "MSD", NumericCode: 3, IsActive: true, CountryID: omanCountry.ID},
			{Name: "Al Buraimi", Code: "ABM", NumericCode: 4, IsActive: true, CountryID: omanCountry.ID},
			{Name: "Al Wusta", Code: "AWT", NumericCode: 5, IsActive: true, CountryID: omanCountry.ID},
		}
	}

	// Create provinces for Kuwait
	var kuwaitProvinces []models.Province
	if kuwaitCountry.ID != "" {
		kuwaitProvinces = []models.Province{
			{Name: "Al Asimah", Code: "AAS", NumericCode: 1, IsActive: true, CountryID: kuwaitCountry.ID},
			{Name: "Hawalli", Code: "HWL", NumericCode: 2, IsActive: true, CountryID: kuwaitCountry.ID},
			{Name: "Al Ahmadi", Code: "AAH", NumericCode: 3, IsActive: true, CountryID: kuwaitCountry.ID},
			{Name: "Al Jahra", Code: "AJH", NumericCode: 4, IsActive: true, CountryID: kuwaitCountry.ID},
			{Name: "Mubarak Al-Kabeer", Code: "MAK", NumericCode: 5, IsActive: true, CountryID: kuwaitCountry.ID},
		}
	}

	// Create provinces for Bahrain
	var bahrainProvinces []models.Province
	if bahrainCountry.ID != "" {
		bahrainProvinces = []models.Province{
			{Name: "Capital", Code: "CAP", NumericCode: 1, IsActive: true, CountryID: bahrainCountry.ID},
			{Name: "Muharraq", Code: "MHR", NumericCode: 2, IsActive: true, CountryID: bahrainCountry.ID},
			{Name: "Northern", Code: "NRT", NumericCode: 3, IsActive: true, CountryID: bahrainCountry.ID},
			{Name: "Southern", Code: "SUT", NumericCode: 4, IsActive: true, CountryID: bahrainCountry.ID},
		}
	}

	// Create provinces for Cyprus
	var cyprusProvinces []models.Province
	if cyprusCountry.ID != "" {
		cyprusProvinces = []models.Province{
			{Name: "Nicosia", Code: "NIC", NumericCode: 1, IsActive: true, CountryID: cyprusCountry.ID},
			{Name: "Limassol", Code: "LIM", NumericCode: 2, IsActive: true, CountryID: cyprusCountry.ID},
			{Name: "Larnaca", Code: "LAR", NumericCode: 3, IsActive: true, CountryID: cyprusCountry.ID},
			{Name: "Paphos", Code: "PAP", NumericCode: 4, IsActive: true, CountryID: cyprusCountry.ID},
			{Name: "Famagusta", Code: "FAM", NumericCode: 5, IsActive: true, CountryID: cyprusCountry.ID},
		}
	}

	// Create provinces for Georgia
	var georgiaProvinces []models.Province
	if georgiaCountry.ID != "" {
		georgiaProvinces = []models.Province{
			{Name: "Tbilisi", Code: "TBL", NumericCode: 1, IsActive: true, CountryID: georgiaCountry.ID},
			{Name: "Imereti", Code: "IMR", NumericCode: 2, IsActive: true, CountryID: georgiaCountry.ID},
			{Name: "Kvemo Kartli", Code: "KVK", NumericCode: 3, IsActive: true, CountryID: georgiaCountry.ID},
			{Name: "Kakheti", Code: "KKH", NumericCode: 4, IsActive: true, CountryID: georgiaCountry.ID},
			{Name: "Samegrelo-Zemo Svaneti", Code: "SZS", NumericCode: 5, IsActive: true, CountryID: georgiaCountry.ID},
		}
	}

	// Create provinces for Armenia
	var armeniaProvinces []models.Province
	if armeniaCountry.ID != "" {
		armeniaProvinces = []models.Province{
			{Name: "Yerevan", Code: "YRV", NumericCode: 1, IsActive: true, CountryID: armeniaCountry.ID},
			{Name: "Shirak", Code: "SHK", NumericCode: 2, IsActive: true, CountryID: armeniaCountry.ID},
			{Name: "Lori", Code: "LOR", NumericCode: 3, IsActive: true, CountryID: armeniaCountry.ID},
			{Name: "Ararat", Code: "ART", NumericCode: 4, IsActive: true, CountryID: armeniaCountry.ID},
			{Name: "Kotayk", Code: "KTK", NumericCode: 5, IsActive: true, CountryID: armeniaCountry.ID},
		}
	}

	// Create provinces for Azerbaijan
	var azerbaijanProvinces []models.Province
	if azerbaijanCountry.ID != "" {
		azerbaijanProvinces = []models.Province{
			{Name: "Baku", Code: "BAK", NumericCode: 1, IsActive: true, CountryID: azerbaijanCountry.ID},
			{Name: "Ganja", Code: "GNJ", NumericCode: 2, IsActive: true, CountryID: azerbaijanCountry.ID},
			{Name: "Sumqayit", Code: "SMQ", NumericCode: 3, IsActive: true, CountryID: azerbaijanCountry.ID},
			{Name: "Mingachevir", Code: "MNG", NumericCode: 4, IsActive: true, CountryID: azerbaijanCountry.ID},
			{Name: "Nakhchivan", Code: "NKH", NumericCode: 5, IsActive: true, CountryID: azerbaijanCountry.ID},
		}
	}

	// Create provinces for Kazakhstan
	var kazakhstanProvinces []models.Province
	if kazakhstanCountry.ID != "" {
		kazakhstanProvinces = []models.Province{
			{Name: "Almaty", Code: "ALM", NumericCode: 1, IsActive: true, CountryID: kazakhstanCountry.ID},
			{Name: "Astana", Code: "AST", NumericCode: 2, IsActive: true, CountryID: kazakhstanCountry.ID},
			{Name: "Shymkent", Code: "SHM", NumericCode: 3, IsActive: true, CountryID: kazakhstanCountry.ID},
			{Name: "Karaganda", Code: "KRG", NumericCode: 4, IsActive: true, CountryID: kazakhstanCountry.ID},
			{Name: "Aktobe", Code: "AKT", NumericCode: 5, IsActive: true, CountryID: kazakhstanCountry.ID},
		}
	}

	// Create provinces for Uzbekistan
	var uzbekistanProvinces []models.Province
	if uzbekistanCountry.ID != "" {
		uzbekistanProvinces = []models.Province{
			{Name: "Tashkent", Code: "TSH", NumericCode: 1, IsActive: true, CountryID: uzbekistanCountry.ID},
			{Name: "Samarkand", Code: "SMR", NumericCode: 2, IsActive: true, CountryID: uzbekistanCountry.ID},
			{Name: "Bukhara", Code: "BKH", NumericCode: 3, IsActive: true, CountryID: uzbekistanCountry.ID},
			{Name: "Andijan", Code: "AND", NumericCode: 4, IsActive: true, CountryID: uzbekistanCountry.ID},
			{Name: "Fergana", Code: "FRG", NumericCode: 5, IsActive: true, CountryID: uzbekistanCountry.ID},
		}
	}

	// Create provinces for Turkmenistan
	var turkmenistanProvinces []models.Province
	if turkmenistanCountry.ID != "" {
		turkmenistanProvinces = []models.Province{
			{Name: "Ashgabat", Code: "ASH", NumericCode: 1, IsActive: true, CountryID: turkmenistanCountry.ID},
			{Name: "Ahal", Code: "AHL", NumericCode: 2, IsActive: true, CountryID: turkmenistanCountry.ID},
			{Name: "Balkan", Code: "BLK", NumericCode: 3, IsActive: true, CountryID: turkmenistanCountry.ID},
			{Name: "Dashoguz", Code: "DSH", NumericCode: 4, IsActive: true, CountryID: turkmenistanCountry.ID},
			{Name: "Lebap", Code: "LBP", NumericCode: 5, IsActive: true, CountryID: turkmenistanCountry.ID},
		}
	}

	// Create provinces for Kyrgyzstan
	var kyrgyzstanProvinces []models.Province
	if kyrgyzstanCountry.ID != "" {
		kyrgyzstanProvinces = []models.Province{
			{Name: "Bishkek", Code: "BI", NumericCode: 1, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Osh", Code: "OS", NumericCode: 2, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Batken", Code: "BA", NumericCode: 3, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Chuy", Code: "CH", NumericCode: 4, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Issyk-Kul", Code: "IK", NumericCode: 5, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Jalal-Abad", Code: "JA", NumericCode: 6, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Naryn", Code: "NA", NumericCode: 7, IsActive: true, CountryID: kyrgyzstanCountry.ID},
			{Name: "Talas", Code: "TA", NumericCode: 8, IsActive: true, CountryID: kyrgyzstanCountry.ID},
		}
	}

	// Create provinces for Tajikistan
	var tajikistanProvinces []models.Province
	if tajikistanCountry.ID != "" {
		tajikistanProvinces = []models.Province{
			{Name: "Dushanbe", Code: "DU", NumericCode: 1, IsActive: true, CountryID: tajikistanCountry.ID},
			{Name: "Gorno-Badakhshan", Code: "GB", NumericCode: 2, IsActive: true, CountryID: tajikistanCountry.ID},
			{Name: "Khatlon", Code: "KT", NumericCode: 3, IsActive: true, CountryID: tajikistanCountry.ID},
			{Name: "Sughd", Code: "SU", NumericCode: 4, IsActive: true, CountryID: tajikistanCountry.ID},
			{Name: "Districts of Republican Subordination", Code: "DR", NumericCode: 5, IsActive: true, CountryID: tajikistanCountry.ID},
		}
	}

	// Create provinces for North Korea
	var northKoreaProvinces []models.Province
	if northKoreaCountry.ID != "" {
		northKoreaProvinces = []models.Province{
			{Name: "Pyongyang", Code: "PY", NumericCode: 1, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "North Pyongan", Code: "NP", NumericCode: 2, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "South Pyongan", Code: "SP", NumericCode: 3, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "North Hwanghae", Code: "NH", NumericCode: 4, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "South Hwanghae", Code: "SH", NumericCode: 5, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "Kangwon", Code: "KW", NumericCode: 6, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "North Hamgyong", Code: "NH", NumericCode: 7, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "South Hamgyong", Code: "SH", NumericCode: 8, IsActive: true, CountryID: northKoreaCountry.ID},
			{Name: "Ryanggang", Code: "RY", NumericCode: 9, IsActive: true, CountryID: northKoreaCountry.ID},
		}
	}

	// Create provinces for Taiwan
	var taiwanProvinces []models.Province
	if taiwanCountry.ID != "" {
		taiwanProvinces = []models.Province{
			{Name: "Taipei", Code: "TP", NumericCode: 1, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "New Taipei", Code: "NT", NumericCode: 2, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Taoyuan", Code: "TY", NumericCode: 3, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Taichung", Code: "TC", NumericCode: 4, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Tainan", Code: "TN", NumericCode: 5, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Kaohsiung", Code: "KH", NumericCode: 6, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Keelung", Code: "KL", NumericCode: 7, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Hsinchu", Code: "HC", NumericCode: 8, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Chiayi", Code: "CY", NumericCode: 9, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Yilan", Code: "YL", NumericCode: 10, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Hualien", Code: "HL", NumericCode: 11, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Taitung", Code: "TT", NumericCode: 12, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Penghu", Code: "PH", NumericCode: 13, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Kinmen", Code: "KM", NumericCode: 14, IsActive: true, CountryID: taiwanCountry.ID},
			{Name: "Lienchiang", Code: "LC", NumericCode: 15, IsActive: true, CountryID: taiwanCountry.ID},
		}
	}

	// Create provinces for Hong Kong
	var hongKongProvinces []models.Province
	if hongKongCountry.ID != "" {
		hongKongProvinces = []models.Province{
			{Name: "Hong Kong Island", Code: "HK", NumericCode: 1, IsActive: true, CountryID: hongKongCountry.ID},
			{Name: "Kowloon", Code: "KL", NumericCode: 2, IsActive: true, CountryID: hongKongCountry.ID},
			{Name: "New Territories", Code: "NT", NumericCode: 3, IsActive: true, CountryID: hongKongCountry.ID},
		}
	}

	// Create provinces for Macau
	var macauProvinces []models.Province
	if macauCountry.ID != "" {
		macauProvinces = []models.Province{
			{Name: "Macau Peninsula", Code: "MP", NumericCode: 1, IsActive: true, CountryID: macauCountry.ID},
			{Name: "Taipa", Code: "TP", NumericCode: 2, IsActive: true, CountryID: macauCountry.ID},
			{Name: "Coloane", Code: "CL", NumericCode: 3, IsActive: true, CountryID: macauCountry.ID},
		}
	}

	// Create provinces for Palestine
	var palestineProvinces []models.Province
	if palestineCountry.ID != "" {
		palestineProvinces = []models.Province{
			{Name: "Gaza", Code: "GZ", NumericCode: 1, IsActive: true, CountryID: palestineCountry.ID},
			{Name: "West Bank", Code: "WB", NumericCode: 2, IsActive: true, CountryID: palestineCountry.ID},
			{Name: "East Jerusalem", Code: "EJ", NumericCode: 3, IsActive: true, CountryID: palestineCountry.ID},
		}
	}

	// Combine all provinces
	allProvinces := append([]models.Province{}, italyProvinces...)
	allProvinces = append(allProvinces, spainProvinces...)
	allProvinces = append(allProvinces, mongoliaProvinces...)
	allProvinces = append(allProvinces, nepalProvinces...)
	allProvinces = append(allProvinces, bangladeshProvinces...)
	allProvinces = append(allProvinces, sriLankaProvinces...)
	allProvinces = append(allProvinces, pakistanProvinces...)
	allProvinces = append(allProvinces, afghanistanProvinces...)
	allProvinces = append(allProvinces, bhutanProvinces...)
	allProvinces = append(allProvinces, maldivesProvinces...)
	allProvinces = append(allProvinces, usProvinces...)
	allProvinces = append(allProvinces, canadaProvinces...)
	allProvinces = append(allProvinces, japanProvinces...)
	allProvinces = append(allProvinces, australiaProvinces...)
	allProvinces = append(allProvinces, brazilProvinces...)
	allProvinces = append(allProvinces, indiaProvinces...)
	allProvinces = append(allProvinces, chinaProvinces...)
	allProvinces = append(allProvinces, indonesiaProvinces...)
	allProvinces = append(allProvinces, singaporeProvinces...)
	allProvinces = append(allProvinces, malaysiaProvinces...)
	allProvinces = append(allProvinces, philippinesProvinces...)
	allProvinces = append(allProvinces, thailandProvinces...)
	allProvinces = append(allProvinces, vietnamProvinces...)
	allProvinces = append(allProvinces, southKoreaProvinces...)
	allProvinces = append(allProvinces, russiaProvinces...)
	allProvinces = append(allProvinces, mexicoProvinces...)
	allProvinces = append(allProvinces, newZealandProvinces...)
	allProvinces = append(allProvinces, bruneiProvinces...)
	allProvinces = append(allProvinces, cambodiaProvinces...)
	allProvinces = append(allProvinces, laosProvinces...)
	allProvinces = append(allProvinces, myanmarProvinces...)
	allProvinces = append(allProvinces, timorLesteProvinces...)
	allProvinces = append(allProvinces, ukraineProvinces...)
	allProvinces = append(allProvinces, belarusProvinces...)
	allProvinces = append(allProvinces, moldovaProvinces...)
	allProvinces = append(allProvinces, romaniaProvinces...)
	allProvinces = append(allProvinces, bulgariaProvinces...)
	allProvinces = append(allProvinces, serbiaProvinces...)
	allProvinces = append(allProvinces, croatiaProvinces...)
	allProvinces = append(allProvinces, sloveniaProvinces...)
	allProvinces = append(allProvinces, slovakiaProvinces...)
	allProvinces = append(allProvinces, estoniaProvinces...)
	allProvinces = append(allProvinces, latviaProvinces...)
	allProvinces = append(allProvinces, lithuaniaProvinces...)
	allProvinces = append(allProvinces, albaniaProvinces...)
	allProvinces = append(allProvinces, northMacedoniaProvinces...)
	allProvinces = append(allProvinces, kosovoProvinces...)
	allProvinces = append(allProvinces, montenegroProvinces...)
	allProvinces = append(allProvinces, bosniaHerzegovinaProvinces...)
	allProvinces = append(allProvinces, portugalProvinces...)
	allProvinces = append(allProvinces, netherlandsProvinces...)
	allProvinces = append(allProvinces, belgiumProvinces...)
	allProvinces = append(allProvinces, switzerlandProvinces...)
	allProvinces = append(allProvinces, austriaProvinces...)
	allProvinces = append(allProvinces, swedenProvinces...)
	allProvinces = append(allProvinces, norwayProvinces...)
	allProvinces = append(allProvinces, denmarkProvinces...)
	allProvinces = append(allProvinces, finlandProvinces...)
	allProvinces = append(allProvinces, polandProvinces...)
	allProvinces = append(allProvinces, czechRepublicProvinces...)
	allProvinces = append(allProvinces, hungaryProvinces...)
	allProvinces = append(allProvinces, greeceProvinces...)
	allProvinces = append(allProvinces, turkeyProvinces...)
	allProvinces = append(allProvinces, egyptProvinces...)
	allProvinces = append(allProvinces, southAfricaProvinces...)
	allProvinces = append(allProvinces, nigeriaProvinces...)
	allProvinces = append(allProvinces, kenyaProvinces...)
	allProvinces = append(allProvinces, ghanaProvinces...)
	allProvinces = append(allProvinces, moroccoProvinces...)
	allProvinces = append(allProvinces, algeriaProvinces...)
	allProvinces = append(allProvinces, tunisiaProvinces...)
	allProvinces = append(allProvinces, ethiopiaProvinces...)
	allProvinces = append(allProvinces, argentinaProvinces...)
	allProvinces = append(allProvinces, chileProvinces...)
	allProvinces = append(allProvinces, colombiaProvinces...)
	allProvinces = append(allProvinces, peruProvinces...)
	allProvinces = append(allProvinces, venezuelaProvinces...)
	allProvinces = append(allProvinces, saudiArabiaProvinces...)
	allProvinces = append(allProvinces, uaeProvinces...)
	allProvinces = append(allProvinces, qatarProvinces...)
	allProvinces = append(allProvinces, israelProvinces...)
	allProvinces = append(allProvinces, jordanProvinces...)
	allProvinces = append(allProvinces, lebanonProvinces...)
	allProvinces = append(allProvinces, iraqProvinces...)
	allProvinces = append(allProvinces, iranProvinces...)
	allProvinces = append(allProvinces, syriaProvinces...)
	allProvinces = append(allProvinces, yemenProvinces...)
	allProvinces = append(allProvinces, omanProvinces...)
	allProvinces = append(allProvinces, kuwaitProvinces...)
	allProvinces = append(allProvinces, bahrainProvinces...)
	allProvinces = append(allProvinces, cyprusProvinces...)
	allProvinces = append(allProvinces, georgiaProvinces...)
	allProvinces = append(allProvinces, armeniaProvinces...)
	allProvinces = append(allProvinces, azerbaijanProvinces...)
	allProvinces = append(allProvinces, kazakhstanProvinces...)
	allProvinces = append(allProvinces, uzbekistanProvinces...)
	allProvinces = append(allProvinces, turkmenistanProvinces...)
	allProvinces = append(allProvinces, kyrgyzstanProvinces...)
	allProvinces = append(allProvinces, tajikistanProvinces...)
	allProvinces = append(allProvinces, northKoreaProvinces...)
	allProvinces = append(allProvinces, taiwanProvinces...)
	allProvinces = append(allProvinces, hongKongProvinces...)
	allProvinces = append(allProvinces, macauProvinces...)
	allProvinces = append(allProvinces, palestineProvinces...)
	allProvinces = append(allProvinces, papuaNewGuineaProvinces...)
	allProvinces = append(allProvinces, fijiProvinces...)
	allProvinces = append(allProvinces, solomonIslandsProvinces...)
	allProvinces = append(allProvinces, samoaProvinces...)
	allProvinces = append(allProvinces, tongaProvinces...)
	allProvinces = append(allProvinces, vanuatuProvinces...)
	allProvinces = append(allProvinces, micronesiaProvinces...)
	allProvinces = append(allProvinces, palauProvinces...)
	allProvinces = append(allProvinces, nauruProvinces...)
	allProvinces = append(allProvinces, tuvaluProvinces...)
	allProvinces = append(allProvinces, marshallIslandsProvinces...)
	allProvinces = append(allProvinces, kiribatiProvinces...)
	allProvinces = append(allProvinces, franceProvinces...)
	allProvinces = append(allProvinces, germanyProvinces...)
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
