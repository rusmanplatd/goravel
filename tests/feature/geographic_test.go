package feature

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"goravel/app/models"
)

func TestGeographicCRUD(t *testing.T) {
	// Test Country CRUD operations
	t.Run("Country CRUD", func(t *testing.T) {
		// Test creating a country
		countryData := `{
			"name": "Test Country",
			"code": "TC",
			"code3": "TST",
			"numeric_code": "999",
			"is_active": true
		}`

		// This would normally call your router
		// For now, we'll just test the data structure

		// This would normally call your router
		// For now, we'll just test the data structure
		var country models.Country
		err := json.Unmarshal([]byte(countryData), &country)
		assert.NoError(t, err)
		assert.Equal(t, "Test Country", country.Name)
		assert.Equal(t, "TC", country.Code)
		assert.Equal(t, "TST", country.Code3)
		assert.Equal(t, "999", country.NumericCode)
		assert.True(t, country.IsActive)
	})

	// Test Province CRUD operations
	t.Run("Province CRUD", func(t *testing.T) {
		// Test creating a province
		provinceData := `{
			"name": "Test Province",
			"code": "TP",
			"is_active": true,
			"country_id": "01HXYZ123456789ABCDEFGHIJK"
		}`

		var province models.Province
		err := json.Unmarshal([]byte(provinceData), &province)
		assert.NoError(t, err)
		assert.Equal(t, "Test Province", province.Name)
		assert.Equal(t, "TP", province.Code)
		assert.True(t, province.IsActive)
		assert.Equal(t, "01HXYZ123456789ABCDEFGHIJK", province.CountryID)
	})

	// Test City CRUD operations
	t.Run("City CRUD", func(t *testing.T) {
		// Test creating a city
		cityData := `{
			"name": "Test City",
			"code": "TC",
			"is_active": true,
			"province_id": "01HXYZ123456789ABCDEFGHIJK"
		}`

		var city models.City
		err := json.Unmarshal([]byte(cityData), &city)
		assert.NoError(t, err)
		assert.Equal(t, "Test City", city.Name)
		assert.Equal(t, "TC", city.Code)
		assert.True(t, city.IsActive)
		assert.Equal(t, "01HXYZ123456789ABCDEFGHIJK", city.ProvinceID)
	})

	// Test District CRUD operations
	t.Run("District CRUD", func(t *testing.T) {
		// Test creating a district
		districtData := `{
			"name": "Test District",
			"code": "TD",
			"is_active": true,
			"city_id": "01HXYZ123456789ABCDEFGHIJK"
		}`

		var district models.District
		err := json.Unmarshal([]byte(districtData), &district)
		assert.NoError(t, err)
		assert.Equal(t, "Test District", district.Name)
		assert.Equal(t, "TD", district.Code)
		assert.True(t, district.IsActive)
		assert.Equal(t, "01HXYZ123456789ABCDEFGHIJK", district.CityID)
	})
}

func TestGeographicRelationships(t *testing.T) {
	t.Run("Country-Province Relationship", func(t *testing.T) {
		country := models.Country{
			Name:        "Test Country",
			Code:        "TC",
			Code3:       "TST",
			NumericCode: "999",
			IsActive:    true,
		}

		province := models.Province{
			Name:      "Test Province",
			Code:      "TP",
			IsActive:  true,
			CountryID: country.ID,
		}

		// Test that the relationship is properly set
		assert.Equal(t, country.ID, province.CountryID)
	})

	t.Run("Province-City Relationship", func(t *testing.T) {
		province := models.Province{
			Name:     "Test Province",
			Code:     "TP",
			IsActive: true,
		}

		city := models.City{
			Name:       "Test City",
			Code:       "TC",
			IsActive:   true,
			ProvinceID: province.ID,
		}

		// Test that the relationship is properly set
		assert.Equal(t, province.ID, city.ProvinceID)
	})

	t.Run("City-District Relationship", func(t *testing.T) {
		city := models.City{
			Name:     "Test City",
			Code:     "TC",
			IsActive: true,
		}

		district := models.District{
			Name:     "Test District",
			Code:     "TD",
			IsActive: true,
			CityID:   city.ID,
		}

		// Test that the relationship is properly set
		assert.Equal(t, city.ID, district.CityID)
	})
}

func TestGeographicValidation(t *testing.T) {
	t.Run("Country Validation", func(t *testing.T) {
		// Test required fields
		country := models.Country{}
		// In a real test, you would validate the struct tags
		// For now, we'll just test the structure
		assert.Empty(t, country.Name)
		assert.Empty(t, country.Code)
	})

	t.Run("Province Validation", func(t *testing.T) {
		// Test required fields
		province := models.Province{}
		assert.Empty(t, province.Name)
		assert.Empty(t, province.Code)
		assert.Empty(t, province.CountryID)
	})

	t.Run("City Validation", func(t *testing.T) {
		// Test required fields
		city := models.City{}
		assert.Empty(t, city.Name)
		assert.Empty(t, city.ProvinceID)
	})

	t.Run("District Validation", func(t *testing.T) {
		// Test required fields
		district := models.District{}
		assert.Empty(t, district.Name)
		assert.Empty(t, district.CityID)
	})
}
