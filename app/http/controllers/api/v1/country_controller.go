package v1

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type CountryController struct {
	// Dependent services
}

func NewCountryController() *CountryController {
	return &CountryController{
		// Inject services
	}
}

// Index returns all countries
// @Summary Get all countries
// @Description Retrieve a list of all countries with optional filtering and cursor-based pagination
// @Tags countries
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or code"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Country}
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries [get]
func (cc *CountryController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")

	// Build query
	query := facades.Orm().Query()

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ? OR code LIKE ? OR code3 LIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// Apply active status filter
	if isActive != "" {
		if isActive == "true" {
			query = query.Where("is_active = ?", true)
		} else if isActive == "false" {
			query = query.Where("is_active = ?", false)
		}
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid cursor format",
			Timestamp: time.Now(),
		})
	}

	var countries []models.Country
	err = query.Find(&countries)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve countries",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(countries) > limit
	if hasMore {
		countries = countries[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(countries, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   countries,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// Show returns a specific country
// @Summary Get country by ID
// @Description Retrieve a specific country by their ID
// @Tags countries
// @Accept json
// @Produce json
// @Param id path string true "Country ID"
// @Success 200 {object} responses.APIResponse{data=models.Country}
// @Failure 404 {object} responses.ErrorResponse
// @Router /countries/{id} [get]
func (cc *CountryController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var country models.Country
	err := facades.Orm().Query().Where("id = ?", id).First(&country)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Country not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      country,
		Timestamp: time.Now(),
	})
}

// Store creates a new country
// @Summary Create a new country
// @Description Create a new country with the provided information
// @Tags countries
// @Accept json
// @Produce json
// @Param country body requests.CreateCountryRequest true "Country information"
// @Success 201 {object} responses.APIResponse{data=models.Country}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries [post]
func (cc *CountryController) Store(ctx http.Context) http.Response {
	var request requests.CreateCountryRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	country := models.Country{
		Name:        request.Name,
		Code:        request.Code,
		Code3:       request.Code3,
		NumericCode: request.NumericCode,
		IsActive:    request.IsActive,
	}
	country.ID = helpers.GenerateULID()

	err := facades.Orm().Query().Create(&country)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create country",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      country,
		Timestamp: time.Now(),
	})
}

// Update updates an existing country
// @Summary Update a country
// @Description Update an existing country with the provided information
// @Tags countries
// @Accept json
// @Produce json
// @Param id path string true "Country ID"
// @Param country body requests.UpdateCountryRequest true "Country information"
// @Success 200 {object} responses.APIResponse{data=models.Country}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries/{id} [put]
func (cc *CountryController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	var request requests.UpdateCountryRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	var country models.Country
	err := facades.Orm().Query().Where("id = ?", id).First(&country)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Country not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		country.Name = request.Name
	}
	if request.Code != "" {
		country.Code = request.Code
	}
	if request.Code3 != "" {
		country.Code3 = request.Code3
	}
	if request.NumericCode != "" {
		country.NumericCode = request.NumericCode
	}
	country.IsActive = request.IsActive

	err = facades.Orm().Query().Save(&country)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update country",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      country,
		Timestamp: time.Now(),
	})
}

// Delete removes a country
// @Summary Delete a country
// @Description Remove a country from the system
// @Tags countries
// @Accept json
// @Produce json
// @Param id path string true "Country ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries/{id} [delete]
func (cc *CountryController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var country models.Country
	err := facades.Orm().Query().Where("id = ?", id).First(&country)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Country not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&country)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete country",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Country deleted successfully",
		Timestamp: time.Now(),
	})
}

// BulkDelete removes multiple countries
// @Summary Delete multiple countries
// @Description Remove multiple countries from the system
// @Tags countries
// @Accept json
// @Produce json
// @Param ids body []string true "Array of country IDs"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries/bulk-delete [post]
func (cc *CountryController) BulkDelete(ctx http.Context) http.Response {
	var request struct {
		IDs []string `json:"ids" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	if len(request.IDs) == 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "No country IDs provided",
			Timestamp: time.Now(),
		})
	}

	_, err := facades.Orm().Query().Where("id IN ?", request.IDs).Delete(&models.Country{})
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete countries",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Successfully deleted %d countries", len(request.IDs)),
		Timestamp: time.Now(),
	})
}

// ToggleActive toggles the active status of a country
// @Summary Toggle country active status
// @Description Toggle the active status of a country
// @Tags countries
// @Accept json
// @Produce json
// @Param id path string true "Country ID"
// @Success 200 {object} responses.APIResponse{data=models.Country}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /countries/{id}/toggle-active [patch]
func (cc *CountryController) ToggleActive(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var country models.Country
	err := facades.Orm().Query().Where("id = ?", id).First(&country)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Country not found",
			Timestamp: time.Now(),
		})
	}

	// Toggle the active status
	country.IsActive = !country.IsActive

	err = facades.Orm().Query().Save(&country)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update country",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      country,
		Message:   fmt.Sprintf("Country %s status updated", country.Name),
		Timestamp: time.Now(),
	})
}

// Provinces returns all provinces for a specific country
// @Summary Get provinces by country
// @Description Retrieve all provinces for a specific country
// @Tags countries
// @Accept json
// @Produce json
// @Param id path string true "Country ID"
// @Success 200 {object} responses.APIResponse{data=[]models.Province}
// @Failure 404 {object} responses.ErrorResponse
// @Router /countries/{id}/provinces [get]
func (cc *CountryController) Provinces(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var country models.Country
	err := facades.Orm().Query().Where("id = ?", id).First(&country)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Country not found",
			Timestamp: time.Now(),
		})
	}

	var provinces []models.Province
	err = facades.Orm().Query().Where("country_id = ?", id).Find(&provinces)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve provinces",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      provinces,
		Timestamp: time.Now(),
	})
}
