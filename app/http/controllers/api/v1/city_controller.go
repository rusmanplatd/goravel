package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
)

type CityController struct {
	// Dependent services
}

func NewCityController() *CityController {
	return &CityController{
		// Inject services
	}
}

// Index returns all cities
// @Summary Get all cities
// @Description Retrieve a list of all cities with optional filtering and cursor-based pagination
// @Tags cities
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or code"
// @Param is_active query bool false "Filter by active status"
// @Param province_id query string false "Filter by province ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.City}
// @Failure 500 {object} responses.ErrorResponse
// @Router /cities [get]
func (cc *CityController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")
	provinceID := ctx.Request().Input("province_id", "")

	// Build query
	query := facades.Orm().Query()

	// Apply search filter
	if search != "" {
		query = query.Where("name LIKE ? OR code LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	// Apply active status filter
	if isActive != "" {
		if isActive == "true" {
			query = query.Where("is_active = ?", true)
		} else if isActive == "false" {
			query = query.Where("is_active = ?", false)
		}
	}

	// Apply province filter
	if provinceID != "" {
		query = query.Where("province_id = ?", provinceID)
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

	var cities []models.City
	err = query.Find(&cities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve cities",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(cities) > limit
	if hasMore {
		cities = cities[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(cities, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   cities,
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

// Show returns a specific city
// @Summary Get city by ID
// @Description Retrieve a specific city by their ID
// @Tags cities
// @Accept json
// @Produce json
// @Param id path string true "City ID"
// @Success 200 {object} responses.APIResponse{data=models.City}
// @Failure 404 {object} responses.ErrorResponse
// @Router /cities/{id} [get]
func (cc *CityController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var city models.City
	err := facades.Orm().Query().Where("id = ?", id).First(&city)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "City not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      city,
		Timestamp: time.Now(),
	})
}

// Store creates a new city
// @Summary Create a new city
// @Description Create a new city with the provided information
// @Tags cities
// @Accept json
// @Produce json
// @Param city body requests.CreateCityRequest true "City information"
// @Success 201 {object} responses.APIResponse{data=models.City}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /cities [post]
func (cc *CityController) Store(ctx http.Context) http.Response {
	var request requests.CreateCityRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	city := models.City{
		Name:       request.Name,
		Code:       request.Code,
		IsActive:   request.IsActive,
		ProvinceID: request.ProvinceID,
	}
	city.ID = helpers.GenerateULID()

	err := facades.Orm().Query().Create(&city)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create city",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      city,
		Timestamp: time.Now(),
	})
}

// Update updates an existing city
// @Summary Update a city
// @Description Update an existing city with the provided information
// @Tags cities
// @Accept json
// @Produce json
// @Param id path string true "City ID"
// @Param city body requests.UpdateCityRequest true "City information"
// @Success 200 {object} responses.APIResponse{data=models.City}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /cities/{id} [put]
func (cc *CityController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	var request requests.UpdateCityRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	var city models.City
	err := facades.Orm().Query().Where("id = ?", id).First(&city)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "City not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		city.Name = request.Name
	}
	if request.Code != "" {
		city.Code = request.Code
	}
	if request.ProvinceID != "" {
		city.ProvinceID = request.ProvinceID
	}
	city.IsActive = request.IsActive

	err = facades.Orm().Query().Save(&city)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update city",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      city,
		Timestamp: time.Now(),
	})
}

// Delete removes a city
// @Summary Delete a city
// @Description Remove a city from the system
// @Tags cities
// @Accept json
// @Produce json
// @Param id path string true "City ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /cities/{id} [delete]
func (cc *CityController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var city models.City
	err := facades.Orm().Query().Where("id = ?", id).First(&city)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "City not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&city)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete city",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "City deleted successfully",
		Timestamp: time.Now(),
	})
}

// Districts returns all districts for a specific city
// @Summary Get districts by city
// @Description Retrieve all districts for a specific city
// @Tags cities
// @Accept json
// @Produce json
// @Param id path string true "City ID"
// @Success 200 {object} responses.APIResponse{data=[]models.District}
// @Failure 404 {object} responses.ErrorResponse
// @Router /cities/{id}/districts [get]
func (cc *CityController) Districts(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var city models.City
	err := facades.Orm().Query().Where("id = ?", id).First(&city)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "City not found",
			Timestamp: time.Now(),
		})
	}

	var districts []models.District
	err = facades.Orm().Query().Where("city_id = ?", id).Find(&districts)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve districts",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      districts,
		Timestamp: time.Now(),
	})
}
