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

type ProvinceController struct {
	// Dependent services
}

func NewProvinceController() *ProvinceController {
	return &ProvinceController{
		// Inject services
	}
}

// Index returns all provinces
// @Summary Get all provinces
// @Description Retrieve a list of all provinces with optional filtering and cursor-based pagination
// @Tags provinces
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or code"
// @Param is_active query bool false "Filter by active status"
// @Param country_id query string false "Filter by country ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Province}
// @Failure 500 {object} responses.ErrorResponse
// @Router /provinces [get]
func (pc *ProvinceController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")
	countryID := ctx.Request().Input("country_id", "")

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

	// Apply country filter
	if countryID != "" {
		query = query.Where("country_id = ?", countryID)
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

	var provinces []models.Province
	err = query.Find(&provinces)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve provinces",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(provinces) > limit
	if hasMore {
		provinces = provinces[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(provinces, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   provinces,
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

// Show returns a specific province
// @Summary Get province by ID
// @Description Retrieve a specific province by their ID
// @Tags provinces
// @Accept json
// @Produce json
// @Param id path string true "Province ID"
// @Success 200 {object} responses.APIResponse{data=models.Province}
// @Failure 404 {object} responses.ErrorResponse
// @Router /provinces/{id} [get]
func (pc *ProvinceController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var province models.Province
	err := facades.Orm().Query().Where("id = ?", id).First(&province)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Province not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      province,
		Timestamp: time.Now(),
	})
}

// Store creates a new province
// @Summary Create a new province
// @Description Create a new province with the provided information
// @Tags provinces
// @Accept json
// @Produce json
// @Param province body requests.CreateProvinceRequest true "Province information"
// @Success 201 {object} responses.APIResponse{data=models.Province}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /provinces [post]
func (pc *ProvinceController) Store(ctx http.Context) http.Response {
	var request requests.CreateProvinceRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	province := models.Province{
		Name:      request.Name,
		Code:      request.Code,
		IsActive:  request.IsActive,
		CountryID: request.CountryID,
	}
	province.ID = helpers.GenerateULID()

	err := facades.Orm().Query().Create(&province)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create province",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      province,
		Timestamp: time.Now(),
	})
}

// Update updates an existing province
// @Summary Update a province
// @Description Update an existing province with the provided information
// @Tags provinces
// @Accept json
// @Produce json
// @Param id path string true "Province ID"
// @Param province body requests.UpdateProvinceRequest true "Province information"
// @Success 200 {object} responses.APIResponse{data=models.Province}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /provinces/{id} [put]
func (pc *ProvinceController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	var request requests.UpdateProvinceRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	var province models.Province
	err := facades.Orm().Query().Where("id = ?", id).First(&province)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Province not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		province.Name = request.Name
	}
	if request.Code != "" {
		province.Code = request.Code
	}
	if request.CountryID != "" {
		province.CountryID = request.CountryID
	}
	province.IsActive = request.IsActive

	err = facades.Orm().Query().Save(&province)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update province",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      province,
		Timestamp: time.Now(),
	})
}

// Delete removes a province
// @Summary Delete a province
// @Description Remove a province from the system
// @Tags provinces
// @Accept json
// @Produce json
// @Param id path string true "Province ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /provinces/{id} [delete]
func (pc *ProvinceController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var province models.Province
	err := facades.Orm().Query().Where("id = ?", id).First(&province)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Province not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&province)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete province",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Province deleted successfully",
		Timestamp: time.Now(),
	})
}

// Cities returns all cities for a specific province
// @Summary Get cities by province
// @Description Retrieve all cities for a specific province
// @Tags provinces
// @Accept json
// @Produce json
// @Param id path string true "Province ID"
// @Success 200 {object} responses.APIResponse{data=[]models.City}
// @Failure 404 {object} responses.ErrorResponse
// @Router /provinces/{id}/cities [get]
func (pc *ProvinceController) Cities(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var province models.Province
	err := facades.Orm().Query().Where("id = ?", id).First(&province)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Province not found",
			Timestamp: time.Now(),
		})
	}

	var cities []models.City
	err = facades.Orm().Query().Where("province_id = ?", id).Find(&cities)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve cities",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      cities,
		Timestamp: time.Now(),
	})
}
