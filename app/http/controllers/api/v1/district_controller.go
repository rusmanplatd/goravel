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

type DistrictController struct {
	// Dependent services
}

func NewDistrictController() *DistrictController {
	return &DistrictController{
		// Inject services
	}
}

// Index returns all districts
// @Summary Get all districts
// @Description Retrieve a list of all districts with optional filtering and cursor-based pagination
// @Tags districts
// @Accept json
// @Produce json
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(10)
// @Param search query string false "Search by name or code"
// @Param is_active query bool false "Filter by active status"
// @Param city_id query string false "Filter by city ID"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.District}
// @Failure 500 {object} responses.ErrorResponse
// @Router /districts [get]
func (dc *DistrictController) Index(ctx http.Context) http.Response {
	// Get query parameters
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 10)
	search := ctx.Request().Input("search", "")
	isActive := ctx.Request().Input("is_active", "")
	cityID := ctx.Request().Input("city_id", "")

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

	// Apply city filter
	if cityID != "" {
		query = query.Where("city_id = ?", cityID)
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

	var districts []models.District
	err = query.Find(&districts)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve districts",
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(districts) > limit
	if hasMore {
		districts = districts[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(districts, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   districts,
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

// Show returns a specific district
// @Summary Get district by ID
// @Description Retrieve a specific district by their ID
// @Tags districts
// @Accept json
// @Produce json
// @Param id path string true "District ID"
// @Success 200 {object} responses.APIResponse{data=models.District}
// @Failure 404 {object} responses.ErrorResponse
// @Router /districts/{id} [get]
func (dc *DistrictController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var district models.District
	err := facades.Orm().Query().Where("id = ?", id).First(&district)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "District not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      district,
		Timestamp: time.Now(),
	})
}

// Store creates a new district
// @Summary Create a new district
// @Description Create a new district with the provided information
// @Tags districts
// @Accept json
// @Produce json
// @Param district body requests.CreateDistrictRequest true "District information"
// @Success 201 {object} responses.APIResponse{data=models.District}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /districts [post]
func (dc *DistrictController) Store(ctx http.Context) http.Response {
	var request requests.CreateDistrictRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	district := models.District{
		Name:     request.Name,
		Code:     request.Code,
		IsActive: request.IsActive,
		CityID:   request.CityID,
	}
	district.ID = helpers.GenerateULID()

	err := facades.Orm().Query().Create(&district)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create district",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      district,
		Timestamp: time.Now(),
	})
}

// Update updates an existing district
// @Summary Update a district
// @Description Update an existing district with the provided information
// @Tags districts
// @Accept json
// @Produce json
// @Param id path string true "District ID"
// @Param district body requests.UpdateDistrictRequest true "District information"
// @Success 200 {object} responses.APIResponse{data=models.District}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /districts/{id} [put]
func (dc *DistrictController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")
	var request requests.UpdateDistrictRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data",
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	var district models.District
	err := facades.Orm().Query().Where("id = ?", id).First(&district)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "District not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields if provided
	if request.Name != "" {
		district.Name = request.Name
	}
	if request.Code != "" {
		district.Code = request.Code
	}
	if request.CityID != "" {
		district.CityID = request.CityID
	}
	district.IsActive = request.IsActive

	err = facades.Orm().Query().Save(&district)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update district",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      district,
		Timestamp: time.Now(),
	})
}

// Delete removes a district
// @Summary Delete a district
// @Description Remove a district from the system
// @Tags districts
// @Accept json
// @Produce json
// @Param id path string true "District ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /districts/{id} [delete]
func (dc *DistrictController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var district models.District
	err := facades.Orm().Query().Where("id = ?", id).First(&district)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "District not found",
			Timestamp: time.Now(),
		})
	}

	_, err = facades.Orm().Query().Delete(&district)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete district",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "District deleted successfully",
		Timestamp: time.Now(),
	})
}
