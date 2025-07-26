package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
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
// @Description Retrieve a list of all districts with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags districts
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[code] query string false "Filter by code (partial match)"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[city_id] query string false "Filter by city ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("name")
// @Param include query string false "Include relationships (comma-separated): city,city.province,city.province.country"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.District}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /districts [get]
func (dc *DistrictController) Index(ctx http.Context) http.Response {
	var districts []models.District

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.District{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("code"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("city_id"),
		).
		AllowedSorts("name", "code", "created_at", "updated_at").
		AllowedIncludes("city", "city.province", "city.province.country").
		DefaultSort("name")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&districts)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve districts: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Districts retrieved successfully", result)
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
