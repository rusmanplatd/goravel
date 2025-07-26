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
// @Description Retrieve a list of all provinces with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags provinces
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[code] query string false "Filter by code (partial match)"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[country_id] query string false "Filter by country ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("name")
// @Param include query string false "Include relationships (comma-separated): country,cities,cities.districts"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.Province}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /provinces [get]
func (pc *ProvinceController) Index(ctx http.Context) http.Response {
	var provinces []models.Province

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.Province{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("code"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("country_id"),
		).
		AllowedSorts("name", "code", "created_at", "updated_at").
		AllowedIncludes("country", "cities", "cities.districts").
		DefaultSort("name")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&provinces)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve provinces: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Provinces retrieved successfully", result)
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
