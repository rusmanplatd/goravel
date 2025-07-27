package v1

import (
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

// JobLevelRequest represents the request data for job level operations
type JobLevelRequest struct {
	Name           string                  `json:"name" validate:"required,min=2,max=255"`
	Description    string                  `json:"description" validate:"omitempty,max=1000"`
	LevelOrder     int                     `json:"level_order" validate:"required,min=1"`
	Code           *string                 `json:"code" validate:"omitempty,min=1,max=10"`
	Color          *string                 `json:"color" validate:"omitempty,hexcolor"`
	Icon           *string                 `json:"icon" validate:"omitempty,max=50"`
	IsActive       bool                    `json:"is_active"`
	MinSalary      *float64                `json:"min_salary" validate:"omitempty,min=0"`
	MaxSalary      *float64                `json:"max_salary" validate:"omitempty,min=0"`
	Currency       string                  `json:"currency" validate:"omitempty,len=3"`
	Requirements   *map[string]interface{} `json:"requirements"`
	Benefits       *map[string]interface{} `json:"benefits"`
	OrganizationID string                  `json:"organization_id" validate:"required,ulid"`
}

type JobLevelController struct {
	// Dependent services
}

func NewJobLevelController() *JobLevelController {
	return &JobLevelController{
		// Inject services
	}
}

// Index returns all job levels
// @Summary Get all job levels
// @Description Retrieve a list of all job levels with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags job-levels
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by name (partial match)"
// @Param filter[code] query string false "Filter by code (partial match)"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[organization_id] query string false "Filter by organization ID"
// @Param filter[level_order] query int false "Filter by level order"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): organization"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.JobLevel}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-levels [get]
func (jlc *JobLevelController) Index(ctx http.Context) http.Response {
	var jobLevels []models.JobLevel

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.JobLevel{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Partial("code"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("organization_id"),
			querybuilder.Exact("level_order"),
		).
		AllowedSorts("name", "code", "level_order", "created_at", "updated_at").
		AllowedIncludes("organization").
		DefaultSort("level_order")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&jobLevels)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve job levels: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Job levels retrieved successfully", result)
}

// Show returns a specific job level
// @Summary Get job level by ID
// @Description Retrieve a specific job level by its ID
// @Tags job-levels
// @Accept json
// @Produce json
// @Param id path string true "Job Level ID"
// @Param include query string false "Include relationships (comma-separated): organization"
// @Success 200 {object} responses.APIResponse{data=models.JobLevel}
// @Failure 404 {object} responses.ErrorResponse
// @Router /job-levels/{id} [get]
func (jlc *JobLevelController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var jobLevel models.JobLevel
	query := facades.Orm().Query()

	// Handle includes
	includes := ctx.Request().Query("include", "")
	if includes != "" {
		for _, include := range []string{"organization"} {
			if strings.Contains(includes, include) {
				query = query.With(include)
			}
		}
	}

	err := query.Where("id = ?", id).First(&jobLevel)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job level not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      jobLevel,
		Timestamp: time.Now(),
	})
}

// Store creates a new job level
// @Summary Create a new job level
// @Description Create a new job level with the provided information
// @Tags job-levels
// @Accept json
// @Produce json
// @Param job_level body JobLevelRequest true "Job level information"
// @Success 201 {object} responses.APIResponse{data=models.JobLevel}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-levels [post]
func (jlc *JobLevelController) Store(ctx http.Context) http.Response {
	var request JobLevelRequest

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data: " + err.Error(),
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	// Get current user for created_by
	userID := ctx.Value("user_id")
	if userID == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	jobLevel := models.JobLevel{
		Name:           request.Name,
		Description:    request.Description,
		LevelOrder:     request.LevelOrder,
		Code:           request.Code,
		Color:          request.Color,
		Icon:           request.Icon,
		IsActive:       request.IsActive,
		MinSalary:      request.MinSalary,
		MaxSalary:      request.MaxSalary,
		Currency:       request.Currency,
		OrganizationID: request.OrganizationID,
	}

	// Set JSON fields
	if request.Requirements != nil {
		if err := jobLevel.SetRequirements(*request.Requirements); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid requirements format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Benefits != nil {
		if err := jobLevel.SetBenefits(*request.Benefits); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid benefits format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Set creator
	userIDStr := userID.(string)
	jobLevel.CreatedBy = &userIDStr

	err := facades.Orm().Query().Create(&jobLevel)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create job level: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      jobLevel,
		Message:   "Job level created successfully",
		Timestamp: time.Now(),
	})
}

// Update updates an existing job level
// @Summary Update a job level
// @Description Update an existing job level's information
// @Tags job-levels
// @Accept json
// @Produce json
// @Param id path string true "Job Level ID"
// @Param job_level body JobLevelRequest true "Updated job level information"
// @Success 200 {object} responses.APIResponse{data=models.JobLevel}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-levels/{id} [put]
func (jlc *JobLevelController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request JobLevelRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid input data: " + err.Error(),
			Code:      "VALIDATION_ERROR",
			Timestamp: time.Now(),
		})
	}

	// Get current user for updated_by
	userID := ctx.Value("user_id")
	if userID == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	var jobLevel models.JobLevel
	err := facades.Orm().Query().Where("id = ?", id).First(&jobLevel)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job level not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields
	jobLevel.Name = request.Name
	jobLevel.Description = request.Description
	jobLevel.LevelOrder = request.LevelOrder
	jobLevel.Code = request.Code
	jobLevel.Color = request.Color
	jobLevel.Icon = request.Icon
	jobLevel.IsActive = request.IsActive
	jobLevel.MinSalary = request.MinSalary
	jobLevel.MaxSalary = request.MaxSalary
	jobLevel.Currency = request.Currency
	jobLevel.OrganizationID = request.OrganizationID

	// Set JSON fields
	if request.Requirements != nil {
		if err := jobLevel.SetRequirements(*request.Requirements); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid requirements format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Benefits != nil {
		if err := jobLevel.SetBenefits(*request.Benefits); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid benefits format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Set updater
	userIDStr := userID.(string)
	jobLevel.UpdatedBy = &userIDStr

	err = facades.Orm().Query().Save(&jobLevel)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update job level: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      jobLevel,
		Message:   "Job level updated successfully",
		Timestamp: time.Now(),
	})
}

// Destroy deletes a job level
// @Summary Delete a job level
// @Description Delete a job level by its ID (soft delete)
// @Tags job-levels
// @Accept json
// @Produce json
// @Param id path string true "Job Level ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-levels/{id} [delete]
func (jlc *JobLevelController) Destroy(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	// Get current user for deleted_by
	userID := ctx.Value("user_id")
	if userID == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	var jobLevel models.JobLevel
	err := facades.Orm().Query().Where("id = ?", id).First(&jobLevel)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job level not found",
			Timestamp: time.Now(),
		})
	}

	// Set deleter
	userIDStr := userID.(string)
	jobLevel.DeletedBy = &userIDStr

	// Soft delete
	_, err = facades.Orm().Query().Delete(&jobLevel)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete job level: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Job level deleted successfully",
		Timestamp: time.Now(),
	})
}
