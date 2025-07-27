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

// JobPositionRequest represents the request data for job position operations
type JobPositionRequest struct {
	Title               string                  `json:"title" validate:"required,min=2,max=255"`
	Description         string                  `json:"description" validate:"omitempty,max=2000"`
	Code                *string                 `json:"code" validate:"omitempty,min=1,max=10"`
	Color               *string                 `json:"color" validate:"omitempty,hexcolor"`
	Icon                *string                 `json:"icon" validate:"omitempty,max=50"`
	IsActive            bool                    `json:"is_active"`
	IsRemote            bool                    `json:"is_remote"`
	EmploymentType      string                  `json:"employment_type" validate:"omitempty,oneof=full_time part_time contract intern"`
	MinSalary           *float64                `json:"min_salary" validate:"omitempty,min=0"`
	MaxSalary           *float64                `json:"max_salary" validate:"omitempty,min=0"`
	Currency            string                  `json:"currency" validate:"omitempty,len=3"`
	Requirements        *map[string]interface{} `json:"requirements"`
	Responsibilities    *map[string]interface{} `json:"responsibilities"`
	Benefits            *map[string]interface{} `json:"benefits"`
	JobLevelID          string                  `json:"job_level_id" validate:"required,ulid"`
	DepartmentID        *string                 `json:"department_id" validate:"omitempty,ulid"`
	OrganizationID      string                  `json:"organization_id" validate:"required,ulid"`
	ReportsToPositionID *string                 `json:"reports_to_position_id" validate:"omitempty,ulid"`
	Headcount           int                     `json:"headcount" validate:"omitempty,min=1"`
	FilledCount         int                     `json:"filled_count" validate:"omitempty,min=0"`
}

type JobPositionController struct {
	// Dependent services
}

func NewJobPositionController() *JobPositionController {
	return &JobPositionController{
		// Inject services
	}
}

// Index returns all job positions
// @Summary Get all job positions
// @Description Retrieve a list of all job positions with filtering, sorting and pagination. Supports both offset and cursor pagination via pagination_type parameter.
// @Tags job-positions
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[title] query string false "Filter by title (partial match)"
// @Param filter[code] query string false "Filter by code (partial match)"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[is_remote] query bool false "Filter by remote work support"
// @Param filter[employment_type] query string false "Filter by employment type"
// @Param filter[job_level_id] query string false "Filter by job level ID"
// @Param filter[department_id] query string false "Filter by department ID"
// @Param filter[organization_id] query string false "Filter by organization ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Param include query string false "Include relationships (comma-separated): job_level,department,organization,reports_to_position"
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.JobPosition}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-positions [get]
func (jpc *JobPositionController) Index(ctx http.Context) http.Response {
	var jobPositions []models.JobPosition

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.JobPosition{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("title"),
			querybuilder.Partial("code"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_remote"),
			querybuilder.Exact("employment_type"),
			querybuilder.Exact("job_level_id"),
			querybuilder.Exact("department_id"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("title", "code", "created_at", "updated_at").
		AllowedIncludes("job_level", "department", "organization", "reports_to_position").
		DefaultSort("-created_at")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&jobPositions)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve job positions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Job positions retrieved successfully", result)
}

// Show returns a specific job position
// @Summary Get job position by ID
// @Description Retrieve a specific job position by its ID
// @Tags job-positions
// @Accept json
// @Produce json
// @Param id path string true "Job Position ID"
// @Param include query string false "Include relationships (comma-separated): job_level,department,organization,reports_to_position"
// @Success 200 {object} responses.APIResponse{data=models.JobPosition}
// @Failure 404 {object} responses.ErrorResponse
// @Router /job-positions/{id} [get]
func (jpc *JobPositionController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var jobPosition models.JobPosition
	query := facades.Orm().Query()

	// Handle includes
	includes := ctx.Request().Query("include", "")
	if includes != "" {
		for _, include := range []string{"job_level", "department", "organization", "reports_to_position"} {
			if strings.Contains(includes, include) {
				query = query.With(include)
			}
		}
	}

	err := query.Where("id = ?", id).First(&jobPosition)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job position not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      jobPosition,
		Timestamp: time.Now(),
	})
}

// Store creates a new job position
// @Summary Create a new job position
// @Description Create a new job position with the provided information
// @Tags job-positions
// @Accept json
// @Produce json
// @Param job_position body JobPositionRequest true "Job position information"
// @Success 201 {object} responses.APIResponse{data=models.JobPosition}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-positions [post]
func (jpc *JobPositionController) Store(ctx http.Context) http.Response {
	var request JobPositionRequest

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

	jobPosition := models.JobPosition{
		Title:               request.Title,
		Description:         request.Description,
		Code:                request.Code,
		Color:               request.Color,
		Icon:                request.Icon,
		IsActive:            request.IsActive,
		IsRemote:            request.IsRemote,
		EmploymentType:      request.EmploymentType,
		MinSalary:           request.MinSalary,
		MaxSalary:           request.MaxSalary,
		Currency:            request.Currency,
		JobLevelID:          request.JobLevelID,
		DepartmentID:        request.DepartmentID,
		OrganizationID:      request.OrganizationID,
		ReportsToPositionID: request.ReportsToPositionID,
		Headcount:           request.Headcount,
		FilledCount:         request.FilledCount,
	}

	// Set JSON fields
	if request.Requirements != nil {
		if err := jobPosition.SetRequirements(*request.Requirements); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid requirements format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Responsibilities != nil {
		if err := jobPosition.SetResponsibilities(*request.Responsibilities); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid responsibilities format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Benefits != nil {
		if err := jobPosition.SetBenefits(*request.Benefits); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid benefits format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Set creator
	userIDStr := userID.(string)
	jobPosition.CreatedBy = &userIDStr

	err := facades.Orm().Query().Create(&jobPosition)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create job position: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      jobPosition,
		Message:   "Job position created successfully",
		Timestamp: time.Now(),
	})
}

// Update updates an existing job position
// @Summary Update a job position
// @Description Update an existing job position's information
// @Tags job-positions
// @Accept json
// @Produce json
// @Param id path string true "Job Position ID"
// @Param job_position body JobPositionRequest true "Updated job position information"
// @Success 200 {object} responses.APIResponse{data=models.JobPosition}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-positions/{id} [put]
func (jpc *JobPositionController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request JobPositionRequest
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

	var jobPosition models.JobPosition
	err := facades.Orm().Query().Where("id = ?", id).First(&jobPosition)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job position not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields
	jobPosition.Title = request.Title
	jobPosition.Description = request.Description
	jobPosition.Code = request.Code
	jobPosition.Color = request.Color
	jobPosition.Icon = request.Icon
	jobPosition.IsActive = request.IsActive
	jobPosition.IsRemote = request.IsRemote
	jobPosition.EmploymentType = request.EmploymentType
	jobPosition.MinSalary = request.MinSalary
	jobPosition.MaxSalary = request.MaxSalary
	jobPosition.Currency = request.Currency
	jobPosition.JobLevelID = request.JobLevelID
	jobPosition.DepartmentID = request.DepartmentID
	jobPosition.OrganizationID = request.OrganizationID
	jobPosition.ReportsToPositionID = request.ReportsToPositionID
	jobPosition.Headcount = request.Headcount
	jobPosition.FilledCount = request.FilledCount

	// Set JSON fields
	if request.Requirements != nil {
		if err := jobPosition.SetRequirements(*request.Requirements); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid requirements format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Responsibilities != nil {
		if err := jobPosition.SetResponsibilities(*request.Responsibilities); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid responsibilities format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	if request.Benefits != nil {
		if err := jobPosition.SetBenefits(*request.Benefits); err != nil {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid benefits format: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Set updater
	userIDStr := userID.(string)
	jobPosition.UpdatedBy = &userIDStr

	err = facades.Orm().Query().Save(&jobPosition)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update job position: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      jobPosition,
		Message:   "Job position updated successfully",
		Timestamp: time.Now(),
	})
}

// Destroy deletes a job position
// @Summary Delete a job position
// @Description Delete a job position by its ID (soft delete)
// @Tags job-positions
// @Accept json
// @Produce json
// @Param id path string true "Job Position ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /job-positions/{id} [delete]
func (jpc *JobPositionController) Destroy(ctx http.Context) http.Response {
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

	var jobPosition models.JobPosition
	err := facades.Orm().Query().Where("id = ?", id).First(&jobPosition)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Job position not found",
			Timestamp: time.Now(),
		})
	}

	// Set deleter
	userIDStr := userID.(string)
	jobPosition.DeletedBy = &userIDStr

	// Soft delete
	_, err = facades.Orm().Query().Delete(&jobPosition)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete job position: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Job position deleted successfully",
		Timestamp: time.Now(),
	})
}
