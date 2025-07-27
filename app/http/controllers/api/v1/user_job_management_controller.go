package v1

import (
	"time"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

// UserJobManagementController handles user job assignments and career progression
type UserJobManagementController struct{}

// NewUserJobManagementController creates a new instance
func NewUserJobManagementController() *UserJobManagementController {
	return &UserJobManagementController{}
}

// AssignUserToPosition assigns a user to a job position
// @Summary Assign user to job position
// @Description Assign a user to a specific job position within an organization
// @Tags user-job-management
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param request body AssignUserRequest true "Assignment details"
// @Success 200 {object} responses.SuccessResponse{data=models.UserEmploymentHistory}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/{user_id}/job-assignment [post]
func (ujmc *UserJobManagementController) AssignUserToPosition(ctx http.Context) http.Response {
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User ID is required",
			Timestamp: time.Now(),
		})
	}

	type AssignUserRequest struct {
		OrganizationID    string   `json:"organization_id" validate:"required,ulid"`
		JobPositionID     *string  `json:"job_position_id" validate:"omitempty,ulid"`
		JobLevelID        *string  `json:"job_level_id" validate:"omitempty,ulid"`
		DepartmentID      *string  `json:"department_id" validate:"omitempty,ulid"`
		TeamID            *string  `json:"team_id" validate:"omitempty,ulid"`
		ManagerID         *string  `json:"manager_id" validate:"omitempty,ulid"`
		JobTitle          string   `json:"job_title" validate:"required"`
		EmployeeID        string   `json:"employee_id"`
		EmploymentType    string   `json:"employment_type" validate:"required"`
		ChangeType        string   `json:"change_type" validate:"required"`
		ChangeReason      string   `json:"change_reason"`
		EffectiveDate     string   `json:"effective_date" validate:"required"`
		Salary            string   `json:"salary"`
		Currency          string   `json:"currency"`
		PerformanceRating *float64 `json:"performance_rating"`
		Notes             string   `json:"notes"`
	}

	var request AssignUserRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Validate user exists
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	// Parse effective date
	effectiveDate, err := time.Parse("2006-01-02", request.EffectiveDate)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid effective date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	// Create employment history entry
	entry := models.UserEmploymentHistory{
		UserID:            userID,
		OrganizationID:    request.OrganizationID,
		JobPositionID:     request.JobPositionID,
		JobLevelID:        request.JobLevelID,
		DepartmentID:      request.DepartmentID,
		TeamID:            request.TeamID,
		ManagerID:         request.ManagerID,
		JobTitle:          request.JobTitle,
		EmployeeID:        request.EmployeeID,
		EmploymentType:    request.EmploymentType,
		ChangeType:        request.ChangeType,
		ChangeReason:      request.ChangeReason,
		EffectiveDate:     effectiveDate,
		IsCurrent:         true,
		Salary:            request.Salary,
		Currency:          request.Currency,
		PerformanceRating: request.PerformanceRating,
		Notes:             request.Notes,
	}

	// Create the employment history entry
	if err := user.CreateEmploymentHistoryEntry(entry); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to assign user to position: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update user organization record
	var userOrg models.UserOrganization
	err = facades.Orm().Query().
		Where("user_id", userID).
		Where("organization_id", request.OrganizationID).
		First(&userOrg)

	if err != nil {
		// Create new user organization record
		userOrg = models.UserOrganization{
			UserID:         userID,
			OrganizationID: request.OrganizationID,
			Role:           "member",
			Status:         "active",
			IsActive:       true,
			JoinedAt:       effectiveDate,
			Title:          request.JobTitle,
			EmployeeID:     request.EmployeeID,
			DepartmentID:   request.DepartmentID,
			JobPositionID:  request.JobPositionID,
			JobLevelID:     request.JobLevelID,
			TeamID:         request.TeamID,
			ManagerID:      request.ManagerID,
			HireDate:       &effectiveDate,
			Salary:         request.Salary,
		}

		if err := facades.Orm().Query().Create(&userOrg); err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to create user organization record: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	} else {
		// Update existing record
		userOrg.JobPositionID = request.JobPositionID
		userOrg.JobLevelID = request.JobLevelID
		userOrg.DepartmentID = request.DepartmentID
		userOrg.TeamID = request.TeamID
		userOrg.ManagerID = request.ManagerID
		userOrg.Title = request.JobTitle
		userOrg.EmployeeID = request.EmployeeID
		userOrg.Salary = request.Salary

		if err := facades.Orm().Query().Save(&userOrg); err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to update user organization record: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
	}

	// Load the created entry with relationships
	var createdEntry models.UserEmploymentHistory
	facades.Orm().Query().
		Where("user_id", userID).
		Where("organization_id", request.OrganizationID).
		Where("is_current", true).
		With("Organization").
		With("JobPosition").
		With("JobLevel").
		With("Department").
		First(&createdEntry)

	return responses.SuccessResponse(ctx, "User successfully assigned to position", createdEntry)
}

// GetUserCareerProgression returns the user's career progression information
// @Summary Get user career progression
// @Description Get detailed career progression information for a user
// @Tags user-job-management
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param organization_id query string true "Organization ID"
// @Success 200 {object} responses.SuccessResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/{user_id}/career-progression [get]
func (ujmc *UserJobManagementController) GetUserCareerProgression(ctx http.Context) http.Response {
	userID := ctx.Request().Route("user_id")
	organizationID := ctx.Request().Query("organization_id")

	if userID == "" || organizationID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User ID and Organization ID are required",
			Timestamp: time.Now(),
		})
	}

	// Validate user exists
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	// Get career progression data
	progression, err := user.GetCareerProgression(organizationID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve career progression: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.SuccessResponse(ctx, "Career progression retrieved successfully", progression)
}

// GetJobAnalytics returns job analytics for the organization
// @Summary Get job analytics
// @Description Get comprehensive job analytics and reporting for an organization
// @Tags user-job-management
// @Accept json
// @Produce json
// @Param organization_id query string true "Organization ID"
// @Param report_type query string false "Report type: distribution, utilization, progression, turnover, salary" default(distribution)
// @Param time_range query int false "Time range in days for time-based reports" default(365)
// @Success 200 {object} responses.SuccessResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/job-analytics [get]
func (ujmc *UserJobManagementController) GetJobAnalytics(ctx http.Context) http.Response {
	organizationID := ctx.Request().Query("organization_id")
	reportType := ctx.Request().Query("report_type", "distribution")
	timeRange := ctx.Request().QueryInt("time_range", 365)

	if organizationID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Organization ID is required",
			Timestamp: time.Now(),
		})
	}

	analyticsService := services.NewJobAnalyticsService()
	var data map[string]interface{}
	var err error

	switch reportType {
	case "distribution":
		data, err = analyticsService.GetOrganizationJobLevelDistribution(organizationID)
	case "utilization":
		data, err = analyticsService.GetJobPositionUtilization(organizationID)
	case "progression":
		data, err = analyticsService.GetCareerProgressionAnalytics(organizationID, timeRange)
	case "turnover":
		data, err = analyticsService.GetEmployeeTurnoverByJobLevel(organizationID, timeRange)
	case "salary":
		data, err = analyticsService.GetSalaryAnalyticsByJobLevel(organizationID)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid report type. Supported types: distribution, utilization, progression, turnover, salary",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate analytics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.SuccessResponse(ctx, "Job analytics retrieved successfully", data)
}

// PromoteUser promotes a user to a higher position or level
// @Summary Promote user
// @Description Promote a user to a higher job level or position
// @Tags user-job-management
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param request body PromoteUserRequest true "Promotion details"
// @Success 200 {object} responses.SuccessResponse{data=models.UserEmploymentHistory}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /users/{user_id}/promote [post]
func (ujmc *UserJobManagementController) PromoteUser(ctx http.Context) http.Response {
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User ID is required",
			Timestamp: time.Now(),
		})
	}

	type PromoteUserRequest struct {
		OrganizationID    string   `json:"organization_id" validate:"required,ulid"`
		NewJobPositionID  *string  `json:"new_job_position_id" validate:"omitempty,ulid"`
		NewJobLevelID     *string  `json:"new_job_level_id" validate:"omitempty,ulid"`
		NewJobTitle       string   `json:"new_job_title" validate:"required"`
		EffectiveDate     string   `json:"effective_date" validate:"required"`
		PromotionReason   string   `json:"promotion_reason" validate:"required"`
		NewSalary         string   `json:"new_salary"`
		PerformanceRating *float64 `json:"performance_rating"`
		Notes             string   `json:"notes"`
	}

	var request PromoteUserRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Validate user exists
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User not found",
			Timestamp: time.Now(),
		})
	}

	// Validate promotion is valid
	if request.NewJobLevelID != nil {
		canPromote, err := user.CanBePromotedTo(request.OrganizationID, *request.NewJobLevelID)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to validate promotion: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		if !canPromote {
			return ctx.Response().Status(400).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Invalid promotion: user cannot be promoted to the specified level",
				Timestamp: time.Now(),
			})
		}
	}

	// Parse effective date
	effectiveDate, err := time.Parse("2006-01-02", request.EffectiveDate)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid effective date format. Use YYYY-MM-DD",
			Timestamp: time.Now(),
		})
	}

	// Get current position details
	currentPosition, err := user.GetCurrentJobPosition(request.OrganizationID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "User has no current position in this organization",
			Timestamp: time.Now(),
		})
	}

	// Create promotion entry
	entry := models.UserEmploymentHistory{
		UserID:            userID,
		OrganizationID:    request.OrganizationID,
		JobPositionID:     request.NewJobPositionID,
		JobLevelID:        request.NewJobLevelID,
		JobTitle:          request.NewJobTitle,
		EmploymentType:    "full_time", // Default, could be made configurable
		ChangeType:        "promotion",
		ChangeReason:      request.PromotionReason,
		EffectiveDate:     effectiveDate,
		IsCurrent:         true,
		Salary:            request.NewSalary,
		Currency:          "USD", // Default, could be made configurable
		PerformanceRating: request.PerformanceRating,
		Notes:             request.Notes,
	}

	// If no new position specified, keep current department/team info
	if currentPosition != nil {
		if request.NewJobPositionID == nil {
			entry.JobPositionID = &currentPosition.ID
		}
		entry.DepartmentID = currentPosition.DepartmentID
	}

	// Create the promotion entry
	if err := user.CreateEmploymentHistoryEntry(entry); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to promote user: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update user organization record
	var userOrg models.UserOrganization
	err = facades.Orm().Query().
		Where("user_id", userID).
		Where("organization_id", request.OrganizationID).
		First(&userOrg)

	if err == nil {
		userOrg.JobPositionID = request.NewJobPositionID
		userOrg.JobLevelID = request.NewJobLevelID
		userOrg.Title = request.NewJobTitle
		userOrg.Salary = request.NewSalary
		facades.Orm().Query().Save(&userOrg)
	}

	// Load the created entry with relationships
	var createdEntry models.UserEmploymentHistory
	facades.Orm().Query().
		Where("user_id", userID).
		Where("organization_id", request.OrganizationID).
		Where("is_current", true).
		With("Organization").
		With("JobPosition").
		With("JobLevel").
		First(&createdEntry)

	return responses.SuccessResponse(ctx, "User promoted successfully", createdEntry)
}
