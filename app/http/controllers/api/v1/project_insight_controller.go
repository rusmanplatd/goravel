package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ProjectInsightController struct {
	insightService *services.ProjectInsightService
}

func NewProjectInsightController() *ProjectInsightController {
	return &ProjectInsightController{
		insightService: services.NewProjectInsightService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *ProjectInsightController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index returns project insights
// @Summary Get project insights
// @Description Retrieve insights and analytics for a project
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param type query string false "Filter by insight type"
// @Param period query string false "Filter by period"
// @Param start_date query string false "Start date filter (YYYY-MM-DD)"
// @Param end_date query string false "End date filter (YYYY-MM-DD)"
// @Success 200 {object} responses.APIResponse{data=[]models.ProjectInsight}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights [get]
func (c *ProjectInsightController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")

	filters := make(map[string]interface{})
	if insightType := ctx.Request().Query("type", ""); insightType != "" {
		filters["type"] = insightType
	}
	if period := ctx.Request().Query("period", ""); period != "" {
		filters["period"] = period
	}
	if startDate := ctx.Request().Query("start_date", ""); startDate != "" {
		filters["start_date"] = startDate
	}
	if endDate := ctx.Request().Query("end_date", ""); endDate != "" {
		filters["end_date"] = endDate
	}

	insights, err := c.insightService.GetInsights(projectID, filters)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve insights: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Insights retrieved successfully",
		Data:      insights,
		Timestamp: time.Now(),
	})
}

// Generate generates insights for a project
// @Summary Generate project insights
// @Description Generate new insights and analytics for a project
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param request body object true "Generation parameters"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights/generate [post]
func (c *ProjectInsightController) Generate(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")

	var requestData struct {
		Period string `json:"period" binding:"required"`
	}
	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	err := c.insightService.GenerateInsights(projectID, requestData.Period)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate insights: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Insights generated successfully",
		Timestamp: time.Now(),
	})
}

// Summary returns project summary metrics
// @Summary Get project summary
// @Description Get a summary of key project metrics and statistics
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights/summary [get]
func (c *ProjectInsightController) Summary(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")

	summary, err := c.insightService.GetProjectSummary(projectID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project summary: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project summary retrieved successfully",
		Data:      summary,
		Timestamp: time.Now(),
	})
}

// Velocity returns velocity insights
// @Summary Get velocity insights
// @Description Get velocity insights for a project
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param period query string false "Period (daily, weekly, monthly, quarterly)" default(weekly)
// @Success 200 {object} responses.APIResponse{data=models.ProjectInsight}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights/velocity [get]
func (c *ProjectInsightController) Velocity(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")
	period := ctx.Request().Query("period", "weekly")

	insight, err := c.insightService.GetLatestInsight(projectID, "velocity", period)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Velocity insight not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Velocity insight retrieved successfully",
		Data:      insight,
		Timestamp: time.Now(),
	})
}

// Burndown returns burndown insights
// @Summary Get burndown insights
// @Description Get burndown chart data for a project
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param period query string false "Period (daily, weekly, monthly, quarterly)" default(weekly)
// @Success 200 {object} responses.APIResponse{data=models.ProjectInsight}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights/burndown [get]
func (c *ProjectInsightController) Burndown(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")
	period := ctx.Request().Query("period", "weekly")

	insight, err := c.insightService.GetLatestInsight(projectID, "burndown", period)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Burndown insight not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Burndown insight retrieved successfully",
		Data:      insight,
		Timestamp: time.Now(),
	})
}

// TaskDistribution returns task distribution insights
// @Summary Get task distribution insights
// @Description Get task distribution analytics for a project
// @Tags project-insights
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param project_id path string true "Project ID"
// @Param period query string false "Period (daily, weekly, monthly, quarterly)" default(weekly)
// @Success 200 {object} responses.APIResponse{data=models.ProjectInsight}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /organizations/{organization_id}/projects/{project_id}/insights/distribution [get]
func (c *ProjectInsightController) TaskDistribution(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Status(401).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unauthorized",
			Timestamp: time.Now(),
		})
	}

	projectID := ctx.Request().Route("project_id")
	period := ctx.Request().Query("period", "weekly")

	insight, err := c.insightService.GetLatestInsight(projectID, "task_distribution", period)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Task distribution insight not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(200).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Task distribution insight retrieved successfully",
		Data:      insight,
		Timestamp: time.Now(),
	})
}
