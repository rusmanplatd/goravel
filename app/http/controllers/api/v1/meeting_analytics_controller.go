package v1

import (
	"goravel/app/http/responses"
	"goravel/app/services"
	"time"

	"github.com/goravel/framework/contracts/http"
)

// MeetingAnalyticsController handles meeting analytics and reporting
type MeetingAnalyticsController struct {
	analyticsService *services.MeetingAnalyticsServiceSimple
}

// NewMeetingAnalyticsController creates a new meeting analytics controller
func NewMeetingAnalyticsController() *MeetingAnalyticsController {
	return &MeetingAnalyticsController{
		analyticsService: services.NewMeetingAnalyticsService(),
	}
}

// GetMeetingStats returns comprehensive meeting statistics
// @Summary Get meeting statistics
// @Description Get comprehensive meeting statistics for a specific meeting
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/stats [get]
func (mac *MeetingAnalyticsController) GetMeetingStats(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	stats, err := mac.analyticsService.GetMeetingStats(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get meeting statistics", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Meeting statistics retrieved successfully", stats)
}

// GetParticipationReport returns detailed participation report
// @Summary Get participation report
// @Description Get detailed participation report for a meeting
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/participation [get]
func (mac *MeetingAnalyticsController) GetParticipationReport(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	report, err := mac.analyticsService.GetParticipationReport(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get participation report", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Participation report retrieved successfully", report)
}

// GetEngagementMetrics returns meeting engagement metrics
// @Summary Get engagement metrics
// @Description Get engagement metrics including chat activity, poll participation, etc.
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/engagement [get]
func (mac *MeetingAnalyticsController) GetEngagementMetrics(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	metrics, err := mac.analyticsService.GetEngagementMetrics(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get engagement metrics", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Engagement metrics retrieved successfully", metrics)
}

// GetAttendanceReport returns attendance analytics
// @Summary Get attendance report
// @Description Get detailed attendance analytics with join/leave patterns
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/attendance [get]
func (mac *MeetingAnalyticsController) GetAttendanceReport(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	report, err := mac.analyticsService.GetAttendanceReport(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get attendance report", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Attendance report retrieved successfully", report)
}

// GetOrganizationalAnalytics returns organization-wide meeting analytics
// @Summary Get organizational analytics
// @Description Get organization-wide meeting analytics and trends
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param organization_id query string false "Organization ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)"
// @Param end_date query string false "End date (YYYY-MM-DD)"
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/analytics/organizational [get]
func (mac *MeetingAnalyticsController) GetOrganizationalAnalytics(ctx http.Context) http.Response {
	organizationID := ctx.Request().Query("organization_id", "")
	startDateStr := ctx.Request().Query("start_date", "")
	endDateStr := ctx.Request().Query("end_date", "")

	var startDate, endDate *time.Time
	if startDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", startDateStr); err == nil {
			startDate = &parsed
		}
	}
	if endDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", endDateStr); err == nil {
			endDate = &parsed
		}
	}

	analytics, err := mac.analyticsService.GetOrganizationalAnalytics(organizationID, startDate, endDate)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get organizational analytics", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Organizational analytics retrieved successfully", analytics)
}

// ExportMeetingReport exports a comprehensive meeting report
// @Summary Export meeting report
// @Description Export a comprehensive meeting report in various formats
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Param format query string false "Export format (pdf, excel, csv)" default(pdf)
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/export [post]
func (mac *MeetingAnalyticsController) ExportMeetingReport(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	format := ctx.Request().Query("format", "pdf")
	if format != "pdf" && format != "excel" && format != "csv" {
		return responses.CreateErrorResponse(ctx, "Invalid format", "Format must be pdf, excel, or csv", 400)
	}

	exportData, err := mac.analyticsService.ExportMeetingReport(meetingID, format)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to export meeting report", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Meeting report exported successfully", exportData)
}

// GetRealTimeMetrics returns real-time meeting metrics
// @Summary Get real-time metrics
// @Description Get real-time meeting metrics for active meetings
// @Tags meeting-analytics
// @Accept json
// @Produce json
// @Param meeting_id path string true "Meeting ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /api/v1/meetings/{meeting_id}/analytics/realtime [get]
func (mac *MeetingAnalyticsController) GetRealTimeMetrics(ctx http.Context) http.Response {
	meetingID := ctx.Request().Route("meeting_id")
	if meetingID == "" {
		return responses.CreateErrorResponse(ctx, "Meeting ID is required", "Missing meeting_id parameter", 400)
	}

	metrics, err := mac.analyticsService.GetRealTimeMetrics(meetingID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get real-time metrics", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Real-time metrics retrieved successfully", metrics)
}
