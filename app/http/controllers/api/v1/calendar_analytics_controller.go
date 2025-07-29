package v1

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/jung-kurt/gofpdf"

	"goravel/app/http/responses"
	"goravel/app/services"
)

type CalendarAnalyticsController struct {
	analyticsService *services.CalendarAnalyticsService
}

func NewCalendarAnalyticsController() *CalendarAnalyticsController {
	return &CalendarAnalyticsController{
		analyticsService: services.NewCalendarAnalyticsService(),
	}
}

// GetUserAnalytics returns analytics for a specific user
// @Summary Get user calendar analytics
// @Description Retrieve comprehensive analytics for a user's calendar usage
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/users/{user_id} [get]
func (cac *CalendarAnalyticsController) GetUserAnalytics(ctx http.Context) http.Response {
	userID := ctx.Request().Route("user_id")

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get analytics
	analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user analytics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GetOrganizationAnalytics returns analytics for a organization/organization
// @Summary Get organization calendar analytics
// @Description Retrieve comprehensive analytics for a organization's calendar usage
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param organization_id path string true "Organization ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/organizations/{organization_id} [get]
func (cac *CalendarAnalyticsController) GetOrganizationAnalytics(ctx http.Context) http.Response {
	organizationId := ctx.Request().Route("organization_id")

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get analytics
	analytics, err := cac.analyticsService.GetOrganizationAnalytics(organizationId, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve organization analytics: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      analytics,
		Timestamp: time.Now(),
	})
}

// GenerateReport generates a comprehensive calendar report
// @Summary Generate calendar report
// @Description Generate a detailed calendar report for users or organizations
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param report_type query string true "Report type: user or organization" Enums(user,organization)
// @Param target_id query string true "Target ID (user ID or organization ID)"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Param format query string false "Report format: json or pdf" Enums(json,pdf) default(json)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/reports [get]
func (cac *CalendarAnalyticsController) GenerateReport(ctx http.Context) http.Response {
	reportType := ctx.Request().Input("report_type", "")
	targetID := ctx.Request().Input("target_id", "")
	format := ctx.Request().Input("format", "json")

	if reportType == "" || targetID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "report_type and target_id are required",
			Timestamp: time.Now(),
		})
	}

	if reportType != "user" && reportType != "organization" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "report_type must be 'user' or 'organization'",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Generate report
	report, err := cac.analyticsService.GenerateCalendarReport(reportType, targetID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate report: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Handle different formats
	switch format {
	case "json":
		return ctx.Response().Success().Json(responses.APIResponse{
			Status:    "success",
			Data:      report,
			Timestamp: time.Now(),
		})
	case "pdf":
		// Generate PDF report
		pdfData, err := cac.generatePDFReport(report, "Calendar Analytics Report")
		if err != nil {
			facades.Log().Error("Failed to generate PDF report", map[string]interface{}{
				"error": err.Error(),
			})
			return ctx.Response().Json(500, responses.APIResponse{
				Status:    "error",
				Message:   "Failed to generate PDF report",
				Error:     err.Error(),
				Timestamp: time.Now(),
			})
		}

		// Set appropriate headers for PDF download
		ctx.Response().Header("Content-Type", "application/pdf")
		ctx.Response().Header("Content-Disposition", "attachment; filename=calendar-analytics-report.pdf")
		ctx.Response().Header("Content-Length", fmt.Sprintf("%d", len(pdfData)))

		return ctx.Response().Success().Data("application/pdf", pdfData)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unsupported format. Use 'json' or 'pdf'",
			Timestamp: time.Now(),
		})
	}
}

// GetMeetingEffectivenessReport returns meeting effectiveness metrics
// @Summary Get meeting effectiveness report
// @Description Get detailed meeting effectiveness metrics for analysis
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id query string false "User ID for user-specific report"
// @Param organization_id query string false "Organization ID for organization-wide report"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/meeting-effectiveness [get]
func (cac *CalendarAnalyticsController) GetMeetingEffectivenessReport(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	organizationId := ctx.Request().Input("organization_id", "")

	if userID == "" && organizationId == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Either user_id or organization_id is required",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	var report map[string]interface{}

	if userID != "" {
		// Get user-specific meeting effectiveness
		analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve meeting effectiveness data: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		report = map[string]interface{}{
			"type":            "user",
			"target_id":       userID,
			"meeting_metrics": analytics["meeting_metrics"],
			"period_start":    startDate,
			"period_end":      endDate,
		}
	} else {
		// Get organization-wide meeting effectiveness
		analytics, err := cac.analyticsService.GetOrganizationAnalytics(organizationId, startDate, endDate)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve meeting effectiveness data: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		report = map[string]interface{}{
			"type":             "organization",
			"target_id":        organizationId,
			"meeting_patterns": analytics["meeting_patterns"],
			"overview":         analytics["overview"],
			"period_start":     startDate,
			"period_end":       endDate,
		}
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      report,
		Timestamp: time.Now(),
	})
}

// GetProductivityInsights returns productivity insights based on calendar data
// @Summary Get productivity insights
// @Description Get productivity insights and recommendations based on calendar patterns
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param user_id query string true "User ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/productivity-insights [get]
func (cac *CalendarAnalyticsController) GetProductivityInsights(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "user_id is required",
			Timestamp: time.Now(),
		})
	}

	// Parse date parameters
	startDate, endDate, err := cac.parseDateRange(ctx)
	if err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get user analytics
	analytics, err := cac.analyticsService.GetUserAnalytics(userID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve productivity insights: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Extract productivity-related data
	insights := map[string]interface{}{
		"user_id":               userID,
		"period_start":          startDate,
		"period_end":            endDate,
		"productivity_insights": analytics["productivity_insights"],
		"time_distribution":     analytics["time_distribution"],
		"collaboration_metrics": analytics["collaboration_metrics"],
	}

	// Add recommendations based on the data
	recommendations := cac.generateProductivityRecommendations(analytics)
	insights["recommendations"] = recommendations

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      insights,
		Timestamp: time.Now(),
	})
}

// Helper methods

func (cac *CalendarAnalyticsController) parseDateRange(ctx http.Context) (time.Time, time.Time, error) {
	// Default to last 30 days
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	// Parse start_date if provided
	if startDateStr := ctx.Request().Input("start_date", ""); startDateStr != "" {
		parsed, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start_date format. Use YYYY-MM-DD")
		}
		startDate = parsed
	}

	// Parse end_date if provided
	if endDateStr := ctx.Request().Input("end_date", ""); endDateStr != "" {
		parsed, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end_date format. Use YYYY-MM-DD")
		}
		endDate = parsed
	}

	// Validate date range
	if startDate.After(endDate) {
		return time.Time{}, time.Time{}, fmt.Errorf("start_date must be before end_date")
	}

	// Limit range to prevent excessive queries
	if endDate.Sub(startDate) > 365*24*time.Hour {
		return time.Time{}, time.Time{}, fmt.Errorf("date range cannot exceed 365 days")
	}

	return startDate, endDate, nil
}

func (cac *CalendarAnalyticsController) generateProductivityRecommendations(analytics map[string]interface{}) []map[string]interface{} {
	recommendations := []map[string]interface{}{}

	// Extract productivity insights
	if productivityData, ok := analytics["productivity_insights"].(map[string]interface{}); ok {
		// Check meeting density
		if meetingDensity, ok := productivityData["meeting_density_per_day"].(float64); ok {
			if meetingDensity > 6 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "meeting_overload",
					"priority":    "high",
					"title":       "High Meeting Density Detected",
					"description": "You have more than 6 meetings per day on average. Consider consolidating meetings or declining non-essential ones.",
					"metric":      meetingDensity,
				})
			}
		}

		// Check focus time
		if focusTime, ok := productivityData["avg_focus_time_minutes"].(float64); ok {
			if focusTime < 30 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "low_focus_time",
					"priority":    "medium",
					"title":       "Limited Focus Time",
					"description": "Your average focus time between meetings is less than 30 minutes. Try to block longer periods for deep work.",
					"metric":      focusTime,
				})
			}
		}

		// Check response rate
		if responseRate, ok := productivityData["invitation_response_rate"].(float64); ok {
			if responseRate < 0.8 {
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "low_response_rate",
					"priority":    "low",
					"title":       "Low Meeting Response Rate",
					"description": "You respond to less than 80% of meeting invitations. Consider improving your meeting response habits.",
					"metric":      responseRate,
				})
			}
		}
	}

	// Check time distribution
	if timeData, ok := analytics["time_distribution"].(map[string]interface{}); ok {
		if timeByType, ok := timeData["time_by_type"].([]interface{}); ok {
			// Look for meeting type imbalances
			var totalMeetingTime float64
			var meetingTypeCount int

			for _, typeData := range timeByType {
				if typeMap, ok := typeData.(map[string]interface{}); ok {
					if minutes, ok := typeMap["total_minutes"].(float64); ok {
						totalMeetingTime += minutes
						meetingTypeCount++
					}
				}
			}

			if meetingTypeCount > 0 && totalMeetingTime > 20*60 { // More than 20 hours per period
				recommendations = append(recommendations, map[string]interface{}{
					"type":        "meeting_time_high",
					"priority":    "medium",
					"title":       "High Meeting Time",
					"description": "You spend significant time in meetings. Consider if all meetings are necessary and look for optimization opportunities.",
					"metric":      totalMeetingTime / 60, // Convert to hours
				})
			}
		}
	}

	return recommendations
}

// generatePDFReport generates a PDF report from analytics data
func (c *CalendarAnalyticsController) generatePDFReport(data map[string]interface{}, title string) ([]byte, error) {
	// Create PDF document using gofpdf library
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Set up fonts
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(190, 10, title)
	pdf.Ln(15)

	// Add report content
	pdf.SetFont("Arial", "", 12)

	// Add summary section
	if summary, exists := data["summary"].(map[string]interface{}); exists {
		c.addSummarySection(pdf, summary)
	}

	// Add metrics section
	if metrics, exists := data["metrics"].(map[string]interface{}); exists {
		c.addMetricsSection(pdf, metrics)
	}

	// Add charts section (as text descriptions)
	if charts, exists := data["charts"].([]interface{}); exists {
		c.addChartsSection(pdf, charts)
	}

	// Add trends section
	if trends, exists := data["trends"].(map[string]interface{}); exists {
		c.addTrendsSection(pdf, trends)
	}

	// Generate PDF bytes
	var buf strings.Builder
	err := pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return []byte(buf.String()), nil
}

// addSummarySection adds summary information to the PDF
func (c *CalendarAnalyticsController) addSummarySection(pdf *gofpdf.Fpdf, summary map[string]interface{}) {
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Summary")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 11)

	if totalEvents, exists := summary["total_events"]; exists {
		pdf.Cell(190, 8, fmt.Sprintf("Total Events: %v", totalEvents))
		pdf.Ln(6)
	}

	if totalParticipants, exists := summary["total_participants"]; exists {
		pdf.Cell(190, 8, fmt.Sprintf("Total Participants: %v", totalParticipants))
		pdf.Ln(6)
	}

	if avgDuration, exists := summary["average_duration"]; exists {
		pdf.Cell(190, 8, fmt.Sprintf("Average Duration: %v minutes", avgDuration))
		pdf.Ln(6)
	}

	if completionRate, exists := summary["completion_rate"]; exists {
		pdf.Cell(190, 8, fmt.Sprintf("Completion Rate: %v%%", completionRate))
		pdf.Ln(6)
	}

	pdf.Ln(5)
}

// addMetricsSection adds metrics information to the PDF
func (c *CalendarAnalyticsController) addMetricsSection(pdf *gofpdf.Fpdf, metrics map[string]interface{}) {
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Key Metrics")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 11)

	for key, value := range metrics {
		displayKey := strings.ReplaceAll(strings.Title(strings.ReplaceAll(key, "_", " ")), "Id", "ID")
		pdf.Cell(190, 8, fmt.Sprintf("%s: %v", displayKey, value))
		pdf.Ln(6)
	}

	pdf.Ln(5)
}

// addChartsSection adds chart descriptions to the PDF
func (c *CalendarAnalyticsController) addChartsSection(pdf *gofpdf.Fpdf, charts []interface{}) {
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Charts and Visualizations")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 11)

	for i, chart := range charts {
		if chartMap, ok := chart.(map[string]interface{}); ok {
			pdf.SetFont("Arial", "B", 12)
			if title, exists := chartMap["title"]; exists {
				pdf.Cell(190, 8, fmt.Sprintf("Chart %d: %v", i+1, title))
				pdf.Ln(8)
			}

			pdf.SetFont("Arial", "", 10)
			if description, exists := chartMap["description"]; exists {
				pdf.MultiCell(190, 6, fmt.Sprintf("Description: %v", description), "", "", false)
				pdf.Ln(4)
			}

			if data, exists := chartMap["data"]; exists {
				pdf.MultiCell(190, 6, fmt.Sprintf("Data: %v", data), "", "", false)
				pdf.Ln(6)
			}
		}
	}

	pdf.Ln(5)
}

// addTrendsSection adds trends information to the PDF
func (c *CalendarAnalyticsController) addTrendsSection(pdf *gofpdf.Fpdf, trends map[string]interface{}) {
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(190, 10, "Trends Analysis")
	pdf.Ln(10)

	pdf.SetFont("Arial", "", 11)

	for key, value := range trends {
		displayKey := strings.ReplaceAll(strings.Title(strings.ReplaceAll(key, "_", " ")), "Id", "ID")

		if valueMap, ok := value.(map[string]interface{}); ok {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(190, 8, displayKey+":")
			pdf.Ln(6)

			pdf.SetFont("Arial", "", 10)
			for subKey, subValue := range valueMap {
				subDisplayKey := strings.ReplaceAll(strings.Title(strings.ReplaceAll(subKey, "_", " ")), "Id", "ID")
				pdf.Cell(190, 6, fmt.Sprintf("  %s: %v", subDisplayKey, subValue))
				pdf.Ln(5)
			}
		} else {
			pdf.Cell(190, 8, fmt.Sprintf("%s: %v", displayKey, value))
			pdf.Ln(6)
		}
	}
}

// generateHTMLReport creates HTML content from analytics data (kept for backward compatibility)
func (c *CalendarAnalyticsController) generateHTMLReport(data map[string]interface{}, title string) string {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .section { margin: 20px 0; }
        .metric { margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #007bff; }
        .chart { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        table { width: 100%%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1 class="header">%s</h1>
`, title, title)

	// Add summary section
	if summary, exists := data["summary"].(map[string]interface{}); exists {
		html += "<div class='section'><h2>Summary</h2>"
		for key, value := range summary {
			displayKey := strings.ReplaceAll(strings.Title(strings.ReplaceAll(key, "_", " ")), "Id", "ID")
			html += fmt.Sprintf("<div class='metric'><strong>%s:</strong> %v</div>", displayKey, value)
		}
		html += "</div>"
	}

	// Add metrics section
	if metrics, exists := data["metrics"].(map[string]interface{}); exists {
		html += "<div class='section'><h2>Key Metrics</h2>"
		html += "<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>"
		for key, value := range metrics {
			displayKey := strings.ReplaceAll(strings.Title(strings.ReplaceAll(key, "_", " ")), "Id", "ID")
			html += fmt.Sprintf("<tr><td>%s</td><td>%v</td></tr>", displayKey, value)
		}
		html += "</tbody></table></div>"
	}

	// Add charts section
	if charts, exists := data["charts"].([]interface{}); exists {
		html += "<div class='section'><h2>Charts</h2>"
		for i, chart := range charts {
			if chartMap, ok := chart.(map[string]interface{}); ok {
				html += fmt.Sprintf("<div class='chart'><h3>Chart %d</h3>", i+1)
				if title, exists := chartMap["title"]; exists {
					html += fmt.Sprintf("<h4>%v</h4>", title)
				}
				if description, exists := chartMap["description"]; exists {
					html += fmt.Sprintf("<p>%v</p>", description)
				}
				html += "</div>"
			}
		}
		html += "</div>"
	}

	html += "</body></html>"
	return html
}

// convertHTMLToPDF converts HTML content to PDF bytes using gofpdf
func (c *CalendarAnalyticsController) convertHTMLToPDF(htmlContent string) []byte {
	// Extract data from HTML for PDF generation
	// This is a simplified approach - in production you might want to use
	// a proper HTML to PDF converter like chromedp or wkhtmltopdf

	// For now, we'll create a simple PDF with extracted text content
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(190, 10, "Analytics Report")
	pdf.Ln(15)

	pdf.SetFont("Arial", "", 12)

	// Extract text content from HTML (simplified)
	text := c.extractTextFromHTML(htmlContent)
	pdf.MultiCell(190, 8, text, "", "", false)

	var buf strings.Builder
	pdf.Output(&buf)

	return []byte(buf.String())
}

// extractTextFromHTML extracts plain text from HTML content
func (c *CalendarAnalyticsController) extractTextFromHTML(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, "")

	// Clean up whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)

	return text
}

// extractTableData extracts table data from HTML content
func (c *CalendarAnalyticsController) extractTableData(htmlContent string) []map[string]string {
	var tables []map[string]string

	// Extract HTML tables using regex
	tablePattern := regexp.MustCompile(`(?s)<table[^>]*>(.*?)</table>`)
	rowPattern := regexp.MustCompile(`(?s)<tr[^>]*>(.*?)</tr>`)
	cellPattern := regexp.MustCompile(`(?s)<t[hd][^>]*>(.*?)</t[hd]>`)

	tableMatches := tablePattern.FindAllStringSubmatch(htmlContent, -1)
	for _, tableMatch := range tableMatches {
		tableHTML := tableMatch[1]
		rowMatches := rowPattern.FindAllStringSubmatch(tableHTML, -1)

		var headers []string
		var rows []map[string]string

		for i, rowMatch := range rowMatches {
			rowHTML := rowMatch[1]
			cellMatches := cellPattern.FindAllStringSubmatch(rowHTML, -1)

			if i == 0 {
				// First row is likely headers
				for _, cellMatch := range cellMatches {
					cellText := c.stripHTMLTags(cellMatch[1])
					headers = append(headers, strings.TrimSpace(cellText))
				}
			} else {
				// Data rows
				rowData := make(map[string]string)
				for j, cellMatch := range cellMatches {
					cellText := c.stripHTMLTags(cellMatch[1])
					if j < len(headers) {
						rowData[headers[j]] = strings.TrimSpace(cellText)
					} else {
						rowData[fmt.Sprintf("column_%d", j)] = strings.TrimSpace(cellText)
					}
				}
				if len(rowData) > 0 {
					rows = append(rows, rowData)
				}
			}
		}

		// Add table metadata
		if len(rows) > 0 {
			tableInfo := map[string]string{
				"type":      "table",
				"row_count": fmt.Sprintf("%d", len(rows)),
				"col_count": fmt.Sprintf("%d", len(headers)),
				"headers":   strings.Join(headers, ","),
			}
			tables = append(tables, tableInfo)
		}
	}

	return tables
}

// extractChartData extracts chart/graph data from HTML content
func (c *CalendarAnalyticsController) extractChartData(htmlContent string) []map[string]interface{} {
	var charts []map[string]interface{}

	// Look for common chart libraries and data patterns
	chartPatterns := map[string]*regexp.Regexp{
		"chart_js":   regexp.MustCompile(`(?s)new\s+Chart\s*\([^,]+,\s*({[^}]+})`),
		"highcharts": regexp.MustCompile(`(?s)Highcharts\.chart\s*\([^,]+,\s*({[^}]+})`),
		"d3_data":    regexp.MustCompile(`(?s)\.data\s*\(\s*(\[[^\]]+\])`),
		"canvas":     regexp.MustCompile(`(?s)<canvas[^>]*id\s*=\s*["']([^"']+)["'][^>]*>`),
		"svg_chart":  regexp.MustCompile(`(?s)<svg[^>]*class\s*=\s*["'][^"']*chart[^"']*["'][^>]*>`),
	}

	for chartType, pattern := range chartPatterns {
		matches := pattern.FindAllStringSubmatch(htmlContent, -1)
		for _, match := range matches {
			chartData := map[string]interface{}{
				"type":  chartType,
				"found": true,
			}

			if len(match) > 1 {
				chartData["config"] = match[1]
			}

			charts = append(charts, chartData)
		}
	}

	// Extract data from script tags
	scriptPattern := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	scriptMatches := scriptPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, scriptMatch := range scriptMatches {
		scriptContent := scriptMatch[1]

		// Look for data arrays
		dataPattern := regexp.MustCompile(`(?s)(?:data|values|series)\s*:\s*(\[[^\]]+\])`)
		dataMatches := dataPattern.FindAllStringSubmatch(scriptContent, -1)

		for _, dataMatch := range dataMatches {
			chartData := map[string]interface{}{
				"type": "script_data",
				"data": dataMatch[1],
			}
			charts = append(charts, chartData)
		}
	}

	return charts
}

// extractStatistics extracts statistical data from HTML content
func (c *CalendarAnalyticsController) extractStatistics(htmlContent string) map[string]interface{} {
	stats := make(map[string]interface{})

	// Common statistical patterns
	statPatterns := map[string]*regexp.Regexp{
		"percentage": regexp.MustCompile(`(\d+(?:\.\d+)?)\s*%`),
		"count":      regexp.MustCompile(`(?i)count\s*:?\s*(\d+)`),
		"average":    regexp.MustCompile(`(?i)(?:average|avg|mean)\s*:?\s*(\d+(?:\.\d+)?)`),
		"total":      regexp.MustCompile(`(?i)total\s*:?\s*(\d+(?:\.\d+)?)`),
		"maximum":    regexp.MustCompile(`(?i)(?:maximum|max)\s*:?\s*(\d+(?:\.\d+)?)`),
		"minimum":    regexp.MustCompile(`(?i)(?:minimum|min)\s*:?\s*(\d+(?:\.\d+)?)`),
		"duration":   regexp.MustCompile(`(\d+)\s*(?:hours?|hrs?|minutes?|mins?|seconds?|secs?)`),
		"growth":     regexp.MustCompile(`(?i)growth\s*:?\s*([+-]?\d+(?:\.\d+)?)\s*%?`),
		"attendance": regexp.MustCompile(`(?i)attendance\s*:?\s*(\d+(?:\.\d+)?)\s*%?`),
	}

	for statType, pattern := range statPatterns {
		matches := pattern.FindAllStringSubmatch(htmlContent, -1)
		if len(matches) > 0 {
			var values []string
			for _, match := range matches {
				if len(match) > 1 {
					values = append(values, match[1])
				}
			}
			if len(values) > 0 {
				if len(values) == 1 {
					stats[statType] = values[0]
				} else {
					stats[statType] = values
				}
			}
		}
	}

	// Extract key-value pairs from definition lists
	dlPattern := regexp.MustCompile(`(?s)<dl[^>]*>(.*?)</dl>`)
	dtPattern := regexp.MustCompile(`(?s)<dt[^>]*>(.*?)</dt>`)
	ddPattern := regexp.MustCompile(`(?s)<dd[^>]*>(.*?)</dd>`)

	dlMatches := dlPattern.FindAllStringSubmatch(htmlContent, -1)
	for _, dlMatch := range dlMatches {
		dlContent := dlMatch[1]
		dtMatches := dtPattern.FindAllStringSubmatch(dlContent, -1)
		ddMatches := ddPattern.FindAllStringSubmatch(dlContent, -1)

		if len(dtMatches) == len(ddMatches) {
			for i := 0; i < len(dtMatches); i++ {
				key := c.stripHTMLTags(dtMatches[i][1])
				value := c.stripHTMLTags(ddMatches[i][1])
				stats[strings.ToLower(strings.ReplaceAll(key, " ", "_"))] = strings.TrimSpace(value)
			}
		}
	}

	return stats
}

// extractMetadata extracts metadata from HTML head section
func (c *CalendarAnalyticsController) extractMetadata(htmlContent string) map[string]string {
	metadata := make(map[string]string)

	// Extract title
	titlePattern := regexp.MustCompile(`(?s)<title[^>]*>(.*?)</title>`)
	if titleMatch := titlePattern.FindStringSubmatch(htmlContent); len(titleMatch) > 1 {
		metadata["title"] = c.stripHTMLTags(titleMatch[1])
	}

	// Extract meta tags
	metaPattern := regexp.MustCompile(`<meta\s+([^>]+)>`)
	metaMatches := metaPattern.FindAllStringSubmatch(htmlContent, -1)

	for _, metaMatch := range metaMatches {
		metaTag := metaMatch[1]

		// Extract name and content attributes
		namePattern := regexp.MustCompile(`name\s*=\s*["']([^"']+)["']`)
		contentPattern := regexp.MustCompile(`content\s*=\s*["']([^"']+)["']`)

		nameMatch := namePattern.FindStringSubmatch(metaTag)
		contentMatch := contentPattern.FindStringSubmatch(metaTag)

		if len(nameMatch) > 1 && len(contentMatch) > 1 {
			metadata[nameMatch[1]] = contentMatch[1]
		}

		// Extract property and content attributes (for Open Graph, etc.)
		propertyPattern := regexp.MustCompile(`property\s*=\s*["']([^"']+)["']`)
		propertyMatch := propertyPattern.FindStringSubmatch(metaTag)

		if len(propertyMatch) > 1 && len(contentMatch) > 1 {
			metadata[propertyMatch[1]] = contentMatch[1]
		}
	}

	// Extract charset
	charsetPattern := regexp.MustCompile(`charset\s*=\s*["']?([^"'\s>]+)`)
	if charsetMatch := charsetPattern.FindStringSubmatch(htmlContent); len(charsetMatch) > 1 {
		metadata["charset"] = charsetMatch[1]
	}

	return metadata
}

// stripHTMLTags removes HTML tags from text
func (c *CalendarAnalyticsController) stripHTMLTags(html string) string {
	// Remove HTML tags
	tagPattern := regexp.MustCompile(`<[^>]*>`)
	text := tagPattern.ReplaceAllString(html, "")

	// Decode common HTML entities
	entities := map[string]string{
		"&amp;":   "&",
		"&lt;":    "<",
		"&gt;":    ">",
		"&quot;":  "\"",
		"&apos;":  "'",
		"&nbsp;":  " ",
		"&copy;":  "©",
		"&reg;":   "®",
		"&trade;": "™",
	}

	for entity, replacement := range entities {
		text = strings.ReplaceAll(text, entity, replacement)
	}

	// Clean up whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}
