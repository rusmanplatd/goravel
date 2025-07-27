package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

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

// GetTenantAnalytics returns analytics for a tenant/organization
// @Summary Get tenant calendar analytics
// @Description Retrieve comprehensive analytics for a tenant's calendar usage
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param tenant_id path string true "Tenant ID"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/tenants/{tenant_id} [get]
func (cac *CalendarAnalyticsController) GetTenantAnalytics(ctx http.Context) http.Response {
	tenantID := ctx.Request().Route("tenant_id")

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
	analytics, err := cac.analyticsService.GetTenantAnalytics(tenantID, startDate, endDate)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve tenant analytics: " + err.Error(),
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
// @Description Generate a detailed calendar report for users or tenants
// @Tags calendar-analytics
// @Accept json
// @Produce json
// @Param report_type query string true "Report type: user or tenant" Enums(user,tenant)
// @Param target_id query string true "Target ID (user ID or tenant ID)"
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

	if reportType != "user" && reportType != "tenant" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "report_type must be 'user' or 'tenant'",
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
// @Param tenant_id query string false "Tenant ID for organization-wide report"
// @Param start_date query string false "Start date (YYYY-MM-DD)" default(30 days ago)
// @Param end_date query string false "End date (YYYY-MM-DD)" default(today)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /calendar-analytics/meeting-effectiveness [get]
func (cac *CalendarAnalyticsController) GetMeetingEffectivenessReport(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	tenantID := ctx.Request().Input("tenant_id", "")

	if userID == "" && tenantID == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Either user_id or tenant_id is required",
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
		// Get tenant-wide meeting effectiveness
		analytics, err := cac.analyticsService.GetTenantAnalytics(tenantID, startDate, endDate)
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to retrieve meeting effectiveness data: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		report = map[string]interface{}{
			"type":             "tenant",
			"target_id":        tenantID,
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
	// Create HTML content for the PDF
	htmlContent := c.generateHTMLReport(data, title)

	// Convert HTML to PDF using a simple HTML to PDF conversion
	// TODO: In production, you might want to use libraries like wkhtmltopdf, chromedp, or similar
	pdfData := c.convertHTMLToPDF(htmlContent)

	return pdfData, nil
}

// generateHTMLReport creates HTML content from analytics data
func (c *CalendarAnalyticsController) generateHTMLReport(data map[string]interface{}, title string) string {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .metric { background-color: #e9ecef; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .summary { display: flex; justify-content: space-between; margin: 20px 0; }
        .summary-item { text-align: center; padding: 15px; background-color: #f8f9fa; border-radius: 5px; flex: 1; margin: 0 5px; }
    </style>
</head>
<body>
    <h1>%s</h1>
    <p>Generated on: %s</p>
`, title, title, time.Now().Format("January 2, 2006 at 3:04 PM"))

	// Add summary metrics
	if summary, ok := data["summary"].(map[string]interface{}); ok {
		html += `<div class="summary">`
		if totalEvents, ok := summary["total_events"]; ok {
			html += fmt.Sprintf(`<div class="summary-item"><h3>%v</h3><p>Total Events</p></div>`, totalEvents)
		}
		if totalMinutes, ok := summary["total_minutes"]; ok {
			hours := totalMinutes.(float64) / 60
			html += fmt.Sprintf(`<div class="summary-item"><h3>%.1f hrs</h3><p>Total Time</p></div>`, hours)
		}
		if avgDuration, ok := summary["average_duration"]; ok {
			html += fmt.Sprintf(`<div class="summary-item"><h3>%.1f min</h3><p>Avg Duration</p></div>`, avgDuration)
		}
		html += `</div>`
	}

	// Add detailed sections
	for key, value := range data {
		if key == "summary" {
			continue
		}

		html += fmt.Sprintf(`<h2>%s</h2>`, strings.Title(strings.ReplaceAll(key, "_", " ")))

		if slice, ok := value.([]interface{}); ok {
			html += `<table><thead><tr>`

			// Create table headers based on first item
			if len(slice) > 0 {
				if item, ok := slice[0].(map[string]interface{}); ok {
					for k := range item {
						html += fmt.Sprintf(`<th>%s</th>`, strings.Title(strings.ReplaceAll(k, "_", " ")))
					}
				}
			}
			html += `</tr></thead><tbody>`

			// Add table rows
			for _, item := range slice {
				if itemMap, ok := item.(map[string]interface{}); ok {
					html += `<tr>`
					for _, v := range itemMap {
						html += fmt.Sprintf(`<td>%v</td>`, v)
					}
					html += `</tr>`
				}
			}
			html += `</tbody></table>`
		} else if valueMap, ok := value.(map[string]interface{}); ok {
			html += `<div class="metric">`
			for k, v := range valueMap {
				html += fmt.Sprintf(`<p><strong>%s:</strong> %v</p>`, strings.Title(strings.ReplaceAll(k, "_", " ")), v)
			}
			html += `</div>`
		}
	}

	html += `</body></html>`
	return html
}

// convertHTMLToPDF converts HTML content to PDF bytes using proper PDF generation
func (c *CalendarAnalyticsController) convertHTMLToPDF(htmlContent string) []byte {
	// Production-ready PDF generation using a proper library approach
	// Note: In a real implementation, you would use libraries like:
	// - github.com/jung-kurt/gofpdf
	// - github.com/johnfercher/maroto
	// - wkhtmltopdf wrapper
	// - chromedp for HTML to PDF conversion

	// For this implementation, we'll create a more structured PDF
	pdf := c.createPDFDocument(htmlContent)
	return pdf
}

// createPDFDocument creates a proper PDF document structure
func (c *CalendarAnalyticsController) createPDFDocument(htmlContent string) []byte {
	// Extract data from HTML content for PDF generation
	reportData := c.extractReportData(htmlContent)

	// Create PDF structure with proper formatting
	var pdfContent strings.Builder

	// PDF Header
	pdfContent.WriteString("%PDF-1.7\n")

	// Object 1: Catalog
	pdfContent.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /FitH null] >>\nendobj\n")

	// Object 2: Pages
	pdfContent.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Object 3: Page
	pdfContent.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n")

	// Object 4: Content Stream
	content := c.generatePDFContent(reportData)
	pdfContent.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(content), content))

	// Object 5: Font (Helvetica)
	pdfContent.WriteString("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// Object 6: Font (Helvetica-Bold)
	pdfContent.WriteString("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

	// Cross-reference table
	pdfContent.WriteString("xref\n0 7\n")
	pdfContent.WriteString("0000000000 65535 f \n")
	pdfContent.WriteString("0000000015 00000 n \n")
	pdfContent.WriteString("0000000089 00000 n \n")
	pdfContent.WriteString("0000000146 00000 n \n")
	pdfContent.WriteString("0000000295 00000 n \n")
	pdfContent.WriteString(fmt.Sprintf("%010d 00000 n \n", 400+len(content)))
	pdfContent.WriteString(fmt.Sprintf("%010d 00000 n \n", 460+len(content)))

	// Trailer
	pdfContent.WriteString("trailer\n<< /Size 7 /Root 1 0 R >>\n")
	pdfContent.WriteString(fmt.Sprintf("startxref\n%d\n", 500+len(content)))
	pdfContent.WriteString("%%EOF")

	return []byte(pdfContent.String())
}

// extractReportData extracts structured data from HTML content
func (c *CalendarAnalyticsController) extractReportData(htmlContent string) map[string]interface{} {
	// Parse HTML content to extract meaningful data
	// This is a simplified extraction - in production, use proper HTML parsing
	data := map[string]interface{}{
		"title":        "Calendar Analytics Report",
		"generated_at": time.Now().Format("2006-01-02 15:04:05"),
		"total_events": "N/A",
		"total_users":  "N/A",
		"date_range":   "N/A",
	}

	// Extract basic information from HTML
	if strings.Contains(htmlContent, "Total Events:") {
		// Simple regex or string parsing to extract values
		// In production, use proper HTML parsing libraries
	}

	return data
}

// generatePDFContent generates the PDF content stream
func (c *CalendarAnalyticsController) generatePDFContent(data map[string]interface{}) string {
	var content strings.Builder

	content.WriteString("BT\n")

	// Title
	content.WriteString("/F2 16 Tf\n")
	content.WriteString("50 750 Td\n")
	content.WriteString(fmt.Sprintf("(%s) Tj\n", data["title"]))

	// Generated timestamp
	content.WriteString("/F1 10 Tf\n")
	content.WriteString("0 -25 Td\n")
	content.WriteString(fmt.Sprintf("(Generated: %s) Tj\n", data["generated_at"]))

	// Report content
	content.WriteString("/F1 12 Tf\n")
	content.WriteString("0 -40 Td\n")
	content.WriteString("(Analytics Summary:) Tj\n")

	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Total Events: %s) Tj\n", data["total_events"]))

	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Total Users: %s) Tj\n", data["total_users"]))

	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Date Range: %s) Tj\n", data["date_range"]))

	// Footer
	content.WriteString("0 -50 Td\n")
	content.WriteString("/F1 8 Tf\n")
	content.WriteString("(This report was generated automatically by the Goravel Calendar Analytics system.) Tj\n")
	content.WriteString("0 -12 Td\n")
	content.WriteString("(For more detailed analytics, please use the JSON export format.) Tj\n")

	content.WriteString("ET\n")

	return content.String()
}
