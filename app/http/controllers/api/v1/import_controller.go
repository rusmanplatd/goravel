package v1

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ImportController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewImportController() *ImportController {
	return &ImportController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// ImportEvents imports events from external sources
// @Summary Import events
// @Description Imports events from various external sources (iCal, CSV, JSON)
// @Tags import
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param import body object{source=string,format=string,data=string} true "Import data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/import [post]
func (ic *ImportController) ImportEvents(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var request struct {
		Source string `json:"source" binding:"required"` // "ical", "csv", "json", "google"
		Format string `json:"format"`                    // Additional format info
		Data   string `json:"data" binding:"required"`   // Import data content
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	var importedEvents []models.CalendarEvent
	var importErrors []string

	switch strings.ToLower(request.Source) {
	case "ical":
		importedEvents, importErrors = ic.importFromICal(request.Data, calendarID, userID, organizationId)
	case "csv":
		importedEvents, importErrors = ic.importFromCSV(request.Data, calendarID, userID, organizationId)
	case "json":
		importedEvents, importErrors = ic.importFromJSON(request.Data, calendarID, userID, organizationId)
	case "google":
		importedEvents, importErrors = ic.importFromGoogleCalendar(request.Data, calendarID, userID, organizationId)
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unsupported import source. Supported: ical, csv, json, google",
			Timestamp: time.Now(),
		})
	}

	// Save imported events
	successCount := 0
	for _, event := range importedEvents {
		if err := facades.Orm().Query().Create(&event); err != nil {
			importErrors = append(importErrors, fmt.Sprintf("Failed to save event '%s': %v", event.Title, err))
		} else {
			successCount++
		}
	}

	response := map[string]interface{}{
		"kind":         "calendar#import",
		"imported":     successCount,
		"total":        len(importedEvents),
		"errors":       importErrors,
		"errorCount":   len(importErrors),
		"calendarId":   calendarID,
		"importSource": request.Source,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Import completed. %d events imported, %d errors", successCount, len(importErrors)),
		Data:      response,
		Timestamp: time.Now(),
	})
}

// ExportEvents exports events to various formats
// @Summary Export events
// @Description Exports events to various formats (iCal, CSV, JSON)
// @Tags import
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param format query string true "Export format (ical, csv, json)"
// @Param timeMin query string false "Start time for export"
// @Param timeMax query string false "End time for export"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/export [get]
func (ic *ImportController) ExportEvents(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	format := ctx.Request().Query("format", "ical")
	timeMin := ctx.Request().Query("timeMin", "")
	timeMax := ctx.Request().Query("timeMax", "")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Get events
	query := facades.Orm().Query().
		Where("calendar_id = ?", calendarID).
		With("Participants.User")

	if timeMin != "" {
		if minTime, err := time.Parse(time.RFC3339, timeMin); err == nil {
			query = query.Where("start_time >= ?", minTime)
		}
	}

	if timeMax != "" {
		if maxTime, err := time.Parse(time.RFC3339, timeMax); err == nil {
			query = query.Where("start_time < ?", maxTime)
		}
	}

	var events []models.CalendarEvent
	err = query.Find(&events)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve events for export",
			Timestamp: time.Now(),
		})
	}

	var exportData string
	var contentType string

	switch strings.ToLower(format) {
	case "ical":
		exportData = ic.exportToICal(events, calendar)
		contentType = "text/calendar"
	case "csv":
		exportData = ic.exportToCSV(events)
		contentType = "text/csv"
	case "json":
		exportData = ic.exportToJSON(events)
		contentType = "application/json"
	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Unsupported export format. Supported: ical, csv, json",
			Timestamp: time.Now(),
		})
	}

	response := map[string]interface{}{
		"kind":        "calendar#export",
		"format":      format,
		"contentType": contentType,
		"data":        exportData,
		"eventCount":  len(events),
		"calendarId":  calendarID,
		"exported":    time.Now().Format(time.RFC3339),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Export completed. %d events exported in %s format", len(events), format),
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Helper functions for different import formats

func (ic *ImportController) importFromICal(data, calendarID, userID, organizationId string) ([]models.CalendarEvent, []string) {
	events := make([]models.CalendarEvent, 0)
	errors := make([]string, 0)

	// Basic iCal parsing (simplified implementation)
	lines := strings.Split(data, "\n")
	var currentEvent *models.CalendarEvent

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "BEGIN:VEVENT" {
			currentEvent = &models.CalendarEvent{
				CalendarID:     &calendarID,
				OrganizationID: organizationId,
				BaseModel: models.BaseModel{
					CreatedBy: &userID,
				},
			}
		} else if line == "END:VEVENT" && currentEvent != nil {
			if currentEvent.Title != "" {
				events = append(events, *currentEvent)
			}
			currentEvent = nil
		} else if currentEvent != nil && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]

				switch key {
				case "SUMMARY":
					currentEvent.Title = value
				case "DESCRIPTION":
					currentEvent.Description = value
				case "LOCATION":
					currentEvent.Location = value
				case "DTSTART":
					if t, err := ic.parseICalDateTime(value); err == nil {
						currentEvent.StartTime = t
					}
				case "DTEND":
					if t, err := ic.parseICalDateTime(value); err == nil {
						currentEvent.EndTime = t
					}
				}
			}
		}
	}

	return events, errors
}

func (ic *ImportController) importFromCSV(data, calendarID, userID, organizationId string) ([]models.CalendarEvent, []string) {
	events := make([]models.CalendarEvent, 0)
	errors := make([]string, 0)

	lines := strings.Split(data, "\n")
	if len(lines) < 2 {
		errors = append(errors, "CSV must have at least a header and one data row")
		return events, errors
	}

	// Parse header
	headers := strings.Split(lines[0], ",")
	headerMap := make(map[string]int)
	for i, header := range headers {
		headerMap[strings.TrimSpace(strings.ToLower(header))] = i
	}

	// Parse data rows
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < len(headers) {
			errors = append(errors, fmt.Sprintf("Row %d has insufficient fields", i+1))
			continue
		}

		event := models.CalendarEvent{
			CalendarID:     &calendarID,
			OrganizationID: organizationId,
			BaseModel: models.BaseModel{
				CreatedBy: &userID,
			},
		}

		// Map CSV fields to event fields
		if idx, exists := headerMap["title"]; exists && idx < len(fields) {
			event.Title = strings.Trim(fields[idx], "\"")
		}
		if idx, exists := headerMap["description"]; exists && idx < len(fields) {
			event.Description = strings.Trim(fields[idx], "\"")
		}
		if idx, exists := headerMap["location"]; exists && idx < len(fields) {
			event.Location = strings.Trim(fields[idx], "\"")
		}
		if idx, exists := headerMap["start_time"]; exists && idx < len(fields) {
			if t, err := time.Parse(time.RFC3339, strings.Trim(fields[idx], "\"")); err == nil {
				event.StartTime = t
			}
		}
		if idx, exists := headerMap["end_time"]; exists && idx < len(fields) {
			if t, err := time.Parse(time.RFC3339, strings.Trim(fields[idx], "\"")); err == nil {
				event.EndTime = t
			}
		}

		if event.Title != "" {
			events = append(events, event)
		}
	}

	return events, errors
}

func (ic *ImportController) importFromJSON(data, calendarID, userID, organizationId string) ([]models.CalendarEvent, []string) {
	events := make([]models.CalendarEvent, 0)
	errors := make([]string, 0)

	var jsonEvents []map[string]interface{}
	if err := json.Unmarshal([]byte(data), &jsonEvents); err != nil {
		errors = append(errors, "Invalid JSON format: "+err.Error())
		return events, errors
	}

	for i, eventData := range jsonEvents {
		event := models.CalendarEvent{
			CalendarID:     &calendarID,
			OrganizationID: organizationId,
			BaseModel: models.BaseModel{
				CreatedBy: &userID,
			},
		}

		if title, ok := eventData["title"].(string); ok {
			event.Title = title
		} else if summary, ok := eventData["summary"].(string); ok {
			event.Title = summary
		}

		if description, ok := eventData["description"].(string); ok {
			event.Description = description
		}

		if location, ok := eventData["location"].(string); ok {
			event.Location = location
		}

		if startTime, ok := eventData["start_time"].(string); ok {
			if t, err := time.Parse(time.RFC3339, startTime); err == nil {
				event.StartTime = t
			}
		}

		if endTime, ok := eventData["end_time"].(string); ok {
			if t, err := time.Parse(time.RFC3339, endTime); err == nil {
				event.EndTime = t
			}
		}

		if event.Title != "" {
			events = append(events, event)
		} else {
			errors = append(errors, fmt.Sprintf("Event %d missing required title field", i+1))
		}
	}

	return events, errors
}

func (ic *ImportController) importFromGoogleCalendar(data, calendarID, userID, organizationId string) ([]models.CalendarEvent, []string) {
	events := make([]models.CalendarEvent, 0)
	errors := make([]string, 0)

	var googleData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &googleData); err != nil {
		errors = append(errors, "Invalid Google Calendar JSON format: "+err.Error())
		return events, errors
	}

	items, ok := googleData["items"].([]interface{})
	if !ok {
		errors = append(errors, "No items array found in Google Calendar data")
		return events, errors
	}

	for i, item := range items {
		eventMap, ok := item.(map[string]interface{})
		if !ok {
			errors = append(errors, fmt.Sprintf("Item %d is not a valid event object", i+1))
			continue
		}

		event := models.CalendarEvent{
			CalendarID:     &calendarID,
			OrganizationID: organizationId,
			BaseModel: models.BaseModel{
				CreatedBy: &userID,
			},
		}

		if summary, ok := eventMap["summary"].(string); ok {
			event.Title = summary
		}

		if description, ok := eventMap["description"].(string); ok {
			event.Description = description
		}

		if location, ok := eventMap["location"].(string); ok {
			event.Location = location
		}

		// Parse start time
		if start, ok := eventMap["start"].(map[string]interface{}); ok {
			if dateTime, ok := start["dateTime"].(string); ok {
				if t, err := time.Parse(time.RFC3339, dateTime); err == nil {
					event.StartTime = t
				}
			}
		}

		// Parse end time
		if end, ok := eventMap["end"].(map[string]interface{}); ok {
			if dateTime, ok := end["dateTime"].(string); ok {
				if t, err := time.Parse(time.RFC3339, dateTime); err == nil {
					event.EndTime = t
				}
			}
		}

		if event.Title != "" {
			events = append(events, event)
		} else {
			errors = append(errors, fmt.Sprintf("Event %d missing required summary field", i+1))
		}
	}

	return events, errors
}

// Helper functions for export formats

func (ic *ImportController) exportToICal(events []models.CalendarEvent, calendar models.UserCalendar) string {
	var ical strings.Builder

	ical.WriteString("BEGIN:VCALENDAR\r\n")
	ical.WriteString("VERSION:2.0\r\n")
	ical.WriteString("PRODID:-//Goravel Calendar//EN\r\n")
	ical.WriteString(fmt.Sprintf("X-WR-CALNAME:%s\r\n", calendar.Name))

	for _, event := range events {
		ical.WriteString("BEGIN:VEVENT\r\n")
		ical.WriteString(fmt.Sprintf("UID:%s\r\n", event.ID))
		ical.WriteString(fmt.Sprintf("SUMMARY:%s\r\n", event.Title))
		if event.Description != "" {
			ical.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", event.Description))
		}
		if event.Location != "" {
			ical.WriteString(fmt.Sprintf("LOCATION:%s\r\n", event.Location))
		}
		ical.WriteString(fmt.Sprintf("DTSTART:%s\r\n", event.StartTime.UTC().Format("20060102T150405Z")))
		ical.WriteString(fmt.Sprintf("DTEND:%s\r\n", event.EndTime.UTC().Format("20060102T150405Z")))
		ical.WriteString(fmt.Sprintf("CREATED:%s\r\n", event.CreatedAt.UTC().Format("20060102T150405Z")))
		ical.WriteString(fmt.Sprintf("LAST-MODIFIED:%s\r\n", event.UpdatedAt.UTC().Format("20060102T150405Z")))
		ical.WriteString("END:VEVENT\r\n")
	}

	ical.WriteString("END:VCALENDAR\r\n")
	return ical.String()
}

func (ic *ImportController) exportToCSV(events []models.CalendarEvent) string {
	var csv strings.Builder

	// Header
	csv.WriteString("Title,Description,Location,Start Time,End Time,Created,Updated\n")

	// Data rows
	for _, event := range events {
		csv.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","%s","%s","%s"`+"\n",
			event.Title,
			event.Description,
			event.Location,
			event.StartTime.Format(time.RFC3339),
			event.EndTime.Format(time.RFC3339),
			event.CreatedAt.Format(time.RFC3339),
			event.UpdatedAt.Format(time.RFC3339),
		))
	}

	return csv.String()
}

func (ic *ImportController) exportToJSON(events []models.CalendarEvent) string {
	exportEvents := make([]map[string]interface{}, len(events))

	for i, event := range events {
		exportEvents[i] = map[string]interface{}{
			"id":           event.ID,
			"title":        event.Title,
			"description":  event.Description,
			"location":     event.Location,
			"start_time":   event.StartTime.Format(time.RFC3339),
			"end_time":     event.EndTime.Format(time.RFC3339),
			"is_all_day":   event.IsAllDay,
			"is_recurring": event.IsRecurring,
			"timezone":     event.Timezone,
			"status":       event.Status,
			"color":        event.Color,
			"created_at":   event.CreatedAt.Format(time.RFC3339),
			"updated_at":   event.UpdatedAt.Format(time.RFC3339),
		}
	}

	jsonData, _ := json.MarshalIndent(exportEvents, "", "  ")
	return string(jsonData)
}

// Helper function to parse iCal datetime
func (ic *ImportController) parseICalDateTime(value string) (time.Time, error) {
	// Remove timezone info for simple parsing
	value = strings.Replace(value, "Z", "", 1)

	// Try different formats
	formats := []string{
		"20060102T150405",
		"20060102",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", value)
}
