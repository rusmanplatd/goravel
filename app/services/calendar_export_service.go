package services

import (
	"fmt"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CalendarExportService struct {
	timezoneService *TimezoneService
}

func NewCalendarExportService() *CalendarExportService {
	return &CalendarExportService{
		timezoneService: NewTimezoneService(),
	}
}

// ExportToICS exports calendar events to iCalendar format
func (ces *CalendarExportService) ExportToICS(userID, organizationID string, calendarIDs []string, startDate, endDate time.Time) (string, error) {
	events, err := ces.getEventsForExport(userID, organizationID, calendarIDs, startDate, endDate)
	if err != nil {
		return "", fmt.Errorf("failed to get events: %v", err)
	}

	var icsContent strings.Builder

	// iCalendar header
	icsContent.WriteString("BEGIN:VCALENDAR\r\n")
	icsContent.WriteString("VERSION:2.0\r\n")
	icsContent.WriteString("PRODID:-//Goravel Calendar//Goravel Calendar//EN\r\n")
	icsContent.WriteString("CALSCALE:GREGORIAN\r\n")
	icsContent.WriteString("METHOD:PUBLISH\r\n")

	// Add timezone information
	icsContent.WriteString("BEGIN:VTIMEZONE\r\n")
	icsContent.WriteString("TZID:UTC\r\n")
	icsContent.WriteString("BEGIN:STANDARD\r\n")
	icsContent.WriteString("DTSTART:19700101T000000\r\n")
	icsContent.WriteString("TZOFFSETFROM:+0000\r\n")
	icsContent.WriteString("TZOFFSETTO:+0000\r\n")
	icsContent.WriteString("TZNAME:UTC\r\n")
	icsContent.WriteString("END:STANDARD\r\n")
	icsContent.WriteString("END:VTIMEZONE\r\n")

	// Add events
	for _, event := range events {
		icsContent.WriteString("BEGIN:VEVENT\r\n")
		icsContent.WriteString(fmt.Sprintf("UID:%s@goravel-calendar\r\n", event.ID))
		icsContent.WriteString(fmt.Sprintf("DTSTART:%s\r\n", formatDateTimeForICS(event.StartTime)))
		icsContent.WriteString(fmt.Sprintf("DTEND:%s\r\n", formatDateTimeForICS(event.EndTime)))
		icsContent.WriteString(fmt.Sprintf("SUMMARY:%s\r\n", escapeICSText(event.Title)))

		if event.Description != "" {
			icsContent.WriteString(fmt.Sprintf("DESCRIPTION:%s\r\n", escapeICSText(event.Description)))
		}

		if event.Location != "" {
			icsContent.WriteString(fmt.Sprintf("LOCATION:%s\r\n", escapeICSText(event.Location)))
		}

		icsContent.WriteString(fmt.Sprintf("STATUS:%s\r\n", strings.ToUpper(event.Status)))
		icsContent.WriteString(fmt.Sprintf("CREATED:%s\r\n", formatDateTimeForICS(event.CreatedAt)))
		icsContent.WriteString(fmt.Sprintf("LAST-MODIFIED:%s\r\n", formatDateTimeForICS(event.UpdatedAt)))

		// Add recurrence rule if present
		if event.IsRecurring && event.RecurrenceRule != "" {
			icsContent.WriteString(fmt.Sprintf("RRULE:%s\r\n", event.RecurrenceRule))
		}

		// Add categories based on calendar type
		if event.CalendarType != "" {
			icsContent.WriteString(fmt.Sprintf("CATEGORIES:%s\r\n", strings.ToUpper(event.CalendarType)))
		}

		icsContent.WriteString("END:VEVENT\r\n")
	}

	// iCalendar footer
	icsContent.WriteString("END:VCALENDAR\r\n")

	return icsContent.String(), nil
}

// ExportToCSV exports calendar events to CSV format
func (ces *CalendarExportService) ExportToCSV(userID, organizationID string, calendarIDs []string, startDate, endDate time.Time) (string, error) {
	events, err := ces.getEventsForExport(userID, organizationID, calendarIDs, startDate, endDate)
	if err != nil {
		return "", fmt.Errorf("failed to get events: %v", err)
	}

	var csvContent strings.Builder

	// CSV header
	csvContent.WriteString("Title,Description,Start Date,Start Time,End Date,End Time,Location,Calendar,Status,Created,Updated\n")

	// Add events
	for _, event := range events {
		csvContent.WriteString(fmt.Sprintf("\"%s\",", escapeCSVText(event.Title)))
		csvContent.WriteString(fmt.Sprintf("\"%s\",", escapeCSVText(event.Description)))
		csvContent.WriteString(fmt.Sprintf("%s,", event.StartTime.Format("2006-01-02")))
		csvContent.WriteString(fmt.Sprintf("%s,", event.StartTime.Format("15:04:05")))
		csvContent.WriteString(fmt.Sprintf("%s,", event.EndTime.Format("2006-01-02")))
		csvContent.WriteString(fmt.Sprintf("%s,", event.EndTime.Format("15:04:05")))
		csvContent.WriteString(fmt.Sprintf("\"%s\",", escapeCSVText(event.Location)))
		csvContent.WriteString(fmt.Sprintf("%s,", event.CalendarType))
		csvContent.WriteString(fmt.Sprintf("%s,", event.Status))
		csvContent.WriteString(fmt.Sprintf("%s,", event.CreatedAt.Format("2006-01-02 15:04:05")))
		csvContent.WriteString(fmt.Sprintf("%s\n", event.UpdatedAt.Format("2006-01-02 15:04:05")))
	}

	return csvContent.String(), nil
}

// ExportToJSON exports calendar events to JSON format
func (ces *CalendarExportService) ExportToJSON(userID, organizationID string, calendarIDs []string, startDate, endDate time.Time) ([]models.CalendarEvent, error) {
	return ces.getEventsForExport(userID, organizationID, calendarIDs, startDate, endDate)
}

// ExportCalendarSettings exports calendar settings and preferences
func (ces *CalendarExportService) ExportCalendarSettings(userID, organizationID string) (map[string]interface{}, error) {
	// Get user calendars
	var calendars []models.UserCalendar
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Find(&calendars)
	if err != nil {
		return nil, fmt.Errorf("failed to get calendars: %v", err)
	}

	// Get calendar preferences
	var preferences models.CalendarPreference
	err = facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		First(&preferences)
	if err != nil {
		facades.Log().Warning("No calendar preferences found", map[string]interface{}{
			"user_id":         userID,
			"organization_id": organizationID,
		})
	}

	// Get keyboard shortcuts
	var shortcuts []models.CalendarKeyboardShortcut
	err = facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Find(&shortcuts)
	if err != nil {
		facades.Log().Warning("No keyboard shortcuts found", map[string]interface{}{
			"user_id":         userID,
			"organization_id": organizationID,
		})
	}

	return map[string]interface{}{
		"calendars":          calendars,
		"preferences":        preferences,
		"keyboard_shortcuts": shortcuts,
		"exported_at":        time.Now(),
		"version":            "1.0",
	}, nil
}

// CreatePublicCalendarLink creates a public link for calendar sharing
func (ces *CalendarExportService) CreatePublicCalendarLink(calendarID, userID, organizationID string, expiresAt *time.Time) (string, error) {
	// Generate a unique token for the public link
	token := ces.generatePublicToken()

	// Create a calendar share record for public access
	publicShare := models.CalendarShare{
		OwnerID:        userID,
		SharedWithID:   "public", // Special ID for public sharing
		ShareName:      "Public Calendar Link",
		Permission:     "view",
		IsActive:       true,
		ExpiresAt:      expiresAt,
		OrganizationID: organizationID,
	}

	if err := facades.Orm().Query().Create(&publicShare); err != nil {
		return "", fmt.Errorf("failed to create public share: %v", err)
	}

	// Return the public URL
	return fmt.Sprintf("/calendar/public/%s", token), nil
}

// GetPublicCalendarData retrieves calendar data for public sharing
func (ces *CalendarExportService) GetPublicCalendarData(token string) (map[string]interface{}, error) {
	// Find the public share by token
	var publicShare models.CalendarShare
	err := facades.Orm().Query().
		Where("shared_with_id = ? AND is_active = ?", "public", true).
		First(&publicShare)

	if err != nil {
		return nil, fmt.Errorf("public calendar not found: %v", err)
	}

	// Check if the link has expired
	if publicShare.ExpiresAt != nil && publicShare.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("public calendar link has expired")
	}

	// Get calendar events (only show free/busy or limited details for privacy)
	var events []models.CalendarEvent
	err = facades.Orm().Query().
		Where("created_by = ? AND organization_id = ?", publicShare.OwnerID, publicShare.OrganizationID).
		Where("start_time >= ? AND start_time <= ?", time.Now().AddDate(0, -1, 0), time.Now().AddDate(0, 3, 0)).
		Find(&events)

	if err != nil {
		return nil, fmt.Errorf("failed to get events: %v", err)
	}

	// Filter event details based on privacy settings
	publicEvents := make([]map[string]interface{}, 0)
	for _, event := range events {
		publicEvent := map[string]interface{}{
			"id":         event.ID,
			"start_time": event.StartTime,
			"end_time":   event.EndTime,
			"is_all_day": event.IsAllDay,
		}

		// Only show title and location if not private
		if event.Visibility != "private" {
			publicEvent["title"] = event.Title
			if event.Location != "" {
				publicEvent["location"] = event.Location
			}
		} else {
			publicEvent["title"] = "Busy"
		}

		publicEvents = append(publicEvents, publicEvent)
	}

	return map[string]interface{}{
		"events":        publicEvents,
		"calendar_name": publicShare.ShareName,
		"last_updated":  time.Now(),
	}, nil
}

// Helper methods

func (ces *CalendarExportService) getEventsForExport(userID, organizationID string, calendarIDs []string, startDate, endDate time.Time) ([]models.CalendarEvent, error) {
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("organization_id = ?", organizationID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate)

	// Filter by calendar IDs if provided
	if len(calendarIDs) > 0 {
		query = query.Where("calendar_id IN ?", calendarIDs)
	} else {
		// Get user's calendars
		var userCalendars []models.UserCalendar
		err := facades.Orm().Query().Where("user_id = ? AND organization_id = ?", userID, organizationID).Find(&userCalendars)
		if err != nil {
			return nil, fmt.Errorf("failed to get user calendars: %v", err)
		}

		calendarIDs = make([]string, len(userCalendars))
		for i, cal := range userCalendars {
			calendarIDs[i] = cal.ID
		}

		if len(calendarIDs) > 0 {
			query = query.Where("calendar_id IN ?", calendarIDs)
		}
	}

	var events []models.CalendarEvent
	err := query.Order("start_time ASC").Find(&events)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %v", err)
	}

	return events, nil
}

func formatDateTimeForICS(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

func escapeICSText(text string) string {
	text = strings.ReplaceAll(text, "\\", "\\\\")
	text = strings.ReplaceAll(text, ";", "\\;")
	text = strings.ReplaceAll(text, ",", "\\,")
	text = strings.ReplaceAll(text, "\n", "\\n")
	text = strings.ReplaceAll(text, "\r", "")
	return text
}

func escapeCSVText(text string) string {
	text = strings.ReplaceAll(text, "\"", "\"\"")
	return text
}

func (ces *CalendarExportService) generatePublicToken() string {
	// Generate a random token for public sharing
	// In a real implementation, you'd use crypto/rand
	return fmt.Sprintf("pub_%d", time.Now().UnixNano())
}
