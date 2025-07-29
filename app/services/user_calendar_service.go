package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserCalendarService struct {
	notificationService *NotificationService
}

func NewUserCalendarService() *UserCalendarService {
	return &UserCalendarService{
		notificationService: NewNotificationService(),
	}
}

// CreateDefaultCalendars creates default calendars for a new user
func (ucs *UserCalendarService) CreateDefaultCalendars(userID, organizationID string) error {
	defaultCalendars := []models.UserCalendar{
		{
			Name:           "Personal",
			Description:    "Personal events and appointments",
			Color:          "#1976d2",
			Type:           "personal",
			IsVisible:      true,
			IsDefault:      true,
			UserID:         userID,
			OrganizationID: organizationID,
			SortOrder:      1,
		},
		{
			Name:           "Work",
			Description:    "Work-related events and meetings",
			Color:          "#388e3c",
			Type:           "work",
			IsVisible:      true,
			IsDefault:      false,
			UserID:         userID,
			OrganizationID: organizationID,
			SortOrder:      2,
		},
		{
			Name:           "Family",
			Description:    "Family events and activities",
			Color:          "#f57c00",
			Type:           "family",
			IsVisible:      true,
			IsDefault:      false,
			UserID:         userID,
			OrganizationID: organizationID,
			SortOrder:      3,
		},
	}

	for _, calendar := range defaultCalendars {
		if err := facades.Orm().Query().Create(&calendar); err != nil {
			return fmt.Errorf("failed to create default calendar %s: %v", calendar.Name, err)
		}
	}

	return nil
}

// GetUserCalendars retrieves all calendars for a user
func (ucs *UserCalendarService) GetUserCalendars(userID, organizationID string) ([]models.UserCalendar, error) {
	var calendars []models.UserCalendar
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Order("sort_order ASC, created_at ASC").
		Find(&calendars)

	if err != nil {
		return nil, fmt.Errorf("failed to get user calendars: %v", err)
	}

	return calendars, nil
}

// CreateCalendar creates a new calendar for a user
func (ucs *UserCalendarService) CreateCalendar(userID, organizationID string, data map[string]interface{}) (*models.UserCalendar, error) {
	calendar := models.UserCalendar{
		Name:           data["name"].(string),
		Description:    getStringFromMap(data, "description", ""),
		Color:          getStringFromMap(data, "color", "#1976d2"),
		Type:           getStringFromMap(data, "type", "personal"),
		IsVisible:      getBoolFromMap(data, "is_visible", true),
		IsDefault:      false, // Only one default calendar allowed
		Timezone:       getStringFromMap(data, "timezone", "UTC"),
		Visibility:     getStringFromMap(data, "visibility", "private"),
		UserID:         userID,
		OrganizationID: organizationID,
	}

	// Set sort order to be last
	var maxOrder int
	facades.Orm().Query().Model(&models.UserCalendar{}).
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Select("COALESCE(MAX(sort_order), 0)").
		Scan(&maxOrder)
	calendar.SortOrder = maxOrder + 1

	if err := facades.Orm().Query().Create(&calendar); err != nil {
		return nil, fmt.Errorf("failed to create calendar: %v", err)
	}

	return &calendar, nil
}

// UpdateCalendar updates an existing calendar
func (ucs *UserCalendarService) UpdateCalendar(calendarID, userID, organizationID string, data map[string]interface{}) (*models.UserCalendar, error) {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
		First(&calendar)

	if err != nil {
		return nil, fmt.Errorf("calendar not found: %v", err)
	}

	// Update fields if provided
	if name, ok := data["name"]; ok {
		calendar.Name = name.(string)
	}
	if description, ok := data["description"]; ok {
		calendar.Description = description.(string)
	}
	if color, ok := data["color"]; ok {
		calendar.Color = color.(string)
	}
	if calType, ok := data["type"]; ok {
		calendar.Type = calType.(string)
	}
	if isVisible, ok := data["is_visible"]; ok {
		calendar.IsVisible = isVisible.(bool)
	}
	if timezone, ok := data["timezone"]; ok {
		calendar.Timezone = timezone.(string)
	}
	if visibility, ok := data["visibility"]; ok {
		calendar.Visibility = visibility.(string)
	}

	// Handle default calendar setting
	if isDefault, ok := data["is_default"]; ok && isDefault.(bool) {
		// First, unset all other calendars as default
		facades.Orm().Query().Model(&models.UserCalendar{}).
			Where("user_id = ? AND organization_id = ? AND id != ?", userID, organizationID, calendarID).
			Update("is_default", false)
		calendar.IsDefault = true
	}

	if err := facades.Orm().Query().Save(&calendar); err != nil {
		return nil, fmt.Errorf("failed to update calendar: %v", err)
	}

	return &calendar, nil
}

// DeleteCalendar deletes a calendar and handles event migration
func (ucs *UserCalendarService) DeleteCalendar(calendarID, userID, organizationID string) error {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
		First(&calendar)

	if err != nil {
		return fmt.Errorf("calendar not found: %v", err)
	}

	// Don't allow deletion of default calendar
	if calendar.IsDefault {
		return fmt.Errorf("cannot delete default calendar")
	}

	// Find default calendar to migrate events
	var defaultCalendar models.UserCalendar
	err = facades.Orm().Query().
		Where("user_id = ? AND organization_id = ? AND is_default = ?", userID, organizationID, true).
		First(&defaultCalendar)

	if err != nil {
		return fmt.Errorf("no default calendar found for event migration: %v", err)
	}

	// Migrate all events to default calendar
	_, err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("calendar_id = ?", calendarID).
		Update("calendar_id", defaultCalendar.ID)

	if err != nil {
		return fmt.Errorf("failed to migrate events: %v", err)
	}

	// Delete the calendar
	if _, err := facades.Orm().Query().Delete(&calendar); err != nil {
		return fmt.Errorf("failed to delete calendar: %v", err)
	}

	return nil
}

// ReorderCalendars updates the sort order of calendars
func (ucs *UserCalendarService) ReorderCalendars(userID, organizationID string, calendarIDs []string) error {
	for i, calendarID := range calendarIDs {
		_, err := facades.Orm().Query().Model(&models.UserCalendar{}).
			Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
			Update("sort_order", i+1)

		if err != nil {
			return fmt.Errorf("failed to update calendar order: %v", err)
		}
	}

	return nil
}

// ToggleCalendarVisibility toggles the visibility of a calendar
func (ucs *UserCalendarService) ToggleCalendarVisibility(calendarID, userID, organizationID string) (*models.UserCalendar, error) {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
		First(&calendar)

	if err != nil {
		return nil, fmt.Errorf("calendar not found: %v", err)
	}

	calendar.IsVisible = !calendar.IsVisible

	if err := facades.Orm().Query().Save(&calendar); err != nil {
		return nil, fmt.Errorf("failed to toggle calendar visibility: %v", err)
	}

	return &calendar, nil
}

// GetCalendarWithEvents retrieves a calendar with its events
func (ucs *UserCalendarService) GetCalendarWithEvents(calendarID, userID, organizationID string, startDate, endDate time.Time) (*models.UserCalendar, error) {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
		With("Events").
		First(&calendar)

	if err != nil {
		return nil, fmt.Errorf("calendar not found: %v", err)
	}

	return &calendar, nil
}

// GetDefaultCalendar gets the user's default calendar
func (ucs *UserCalendarService) GetDefaultCalendar(userID, organizationID string) (*models.UserCalendar, error) {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ? AND is_default = ?", userID, organizationID, true).
		First(&calendar)

	if err != nil {
		return nil, fmt.Errorf("default calendar not found: %v", err)
	}

	return &calendar, nil
}

// SearchCalendars searches calendars by name or description
func (ucs *UserCalendarService) SearchCalendars(userID, organizationID, query string) ([]models.UserCalendar, error) {
	var calendars []models.UserCalendar
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Where("(name ILIKE ? OR description ILIKE ?)", "%"+query+"%", "%"+query+"%").
		Order("sort_order ASC").
		Find(&calendars)

	if err != nil {
		return nil, fmt.Errorf("failed to search calendars: %v", err)
	}

	return calendars, nil
}

// GetCalendarStatistics returns statistics for a calendar
func (ucs *UserCalendarService) GetCalendarStatistics(calendarID, userID, organizationID string) (map[string]interface{}, error) {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationID).
		First(&calendar)

	if err != nil {
		return nil, fmt.Errorf("calendar not found: %v", err)
	}

	stats := make(map[string]interface{})

	// Total events
	totalEvents, _ := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("calendar_id = ?", calendarID).
		Count()
	stats["total_events"] = totalEvents

	// Events this month
	now := time.Now()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	endOfMonth := startOfMonth.AddDate(0, 1, 0).Add(-time.Nanosecond)

	monthlyEvents, _ := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("calendar_id = ? AND start_time >= ? AND start_time <= ?", calendarID, startOfMonth, endOfMonth).
		Count()
	stats["monthly_events"] = monthlyEvents

	// Upcoming events (next 7 days)
	upcomingEvents, _ := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("calendar_id = ? AND start_time >= ? AND start_time <= ?", calendarID, now, now.AddDate(0, 0, 7)).
		Count()
	stats["upcoming_events"] = upcomingEvents

	return stats, nil
}

// Helper functions
func getStringFromMap(data map[string]interface{}, key, defaultValue string) string {
	if value, ok := data[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func getBoolFromMap(data map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := data[key]; ok {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return defaultValue
}
