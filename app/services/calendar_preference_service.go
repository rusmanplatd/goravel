package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CalendarPreferenceService struct{}

func NewCalendarPreferenceService() *CalendarPreferenceService {
	return &CalendarPreferenceService{}
}

// GetUserPreferences retrieves user calendar preferences
func (cps *CalendarPreferenceService) GetUserPreferences(userID, organizationID string) (*models.CalendarPreference, error) {
	var preferences models.CalendarPreference
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		First(&preferences)

	if err != nil {
		// Create default preferences if none exist
		return cps.CreateDefaultPreferences(userID, organizationID)
	}

	return &preferences, nil
}

// CreateDefaultPreferences creates default calendar preferences for a user
func (cps *CalendarPreferenceService) CreateDefaultPreferences(userID, organizationID string) (*models.CalendarPreference, error) {
	preferences := models.CalendarPreference{
		UserID:                  userID,
		OrganizationID:          organizationID,
		DefaultView:             "week",
		WeekStartsOn:            1, // Monday
		DefaultEventDuration:    60,
		WorkingHoursStart:       "09:00",
		WorkingHoursEnd:         "17:00",
		WorkingDays:             "[1,2,3,4,5]", // Monday to Friday
		TimeFormat:              "24h",
		DateFormat:              "YYYY-MM-DD",
		Timezone:                "UTC",
		Language:                "en-US",
		ShowWeekends:            true,
		ShowDeclinedEvents:      false,
		DefaultEventVisibility:  "private",
		DefaultReminders:        "{\"popup\": 10}",
		AutoAcceptInvitations:   false,
		ShowEventDetailsInMonth: true,
		EnableKeyboardShortcuts: true,
		EnableDragAndDrop:       true,
		EnableQuickAdd:          true,
		CompactView:             false,
		ShowLunarCalendar:       false,
		ColorTheme:              "auto",
		NotificationPreferences: "{\"email\": true, \"push\": false}",
		SyncPreferences:         "{\"auto_sync\": false}",
		PrivacySettings:         "{\"show_free_busy\": true}",
	}

	if err := facades.Orm().Query().Create(&preferences); err != nil {
		return nil, fmt.Errorf("failed to create default preferences: %v", err)
	}

	// Create default keyboard shortcuts
	if err := cps.CreateDefaultKeyboardShortcuts(userID, organizationID); err != nil {
		facades.Log().Warning("Failed to create default keyboard shortcuts", map[string]interface{}{
			"user_id":         userID,
			"organization_id": organizationID,
			"error":           err.Error(),
		})
	}

	return &preferences, nil
}

// UpdatePreferences updates user calendar preferences
func (cps *CalendarPreferenceService) UpdatePreferences(userID, organizationID string, updates map[string]interface{}) (*models.CalendarPreference, error) {
	var preferences models.CalendarPreference
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		First(&preferences)

	if err != nil {
		return nil, fmt.Errorf("preferences not found: %v", err)
	}

	// Update fields
	updateQuery := facades.Orm().Query().Model(&preferences).Where("user_id = ? AND organization_id = ?", userID, organizationID)

	for field, value := range updates {
		switch field {
		case "default_view", "time_format", "date_format", "timezone", "language",
			"default_event_visibility", "color_theme", "working_hours_start", "working_hours_end":
			if str, ok := value.(string); ok {
				_, err = updateQuery.Update(field, str)
			}
		case "week_starts_on", "default_event_duration":
			if num, ok := value.(int); ok {
				_, err = updateQuery.Update(field, num)
			}
		case "show_weekends", "show_declined_events", "auto_accept_invitations",
			"show_event_details_in_month", "enable_keyboard_shortcuts", "enable_drag_and_drop",
			"enable_quick_add", "compact_view", "show_lunar_calendar":
			if b, ok := value.(bool); ok {
				_, err = updateQuery.Update(field, b)
			}
		case "working_days", "default_reminders", "notification_preferences",
			"sync_preferences", "privacy_settings", "custom_css":
			if str, ok := value.(string); ok {
				_, err = updateQuery.Update(field, str)
			}
		}

		if err != nil {
			return nil, fmt.Errorf("failed to update %s: %v", field, err)
		}
	}

	// Reload updated preferences
	err = facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		First(&preferences)

	if err != nil {
		return nil, fmt.Errorf("failed to reload preferences: %v", err)
	}

	return &preferences, nil
}

// CreateDefaultKeyboardShortcuts creates default keyboard shortcuts for a user
func (cps *CalendarPreferenceService) CreateDefaultKeyboardShortcuts(userID, organizationID string) error {
	shortcuts := []models.CalendarKeyboardShortcut{
		{UserID: userID, OrganizationID: organizationID, Action: "create_event", KeyCombination: "C", Description: "Create new event"},
		{UserID: userID, OrganizationID: organizationID, Action: "go_to_today", KeyCombination: "T", Description: "Go to today"},
		{UserID: userID, OrganizationID: organizationID, Action: "previous_period", KeyCombination: "J", Description: "Previous period"},
		{UserID: userID, OrganizationID: organizationID, Action: "next_period", KeyCombination: "K", Description: "Next period"},
		{UserID: userID, OrganizationID: organizationID, Action: "day_view", KeyCombination: "1", Description: "Switch to day view"},
		{UserID: userID, OrganizationID: organizationID, Action: "week_view", KeyCombination: "2", Description: "Switch to week view"},
		{UserID: userID, OrganizationID: organizationID, Action: "month_view", KeyCombination: "3", Description: "Switch to month view"},
		{UserID: userID, OrganizationID: organizationID, Action: "year_view", KeyCombination: "4", Description: "Switch to year view"},
		{UserID: userID, OrganizationID: organizationID, Action: "search", KeyCombination: "/", Description: "Search events"},
		{UserID: userID, OrganizationID: organizationID, Action: "refresh", KeyCombination: "R", Description: "Refresh calendar"},
		{UserID: userID, OrganizationID: organizationID, Action: "settings", KeyCombination: ",", Description: "Open settings"},
		{UserID: userID, OrganizationID: organizationID, Action: "help", KeyCombination: "?", Description: "Show help"},
	}

	for _, shortcut := range shortcuts {
		if err := facades.Orm().Query().Create(&shortcut); err != nil {
			facades.Log().Warning("Failed to create keyboard shortcut", map[string]interface{}{
				"action": shortcut.Action,
				"error":  err.Error(),
			})
		}
	}

	return nil
}

// GetKeyboardShortcuts retrieves user keyboard shortcuts
func (cps *CalendarPreferenceService) GetKeyboardShortcuts(userID, organizationID string) ([]models.CalendarKeyboardShortcut, error) {
	var shortcuts []models.CalendarKeyboardShortcut
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Order("action ASC").
		Find(&shortcuts)

	if err != nil {
		return nil, fmt.Errorf("failed to get keyboard shortcuts: %v", err)
	}

	// If no shortcuts exist, create defaults
	if len(shortcuts) == 0 {
		if err := cps.CreateDefaultKeyboardShortcuts(userID, organizationID); err == nil {
			return cps.GetKeyboardShortcuts(userID, organizationID)
		}
	}

	return shortcuts, nil
}

// UpdateKeyboardShortcut updates a keyboard shortcut
func (cps *CalendarPreferenceService) UpdateKeyboardShortcut(shortcutID, userID, organizationID string, updates map[string]interface{}) error {
	updateQuery := facades.Orm().Query().Model(&models.CalendarKeyboardShortcut{}).
		Where("id = ? AND user_id = ? AND organization_id = ?", shortcutID, userID, organizationID)

	for field, value := range updates {
		switch field {
		case "key_combination", "description":
			if str, ok := value.(string); ok {
				_, err := updateQuery.Update(field, str)
				if err != nil {
					return fmt.Errorf("failed to update %s: %v", field, err)
				}
			}
		case "is_enabled":
			if b, ok := value.(bool); ok {
				_, err := updateQuery.Update(field, b)
				if err != nil {
					return fmt.Errorf("failed to update %s: %v", field, err)
				}
			}
		}
	}

	return nil
}

// SaveViewState saves a calendar view state
func (cps *CalendarPreferenceService) SaveViewState(userID, organizationID, name, viewType string, configuration map[string]interface{}) (*models.CalendarViewState, error) {
	configJSON, err := json.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %v", err)
	}

	viewState := models.CalendarViewState{
		UserID:         userID,
		OrganizationID: organizationID,
		Name:           name,
		ViewType:       viewType,
		Configuration:  string(configJSON),
		LastUsedAt:     &[]time.Time{time.Now()}[0],
	}

	if err := facades.Orm().Query().Create(&viewState); err != nil {
		return nil, fmt.Errorf("failed to save view state: %v", err)
	}

	return &viewState, nil
}

// GetViewStates retrieves user view states
func (cps *CalendarPreferenceService) GetViewStates(userID, organizationID string) ([]models.CalendarViewState, error) {
	var viewStates []models.CalendarViewState
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Order("last_used_at DESC").
		Find(&viewStates)

	if err != nil {
		return nil, fmt.Errorf("failed to get view states: %v", err)
	}

	return viewStates, nil
}

// SetDefaultViewState sets a view state as default
func (cps *CalendarPreferenceService) SetDefaultViewState(viewStateID, userID, organizationID string) error {
	// First, unset all default view states for the user
	_, err := facades.Orm().Query().Model(&models.CalendarViewState{}).
		Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Update("is_default", false)

	if err != nil {
		return fmt.Errorf("failed to unset default view states: %v", err)
	}

	// Set the specified view state as default
	_, err = facades.Orm().Query().Model(&models.CalendarViewState{}).
		Where("id = ? AND user_id = ? AND organization_id = ?", viewStateID, userID, organizationID).
		Update("is_default", true)

	if err != nil {
		return fmt.Errorf("failed to set default view state: %v", err)
	}

	return nil
}

// DeleteViewState deletes a view state
func (cps *CalendarPreferenceService) DeleteViewState(viewStateID, userID, organizationID string) error {
	_, err := facades.Orm().Query().Model(&models.CalendarViewState{}).
		Where("id = ? AND user_id = ? AND organization_id = ?", viewStateID, userID, organizationID).
		Delete()

	if err != nil {
		return fmt.Errorf("failed to delete view state: %v", err)
	}

	return nil
}

// GetWorkingHours returns user's working hours
func (cps *CalendarPreferenceService) GetWorkingHours(userID, organizationID string) (map[string]interface{}, error) {
	preferences, err := cps.GetUserPreferences(userID, organizationID)
	if err != nil {
		return nil, err
	}

	var workingDays []int
	if err := json.Unmarshal([]byte(preferences.WorkingDays), &workingDays); err != nil {
		workingDays = []int{1, 2, 3, 4, 5} // Default to Monday-Friday
	}

	return map[string]interface{}{
		"start_time":   preferences.WorkingHoursStart,
		"end_time":     preferences.WorkingHoursEnd,
		"working_days": workingDays,
		"timezone":     preferences.Timezone,
	}, nil
}

// IsWithinWorkingHours checks if a time is within user's working hours
func (cps *CalendarPreferenceService) IsWithinWorkingHours(userID, organizationID string, checkTime time.Time) (bool, error) {
	workingHours, err := cps.GetWorkingHours(userID, organizationID)
	if err != nil {
		return false, err
	}

	workingDays, ok := workingHours["working_days"].([]int)
	if !ok {
		return false, fmt.Errorf("invalid working days format")
	}

	// Check if the day is a working day
	dayOfWeek := int(checkTime.Weekday())
	isWorkingDay := false
	for _, day := range workingDays {
		if day == dayOfWeek {
			isWorkingDay = true
			break
		}
	}

	if !isWorkingDay {
		return false, nil
	}

	// Check if the time is within working hours
	timeStr := checkTime.Format("15:04")
	startTime := workingHours["start_time"].(string)
	endTime := workingHours["end_time"].(string)

	return timeStr >= startTime && timeStr <= endTime, nil
}

// GetUserTimezone returns user's preferred timezone
func (cps *CalendarPreferenceService) GetUserTimezone(userID, organizationID string) (string, error) {
	preferences, err := cps.GetUserPreferences(userID, organizationID)
	if err != nil {
		return "UTC", err
	}

	return preferences.Timezone, nil
}

// ExportPreferences exports user preferences as JSON
func (cps *CalendarPreferenceService) ExportPreferences(userID, organizationID string) (map[string]interface{}, error) {
	preferences, err := cps.GetUserPreferences(userID, organizationID)
	if err != nil {
		return nil, err
	}

	shortcuts, err := cps.GetKeyboardShortcuts(userID, organizationID)
	if err != nil {
		return nil, err
	}

	viewStates, err := cps.GetViewStates(userID, organizationID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"preferences":        preferences,
		"keyboard_shortcuts": shortcuts,
		"view_states":        viewStates,
		"exported_at":        time.Now(),
	}, nil
}

// ImportPreferences imports user preferences from JSON
func (cps *CalendarPreferenceService) ImportPreferences(userID, organizationID string, data map[string]interface{}) error {
	// Import preferences
	if prefsData, ok := data["preferences"].(map[string]interface{}); ok {
		_, err := cps.UpdatePreferences(userID, organizationID, prefsData)
		if err != nil {
			return fmt.Errorf("failed to import preferences: %v", err)
		}
	}

	// Import keyboard shortcuts
	if shortcutsData, ok := data["keyboard_shortcuts"].([]interface{}); ok {
		// Clear existing shortcuts
		facades.Orm().Query().Model(&models.CalendarKeyboardShortcut{}).
			Where("user_id = ? AND organization_id = ?", userID, organizationID).
			Delete()

		// Import new shortcuts
		for _, shortcutData := range shortcutsData {
			if shortcut, ok := shortcutData.(map[string]interface{}); ok {
				newShortcut := models.CalendarKeyboardShortcut{
					UserID:         userID,
					OrganizationID: organizationID,
					Action:         shortcut["action"].(string),
					KeyCombination: shortcut["key_combination"].(string),
					Description:    shortcut["description"].(string),
					IsEnabled:      shortcut["is_enabled"].(bool),
				}
				facades.Orm().Query().Create(&newShortcut)
			}
		}
	}

	return nil
}
