package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"goravel/app/models"
	"goravel/app/notifications"

	"github.com/goravel/framework/facades"
	"github.com/teambition/rrule-go"
)

type CalendarService struct {
	emailService *EmailService
}

func NewCalendarService() *CalendarService {
	return &CalendarService{
		emailService: NewEmailService(),
	}
}

// ScheduleReminders schedules reminders for a calendar event
func (cs *CalendarService) ScheduleReminders(event *models.CalendarEvent) error {
	if event.ReminderSettings == "" {
		return nil // No reminders configured
	}

	// Parse reminder settings
	var reminderSettings map[string]int
	if err := json.Unmarshal([]byte(event.ReminderSettings), &reminderSettings); err != nil {
		return fmt.Errorf("invalid reminder settings: %v", err)
	}

	// Get event participants
	var participants []models.EventParticipant
	err := facades.Orm().Query().Where("event_id = ? AND send_reminder = ?", event.ID, true).Find(&participants)
	if err != nil {
		return fmt.Errorf("failed to get participants: %v", err)
	}

	// Create reminders for each participant and type
	for _, participant := range participants {
		for reminderType, minutesBefore := range reminderSettings {
			scheduledAt := event.StartTime.Add(-time.Duration(minutesBefore) * time.Minute)

			// Only create future reminders
			if scheduledAt.After(time.Now()) {
				reminder := models.EventReminder{
					EventID:       event.ID,
					UserID:        participant.UserID,
					Type:          reminderType,
					MinutesBefore: minutesBefore,
					ScheduledAt:   scheduledAt,
					Status:        "pending",
				}

				if err := facades.Orm().Query().Create(&reminder); err != nil {
					facades.Log().Error("Failed to create reminder", map[string]interface{}{
						"event_id": event.ID,
						"user_id":  participant.UserID,
						"type":     reminderType,
						"error":    err.Error(),
					})
				}
			}
		}
	}

	return nil
}

// ProcessDueReminders processes reminders that are due to be sent
func (cs *CalendarService) ProcessDueReminders() error {
	var reminders []models.EventReminder
	err := facades.Orm().Query().
		Where("status = ? AND scheduled_at <= ?", "pending", time.Now()).
		With("Event").With("User").
		Find(&reminders)
	if err != nil {
		return fmt.Errorf("failed to get due reminders: %v", err)
	}

	for _, reminder := range reminders {
		if err := cs.sendReminder(&reminder); err != nil {
			facades.Log().Error("Failed to send reminder", map[string]interface{}{
				"reminder_id": reminder.ID,
				"error":       err.Error(),
			})

			// Mark reminder as failed
			reminder.Status = "failed"
			reminder.ErrorMessage = err.Error()
			facades.Orm().Query().Save(&reminder)
		} else {
			// Mark reminder as sent
			now := time.Now()
			reminder.Status = "sent"
			reminder.Sent = true
			reminder.SentAt = &now
			facades.Orm().Query().Save(&reminder)
		}
	}

	return nil
}

// sendReminder sends a reminder based on its type
func (cs *CalendarService) sendReminder(reminder *models.EventReminder) error {
	switch reminder.Type {
	case "email":
		return cs.sendEmailReminder(reminder)
	case "push":
		return cs.sendPushReminder(reminder)
	case "sms":
		return cs.sendSMSReminder(reminder)
	default:
		return fmt.Errorf("unknown reminder type: %s", reminder.Type)
	}
}

// sendEmailReminder sends an email reminder
func (cs *CalendarService) sendEmailReminder(reminder *models.EventReminder) error {
	subject := fmt.Sprintf("Reminder: %s", reminder.Event.Title)
	body := fmt.Sprintf(`
		<h2>Event Reminder</h2>
		<p>This is a reminder for your upcoming event:</p>
		<ul>
			<li><strong>Event:</strong> %s</li>
			<li><strong>Time:</strong> %s</li>
			<li><strong>Location:</strong> %s</li>
		</ul>
		<p>Event starts in %d minutes.</p>
	`, reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04"), reminder.Event.Location, reminder.MinutesBefore)

	return cs.emailService.SendEmail(reminder.User.Email, subject, body, body)
}

// sendPushReminder sends a push notification reminder
func (cs *CalendarService) sendPushReminder(reminder *models.EventReminder) error {
	// Create a notification for the event reminder
	notificationService := NewNotificationService()

	// Create notification using BaseNotification
	notification := notifications.NewBaseNotification()
	notification.SetType("event_reminder")
	notification.SetTitle("Event Reminder")
	notification.SetBody(fmt.Sprintf("Reminder: %s is starting at %s", reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04")))
	notification.SetChannels([]string{"push"})
	notification.SetActionURL("/calendar").SetActionText("View Event")
	notification.AddData("event_title", reminder.Event.Title)
	notification.AddData("event_time", reminder.Event.StartTime)

	// Send push notification
	ctx := context.Background()
	err := notificationService.SendNow(ctx, notification, reminder.User)
	if err != nil {
		facades.Log().Error("Failed to send push reminder", map[string]interface{}{
			"user_id": reminder.UserID,
			"event":   reminder.Event.Title,
			"error":   err.Error(),
		})
		return err
	}

	facades.Log().Info("Push reminder sent successfully", map[string]interface{}{
		"user_id": reminder.UserID,
		"event":   reminder.Event.Title,
	})

	return nil
}

// sendSMSReminder sends an SMS reminder
func (cs *CalendarService) sendSMSReminder(reminder *models.EventReminder) error {
	// Create a notification for the event reminder
	notificationService := NewNotificationService()

	// Create notification using BaseNotification
	notification := notifications.NewBaseNotification()
	notification.SetType("event_reminder")
	notification.SetTitle("Event Reminder")
	notification.SetBody(fmt.Sprintf("Reminder: %s is starting at %s", reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04")))
	notification.SetChannels([]string{"sms"})
	notification.AddData("event_title", reminder.Event.Title)
	notification.AddData("event_time", reminder.Event.StartTime)

	// Send SMS notification
	ctx := context.Background()
	err := notificationService.SendNow(ctx, notification, reminder.User)
	if err != nil {
		facades.Log().Error("Failed to send SMS reminder", map[string]interface{}{
			"user_id": reminder.UserID,
			"event":   reminder.Event.Title,
			"error":   err.Error(),
		})
		return err
	}

	facades.Log().Info("SMS reminder sent successfully", map[string]interface{}{
		"user_id": reminder.UserID,
		"event":   reminder.Event.Title,
	})

	return nil
}

// CheckConflicts checks for scheduling conflicts
func (cs *CalendarService) CheckConflicts(startTime, endTime time.Time, userIDs []string, excludeEventID string) (map[string]interface{}, error) {
	// Build query for conflicting events
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id IN ?", userIDs).
		Where("(start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?) OR (start_time >= ? AND end_time <= ?)",
			endTime, startTime, endTime, startTime, startTime, endTime)

	// Exclude specific event if provided
	if excludeEventID != "" {
		query = query.Where("calendar_events.id != ?", excludeEventID)
	}

	var conflictingEvents []models.CalendarEvent
	err := query.With("Participants.User").Find(&conflictingEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to check conflicts: %v", err)
	}

	// Group conflicts by user
	conflictsByUser := make(map[string][]models.CalendarEvent)
	for _, event := range conflictingEvents {
		for _, participant := range event.Participants {
			for _, userID := range userIDs {
				if userID == participant.UserID {
					conflictsByUser[participant.UserID] = append(conflictsByUser[participant.UserID], event)
					break
				}
			}
		}
	}

	return map[string]interface{}{
		"has_conflicts":      len(conflictingEvents) > 0,
		"conflicts_by_user":  conflictsByUser,
		"total_conflicts":    len(conflictingEvents),
		"conflicting_events": conflictingEvents,
	}, nil
}

// GenerateRecurringEvents generates recurring event instances
func (cs *CalendarService) GenerateRecurringEvents(event *models.CalendarEvent) error {
	if !event.IsRecurring || event.RecurrenceRule == "" {
		return nil
	}

	// Parse RRULE and generate instances using production-ready rrule-go library
	instances := cs.parseRRULE(event)

	for _, instance := range instances {
		// Check if instance already exists
		var existingInstance models.CalendarEvent
		err := facades.Orm().Query().Where("parent_event_id = ? AND start_time = ?", event.ID, instance.StartTime).First(&existingInstance)
		if err == nil {
			continue // Instance already exists
		}

		// Create new instance
		instance.ParentEventID = &event.ID
		instance.OrganizationID = event.OrganizationID
		instance.CreatedBy = event.CreatedBy

		if err := facades.Orm().Query().Create(&instance); err != nil {
			facades.Log().Error("Failed to create recurring instance", map[string]interface{}{
				"parent_event_id": event.ID,
				"start_time":      instance.StartTime,
				"error":           err.Error(),
			})
		}
	}

	return nil
}

// parseRRULE parses RRULE and generates event instances using production-ready rrule-go library
func (cs *CalendarService) parseRRULE(event *models.CalendarEvent) []models.CalendarEvent {
	var instances []models.CalendarEvent

	if event.RecurrenceRule == "" {
		return instances
	}

	// Parse RRULE using production-ready rrule-go library
	rule, err := rrule.StrToRRule(event.RecurrenceRule)
	if err != nil {
		facades.Log().Error("Failed to parse RRULE with rrule-go", map[string]interface{}{
			"event_id":        event.ID,
			"recurrence_rule": event.RecurrenceRule,
			"error":           err.Error(),
		})
		return instances
	}

	// Set reasonable limits for recurring events
	maxInstances := 100                         // Prevent infinite generation
	endDate := event.StartTime.AddDate(2, 0, 0) // Generate up to 2 years ahead

	// If event has an end date, use the earlier of the two
	if !event.EndTime.IsZero() && event.EndTime.Before(endDate) {
		endDate = event.EndTime
	}

	// Generate occurrences
	occurrences := rule.Between(event.StartTime, endDate, true)

	// Limit the number of instances
	if len(occurrences) > maxInstances {
		occurrences = occurrences[:maxInstances]
		facades.Log().Warning("RRULE generated too many instances, limiting to maximum", map[string]interface{}{
			"event_id":      event.ID,
			"max_instances": maxInstances,
			"total_found":   len(rule.Between(event.StartTime, endDate, true)),
		})
	}

	// Convert occurrences to calendar event instances
	duration := cs.calculateEventDuration(event)

	for _, occurrence := range occurrences {
		// Skip the original event time
		if occurrence.Equal(event.StartTime) {
			continue
		}

		instance := models.CalendarEvent{
			Title:          event.Title,
			Description:    event.Description,
			StartTime:      occurrence,
			EndTime:        occurrence.Add(duration),
			Location:       event.Location,
			Color:          event.Color,
			Type:           event.Type,
			IsAllDay:       event.IsAllDay,
			IsRecurring:    false, // Instances are not recurring themselves
			RecurrenceRule: "",    // Clear recurrence rule for instances
			ParentEventID:  &event.ID,
			OrganizationID: event.OrganizationID,
			Status:         event.Status,
			Timezone:       event.Timezone,
		}

		instances = append(instances, instance)
	}

	facades.Log().Info("Generated recurring instances with rrule-go", map[string]interface{}{
		"event_id":          event.ID,
		"instance_count":    len(instances),
		"rule_string":       event.RecurrenceRule,
		"total_occurrences": len(occurrences),
	})

	return instances
}

// calculateEventDuration calculates the duration of an event
func (cs *CalendarService) calculateEventDuration(event *models.CalendarEvent) time.Duration {
	// EndTime is not a pointer in the model, so check if it's zero value
	if event.EndTime.IsZero() {
		// Default duration for events without end time
		if event.IsAllDay {
			return 24 * time.Hour
		}
		return time.Hour // Default 1 hour duration
	}

	return event.EndTime.Sub(event.StartTime)
}

// ValidateRRULE validates an RRULE string using the production library
func (cs *CalendarService) ValidateRRULE(rruleStr string) error {
	if rruleStr == "" {
		return nil // Empty RRULE is valid (no recurrence)
	}

	// Try to parse the RRULE
	_, err := rrule.StrToRRule(rruleStr)
	if err != nil {
		return fmt.Errorf("invalid RRULE: %w", err)
	}

	return nil
}

// GetNextOccurrence gets the next occurrence of a recurring event after a given date
func (cs *CalendarService) GetNextOccurrence(event *models.CalendarEvent, after time.Time) (*time.Time, error) {
	if !event.IsRecurring || event.RecurrenceRule == "" {
		return nil, fmt.Errorf("event is not recurring")
	}

	// Parse RRULE
	rule, err := rrule.StrToRRule(event.RecurrenceRule)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RRULE: %w", err)
	}

	// Get next occurrence after the specified time
	next := rule.After(after, true)
	if next.IsZero() {
		return nil, nil // No more occurrences
	}

	return &next, nil
}

// GetOccurrencesBetween gets all occurrences of a recurring event between two dates
func (cs *CalendarService) GetOccurrencesBetween(event *models.CalendarEvent, start, end time.Time) ([]time.Time, error) {
	if !event.IsRecurring || event.RecurrenceRule == "" {
		// For non-recurring events, check if the event falls within the range
		if (event.StartTime.After(start) || event.StartTime.Equal(start)) &&
			(event.StartTime.Before(end) || event.StartTime.Equal(end)) {
			return []time.Time{event.StartTime}, nil
		}
		return []time.Time{}, nil
	}

	// Parse RRULE
	rule, err := rrule.StrToRRule(event.RecurrenceRule)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RRULE: %w", err)
	}

	// Get occurrences between dates
	occurrences := rule.Between(start, end, true)

	return occurrences, nil
}

// GenerateRRULE creates an RRULE string from common recurrence parameters
func (cs *CalendarService) GenerateRRULE(frequency string, interval int, count int, until *time.Time, byDay []string) (string, error) {
	var parts []string

	// Frequency is required
	if frequency == "" {
		return "", fmt.Errorf("frequency is required")
	}

	// Validate frequency
	validFreqs := map[string]bool{
		"DAILY": true, "WEEKLY": true, "MONTHLY": true, "YEARLY": true,
	}
	if !validFreqs[frequency] {
		return "", fmt.Errorf("invalid frequency: %s", frequency)
	}

	parts = append(parts, fmt.Sprintf("FREQ=%s", frequency))

	// Add interval if specified and greater than 1
	if interval > 1 {
		parts = append(parts, fmt.Sprintf("INTERVAL=%d", interval))
	}

	// Add count or until (mutually exclusive)
	if count > 0 && until != nil {
		return "", fmt.Errorf("COUNT and UNTIL are mutually exclusive")
	}

	if count > 0 {
		parts = append(parts, fmt.Sprintf("COUNT=%d", count))
	}

	if until != nil {
		// Format until date in UTC
		parts = append(parts, fmt.Sprintf("UNTIL=%s", until.UTC().Format("20060102T150405Z")))
	}

	// Add by day if specified
	if len(byDay) > 0 {
		// Validate day names
		validDays := map[string]bool{
			"MO": true, "TU": true, "WE": true, "TH": true, "FR": true, "SA": true, "SU": true,
		}

		for _, day := range byDay {
			if !validDays[day] {
				return "", fmt.Errorf("invalid day: %s", day)
			}
		}

		parts = append(parts, fmt.Sprintf("BYDAY=%s", strings.Join(byDay, ",")))
	}

	rruleStr := strings.Join(parts, ";")

	// Validate the generated RRULE
	if err := cs.ValidateRRULE(rruleStr); err != nil {
		return "", fmt.Errorf("generated invalid RRULE: %w", err)
	}

	return rruleStr, nil
}

// CreateRecurringEventException creates an exception for a recurring event
func (cs *CalendarService) CreateRecurringEventException(parentEventID string, exceptionDate time.Time, modificationType string, newData map[string]interface{}) (*models.CalendarEvent, error) {
	// Get parent event
	var parentEvent models.CalendarEvent
	err := facades.Orm().Query().Where("id = ?", parentEventID).First(&parentEvent)
	if err != nil {
		return nil, fmt.Errorf("parent event not found: %v", err)
	}

	switch modificationType {
	case "cancel":
		// Create a cancelled instance
		exception := models.CalendarEvent{
			Title:          parentEvent.Title + " (Cancelled)",
			Description:    parentEvent.Description,
			StartTime:      exceptionDate,
			EndTime:        exceptionDate.Add(parentEvent.EndTime.Sub(parentEvent.StartTime)),
			Location:       parentEvent.Location,
			Color:          parentEvent.Color,
			Type:           parentEvent.Type,
			Status:         "cancelled",
			ParentEventID:  &parentEvent.ID,
			OrganizationID: parentEvent.OrganizationID,
			CalendarType:   parentEvent.CalendarType,
			Visibility:     parentEvent.Visibility,
			Priority:       parentEvent.Priority,
		}

		if err := facades.Orm().Query().Create(&exception); err != nil {
			return nil, fmt.Errorf("failed to create exception: %v", err)
		}

		return &exception, nil

	case "modify":
		// Create a modified instance
		exception := models.CalendarEvent{
			Title:          parentEvent.Title,
			Description:    parentEvent.Description,
			StartTime:      exceptionDate,
			EndTime:        exceptionDate.Add(parentEvent.EndTime.Sub(parentEvent.StartTime)),
			Location:       parentEvent.Location,
			Color:          parentEvent.Color,
			Type:           parentEvent.Type,
			Status:         "scheduled",
			ParentEventID:  &parentEvent.ID,
			OrganizationID: parentEvent.OrganizationID,
			CalendarType:   parentEvent.CalendarType,
			Visibility:     parentEvent.Visibility,
			Priority:       parentEvent.Priority,
		}

		// Apply modifications
		if title, ok := newData["title"]; ok {
			exception.Title = title.(string)
		}
		if description, ok := newData["description"]; ok {
			exception.Description = description.(string)
		}
		if location, ok := newData["location"]; ok {
			exception.Location = location.(string)
		}
		if startTime, ok := newData["start_time"]; ok {
			if t, ok := startTime.(time.Time); ok {
				exception.StartTime = t
			}
		}
		if endTime, ok := newData["end_time"]; ok {
			if t, ok := endTime.(time.Time); ok {
				exception.EndTime = t
			}
		}

		if err := facades.Orm().Query().Create(&exception); err != nil {
			return nil, fmt.Errorf("failed to create modified exception: %v", err)
		}

		return &exception, nil

	default:
		return nil, fmt.Errorf("invalid modification type: %s", modificationType)
	}
}

// UpdateRecurringSeries updates an entire recurring series
func (cs *CalendarService) UpdateRecurringSeries(parentEventID string, updateData map[string]interface{}, updateFuture bool) error {
	// Get parent event
	var parentEvent models.CalendarEvent
	err := facades.Orm().Query().Where("id = ?", parentEventID).First(&parentEvent)
	if err != nil {
		return fmt.Errorf("parent event not found: %v", err)
	}

	// Update parent event
	if title, ok := updateData["title"]; ok {
		_, err = facades.Orm().Query().Model(&parentEvent).Where("id = ?", parentEventID).Update("title", title)
		if err != nil {
			return err
		}
	}
	if description, ok := updateData["description"]; ok {
		_, err = facades.Orm().Query().Model(&parentEvent).Where("id = ?", parentEventID).Update("description", description)
		if err != nil {
			return err
		}
	}
	if location, ok := updateData["location"]; ok {
		_, err = facades.Orm().Query().Model(&parentEvent).Where("id = ?", parentEventID).Update("location", location)
		if err != nil {
			return err
		}
	}

	// Update future instances if requested
	if updateFuture {
		if title, ok := updateData["title"]; ok {
			_, err = facades.Orm().Query().Model(&models.CalendarEvent{}).
				Where("parent_event_id = ? AND start_time >= ?", parentEventID, time.Now()).
				Update("title", title)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
