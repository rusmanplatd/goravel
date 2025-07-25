package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"goravel/app/models"
	"goravel/app/notifications"

	"github.com/goravel/framework/facades"
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
	notification.SetAction("/calendar", "View Event")
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

	// Parse RRULE and generate instances
	// This is a simplified implementation - in production, you'd use a proper RRULE parser
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
		instance.TenantID = event.TenantID
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

// parseRRULE parses RRULE and generates event instances
func (cs *CalendarService) parseRRULE(event *models.CalendarEvent) []models.CalendarEvent {
	// Enhanced RRULE parser supporting common recurrence patterns
	// For production use, consider github.com/teambition/rrule-go or similar

	var instances []models.CalendarEvent

	if event.RecurrenceRule == "" {
		return instances
	}

	// Parse RRULE string
	rrule, err := cs.parseRRULEString(event.RecurrenceRule)
	if err != nil {
		facades.Log().Error("Failed to parse RRULE", map[string]interface{}{
			"event_id":        event.ID,
			"recurrence_rule": event.RecurrenceRule,
			"error":           err.Error(),
		})
		return instances
	}

	// Generate instances based on the parsed rule
	instances = cs.generateRecurrenceInstances(event, rrule)

	facades.Log().Info("Generated recurring instances", map[string]interface{}{
		"event_id":       event.ID,
		"instance_count": len(instances),
		"frequency":      rrule.Frequency,
		"interval":       rrule.Interval,
	})

	return instances
}

// RRULERule represents a parsed RRULE
type RRULERule struct {
	Frequency  string     // DAILY, WEEKLY, MONTHLY, YEARLY
	Interval   int        // Interval between occurrences
	Count      int        // Number of occurrences (0 = unlimited)
	Until      *time.Time // End date
	ByDay      []string   // Days of week (MO, TU, WE, etc.)
	ByMonth    []int      // Months (1-12)
	ByMonthDay []int      // Days of month (1-31)
}

// parseRRULEString parses an RRULE string into a structured format
func (cs *CalendarService) parseRRULEString(rruleStr string) (*RRULERule, error) {
	rule := &RRULERule{
		Interval: 1, // Default interval
	}

	// Remove RRULE: prefix if present
	if strings.HasPrefix(rruleStr, "RRULE:") {
		rruleStr = strings.TrimPrefix(rruleStr, "RRULE:")
	}

	// Split by semicolon
	parts := strings.Split(rruleStr, ";")

	for _, part := range parts {
		keyValue := strings.Split(part, "=")
		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		switch key {
		case "FREQ":
			rule.Frequency = value
		case "INTERVAL":
			if interval, err := strconv.Atoi(value); err == nil {
				rule.Interval = interval
			}
		case "COUNT":
			if count, err := strconv.Atoi(value); err == nil {
				rule.Count = count
			}
		case "UNTIL":
			if until, err := time.Parse("20060102T150405Z", value); err == nil {
				rule.Until = &until
			} else if until, err := time.Parse("20060102", value); err == nil {
				rule.Until = &until
			}
		case "BYDAY":
			rule.ByDay = strings.Split(value, ",")
		case "BYMONTH":
			for _, monthStr := range strings.Split(value, ",") {
				if month, err := strconv.Atoi(monthStr); err == nil {
					rule.ByMonth = append(rule.ByMonth, month)
				}
			}
		case "BYMONTHDAY":
			for _, dayStr := range strings.Split(value, ",") {
				if day, err := strconv.Atoi(dayStr); err == nil {
					rule.ByMonthDay = append(rule.ByMonthDay, day)
				}
			}
		}
	}

	// Validate required fields
	if rule.Frequency == "" {
		return nil, fmt.Errorf("FREQ is required in RRULE")
	}

	return rule, nil
}

// generateRecurrenceInstances generates event instances based on the RRULE
func (cs *CalendarService) generateRecurrenceInstances(event *models.CalendarEvent, rule *RRULERule) []models.CalendarEvent {
	var instances []models.CalendarEvent

	// Determine end condition
	maxInstances := 100 // Safety limit
	if rule.Count > 0 && rule.Count < maxInstances {
		maxInstances = rule.Count
	}

	endTime := time.Now().AddDate(1, 0, 0) // Default: 1 year from now
	if rule.Until != nil {
		endTime = *rule.Until
	}
	if event.RecurrenceUntil != nil && event.RecurrenceUntil.Before(endTime) {
		endTime = *event.RecurrenceUntil
	}

	currentTime := event.StartTime
	duration := event.EndTime.Sub(event.StartTime)
	instanceCount := 0

	for instanceCount < maxInstances && currentTime.Before(endTime) {
		// Check if this occurrence matches the rule criteria
		if cs.matchesRRULECriteria(currentTime, rule) {
			instance := *event
			instance.ID = "" // Clear ID for new instance
			instance.StartTime = currentTime
			instance.EndTime = currentTime.Add(duration)
			instance.ParentEventID = &event.ID

			instances = append(instances, instance)
			instanceCount++
		}

		// Move to next potential occurrence
		currentTime = cs.getNextOccurrence(currentTime, rule)
	}

	return instances
}

// matchesRRULECriteria checks if a given time matches the RRULE criteria
func (cs *CalendarService) matchesRRULECriteria(t time.Time, rule *RRULERule) bool {
	// Check BYDAY constraint
	if len(rule.ByDay) > 0 {
		weekdayMap := map[string]time.Weekday{
			"SU": time.Sunday, "MO": time.Monday, "TU": time.Tuesday,
			"WE": time.Wednesday, "TH": time.Thursday, "FR": time.Friday, "SA": time.Saturday,
		}

		currentWeekday := t.Weekday()
		matchesDay := false

		for _, day := range rule.ByDay {
			if weekdayMap[day] == currentWeekday {
				matchesDay = true
				break
			}
		}

		if !matchesDay {
			return false
		}
	}

	// Check BYMONTH constraint
	if len(rule.ByMonth) > 0 {
		currentMonth := int(t.Month())
		matchesMonth := false

		for _, month := range rule.ByMonth {
			if month == currentMonth {
				matchesMonth = true
				break
			}
		}

		if !matchesMonth {
			return false
		}
	}

	// Check BYMONTHDAY constraint
	if len(rule.ByMonthDay) > 0 {
		currentDay := t.Day()
		matchesDay := false

		for _, day := range rule.ByMonthDay {
			if day == currentDay {
				matchesDay = true
				break
			}
		}

		if !matchesDay {
			return false
		}
	}

	return true
}

// getNextOccurrence calculates the next potential occurrence based on frequency and interval
func (cs *CalendarService) getNextOccurrence(current time.Time, rule *RRULERule) time.Time {
	switch rule.Frequency {
	case "DAILY":
		return current.AddDate(0, 0, rule.Interval)
	case "WEEKLY":
		return current.AddDate(0, 0, 7*rule.Interval)
	case "MONTHLY":
		return current.AddDate(0, rule.Interval, 0)
	case "YEARLY":
		return current.AddDate(rule.Interval, 0, 0)
	default:
		// Default to daily if frequency is unknown
		return current.AddDate(0, 0, 1)
	}
}
