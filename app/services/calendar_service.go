package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
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
	// TODO: Implement push notification service
	facades.Log().Info("Push reminder would be sent", map[string]interface{}{
		"user_id": reminder.UserID,
		"event":   reminder.Event.Title,
	})
	return nil
}

// sendSMSReminder sends an SMS reminder
func (cs *CalendarService) sendSMSReminder(reminder *models.EventReminder) error {
	// TODO: Implement SMS service
	facades.Log().Info("SMS reminder would be sent", map[string]interface{}{
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
	// This is a simplified RRULE parser
	// In production, you'd use a proper library like github.com/teambition/rrule-go

	var instances []models.CalendarEvent
	currentTime := event.StartTime

	// Simple weekly recurrence for now
	if event.RecurrenceUntil != nil {
		for currentTime.Before(*event.RecurrenceUntil) {
			instance := *event
			instance.ID = "" // Clear ID for new instance
			instance.StartTime = currentTime
			instance.EndTime = currentTime.Add(event.EndTime.Sub(event.StartTime))
			instance.ParentEventID = &event.ID

			instances = append(instances, instance)

			// Move to next week
			currentTime = currentTime.AddDate(0, 0, 7)
		}
	}

	return instances
}
