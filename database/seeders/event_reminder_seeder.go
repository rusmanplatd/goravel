package seeders

import (
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type EventReminderSeeder struct {
}

// Signature The unique signature for the seeder.
func (r *EventReminderSeeder) Signature() string {
	return "event_reminder_seeder"
}

// Run executes the seeder.
func (r *EventReminderSeeder) Run() error {
	// Get existing calendar events
	var events []models.CalendarEvent
	facades.Orm().Query().Limit(10).Find(&events)
	if len(events) == 0 {
		return nil // No events to create reminders for
	}

	// Get existing users
	var users []models.User
	facades.Orm().Query().Limit(5).Find(&users)
	if len(users) == 0 {
		return nil // No users to create reminders for
	}

	// Create sample reminders
	for _, event := range events {
		// Create reminders for each user
		for _, user := range users {
			// Create email reminder (15 minutes before)
			emailReminder := models.EventReminder{
				EventID:       event.ID,
				UserID:        user.ID,
				Type:          "email",
				MinutesBefore: 15,
				ScheduledAt:   event.StartTime.Add(-15 * time.Minute),
				Status:        "pending",
			}
			if err := facades.Orm().Query().Create(&emailReminder); err != nil {
				facades.Log().Error("Failed to create email reminder", map[string]interface{}{
					"event_id": event.ID,
					"user_id":  user.ID,
					"error":    err.Error(),
				})
			}

			// Create push reminder (30 minutes before)
			pushReminder := models.EventReminder{
				EventID:       event.ID,
				UserID:        user.ID,
				Type:          "push",
				MinutesBefore: 30,
				ScheduledAt:   event.StartTime.Add(-30 * time.Minute),
				Status:        "pending",
			}
			if err := facades.Orm().Query().Create(&pushReminder); err != nil {
				facades.Log().Error("Failed to create push reminder", map[string]interface{}{
					"event_id": event.ID,
					"user_id":  user.ID,
					"error":    err.Error(),
				})
			}

			// Create SMS reminder (60 minutes before) for some users
			if user.ID == users[0].ID { // Only for first user
				smsReminder := models.EventReminder{
					EventID:       event.ID,
					UserID:        user.ID,
					Type:          "sms",
					MinutesBefore: 60,
					ScheduledAt:   event.StartTime.Add(-60 * time.Minute),
					Status:        "pending",
				}
				if err := facades.Orm().Query().Create(&smsReminder); err != nil {
					facades.Log().Error("Failed to create SMS reminder", map[string]interface{}{
						"event_id": event.ID,
						"user_id":  user.ID,
						"error":    err.Error(),
					})
				}
			}
		}
	}

	facades.Log().Info("Event reminder seeder completed", map[string]interface{}{
		"events_processed": len(events),
		"users_processed":  len(users),
	})

	return nil
}
