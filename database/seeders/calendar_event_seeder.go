package seeders

import (
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/models"
)

type CalendarEventSeeder struct {
}

// Signature The unique signature for the seeder.
func (r *CalendarEventSeeder) Signature() string {
	return "calendar_event_seeder"
}

// Run executes the seeder.
func (r *CalendarEventSeeder) Run() error {
	// Get existing users and tenants for relationships
	var users []models.User
	facades.Orm().Query().Limit(5).Find(&users)
	if len(users) == 0 {
		return nil // No users to create events for
	}

	var tenants []models.Tenant
	facades.Orm().Query().Limit(3).Find(&tenants)
	if len(tenants) == 0 {
		return nil // No tenants to create events for
	}

	// Create sample calendar events
	events := []models.CalendarEvent{
		{
			Title:          "Team Standup Meeting",
			Description:    "Daily team standup to discuss progress and blockers",
			StartTime:      time.Now().AddDate(0, 0, 1).Add(9 * time.Hour), // Tomorrow at 9 AM
			EndTime:        time.Now().AddDate(0, 0, 1).Add(9*time.Hour + 30*time.Minute),
			Location:       "Conference Room A",
			Color:          "#3B82F6",
			Type:           "meeting",
			IsAllDay:       false,
			IsRecurring:    true,
			RecurrenceRule: "FREQ=DAILY;INTERVAL=1;BYDAY=MO,TU,WE,TH,FR",
			RecurrenceUntil: func() *time.Time {
				t := time.Now().AddDate(0, 1, 0) // 1 month from now
				return &t
			}(),
			Timezone:  "UTC",
			Status:    "scheduled",
			TenantID:  tenants[0].ID,
			CreatedBy: users[0].ID,
		},
		{
			Title:          "Project Review",
			Description:    "Monthly project review with stakeholders",
			StartTime:      time.Now().AddDate(0, 0, 3).Add(14 * time.Hour), // 3 days from now at 2 PM
			EndTime:        time.Now().AddDate(0, 0, 3).Add(15*time.Hour + 30*time.Minute),
			Location:       "Board Room",
			Color:          "#EF4444",
			Type:           "meeting",
			IsAllDay:       false,
			IsRecurring:    true,
			RecurrenceRule: "FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=15",
			RecurrenceUntil: func() *time.Time {
				t := time.Now().AddDate(1, 0, 0) // 1 year from now
				return &t
			}(),
			Timezone:  "UTC",
			Status:    "scheduled",
			TenantID:  tenants[0].ID,
			CreatedBy: users[0].ID,
		},
		{
			Title:       "Client Meeting",
			Description: "Quarterly client meeting to discuss project progress",
			StartTime:   time.Now().AddDate(0, 0, 7).Add(10 * time.Hour), // 1 week from now at 10 AM
			EndTime:     time.Now().AddDate(0, 0, 7).Add(11*time.Hour + 30*time.Minute),
			Location:    "Zoom Meeting",
			Color:       "#10B981",
			Type:        "meeting",
			IsAllDay:    false,
			IsRecurring: false,
			Timezone:    "UTC",
			Status:      "scheduled",
			TenantID:    tenants[0].ID,
			CreatedBy:   users[1].ID,
		},
		{
			Title:          "All Hands Meeting",
			Description:    "Company-wide all hands meeting",
			StartTime:      time.Now().AddDate(0, 0, 14).Add(16 * time.Hour), // 2 weeks from now at 4 PM
			EndTime:        time.Now().AddDate(0, 0, 14).Add(17*time.Hour + 30*time.Minute),
			Location:       "Main Auditorium",
			Color:          "#8B5CF6",
			Type:           "meeting",
			IsAllDay:       false,
			IsRecurring:    true,
			RecurrenceRule: "FREQ=WEEKLY;INTERVAL=2;BYDAY=FR",
			RecurrenceUntil: func() *time.Time {
				t := time.Now().AddDate(0, 6, 0) // 6 months from now
				return &t
			}(),
			Timezone:  "UTC",
			Status:    "scheduled",
			TenantID:  tenants[0].ID,
			CreatedBy: users[0].ID,
		},
		{
			Title:       "Birthday Party",
			Description: "Team birthday celebration",
			StartTime:   time.Now().AddDate(0, 0, 5).Add(18 * time.Hour), // 5 days from now at 6 PM
			EndTime:     time.Now().AddDate(0, 0, 5).Add(20 * time.Hour),
			Location:    "Office Kitchen",
			Color:       "#F59E0B",
			Type:        "event",
			IsAllDay:    false,
			IsRecurring: false,
			Timezone:    "UTC",
			Status:      "scheduled",
			TenantID:    tenants[0].ID,
			CreatedBy:   users[2].ID,
		},
	}

	// Create events
	for i := range events {
		if err := facades.Orm().Query().Create(&events[i]); err != nil {
			return err
		}

		// Add participants to each event
		for j, user := range users {
			if j >= 3 { // Limit to 3 participants per event
				break
			}
			participant := models.EventParticipant{
				EventID:        events[i].ID,
				UserID:         user.ID,
				Role:           "attendee",
				ResponseStatus: "pending",
				IsRequired:     true,
				SendReminder:   true,
			}
			if j == 0 {
				participant.Role = "organizer"
				participant.ResponseStatus = "accepted"
			}
			if err := facades.Orm().Query().Create(&participant); err != nil {
				return err
			}
		}

		// Create meeting details for meeting type events
		if events[i].Type == "meeting" {
			meeting := models.Meeting{
				EventID:                 events[i].ID,
				MeetingType:             "video",
				Platform:                "zoom",
				MeetingURL:              "https://zoom.us/j/" + helpers.GenerateULID()[:8],
				MeetingID:               helpers.GenerateULID()[:8],
				Passcode:                "123456",
				MeetingNotes:            "Agenda will be shared before the meeting",
				RecordMeeting:           false,
				AllowJoinBeforeHost:     true,
				MuteParticipantsOnEntry: false,
				WaitingRoom:             "enabled",
			}
			if err := facades.Orm().Query().Create(&meeting); err != nil {
				return err
			}
		}
	}

	return nil
}
