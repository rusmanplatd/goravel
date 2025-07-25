package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type EventParticipantSeeder struct{}

func (s *EventParticipantSeeder) Signature() string {
	return "EventParticipantSeeder"
}

func (s *EventParticipantSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	var event models.CalendarEvent
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	err = facades.Orm().Query().First(&event)
	if err != nil {
		return nil
	}
	participant := models.EventParticipant{
		EventID:        event.ID,
		UserID:         user.ID,
		Role:           "attendee",
		ResponseStatus: "accepted",
	}
	facades.Orm().Query().Create(&participant)
	return nil
}
