package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type MeetingSeeder struct{}

func (s *MeetingSeeder) Signature() string {
	return "MeetingSeeder"
}

func (s *MeetingSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var event models.CalendarEvent
	err := facades.Orm().Query().First(&event)
	if err != nil {
		return nil
	}
	meeting := models.Meeting{
		EventID:     event.ID,
		MeetingType: "video",
		Platform:    "Zoom",
		MeetingURL:  "https://zoom.us/j/123456789",
		MeetingID:   "123456789",
		Passcode:    "123456",
	}
	facades.Orm().Query().Create(&meeting)
	return nil
}
