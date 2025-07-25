package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type TaskTimeEntrySeeder struct{}

func (s *TaskTimeEntrySeeder) Signature() string {
	return "TaskTimeEntrySeeder"
}

func (s *TaskTimeEntrySeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	var task models.Task
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	err = facades.Orm().Query().First(&task)
	if err != nil {
		return nil
	}
	startTime := time.Now().Add(-8 * time.Hour)
	endTime := time.Now()
	timeEntry := models.TaskTimeEntry{
		TaskID:      task.ID,
		UserID:      user.ID,
		Description: "Worked on task implementation",
		StartTime:   startTime,
		EndTime:     &endTime,
		Duration:    8.0,
		IsBillable:  true,
		Rate:        50.00,
	}
	facades.Orm().Query().Create(&timeEntry)
	return nil
}
