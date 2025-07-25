package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskActivitySeeder struct{}

func (s *TaskActivitySeeder) Signature() string {
	return "TaskActivitySeeder"
}

func (s *TaskActivitySeeder) Run() error {
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
	activity := models.TaskActivity{
		TaskID:      task.ID,
		UserID:      user.ID,
		Type:        "created",
		Description: "Task created",
		Data:        "{\"action\":\"created\"}",
	}
	facades.Orm().Query().Create(&activity)
	return nil
}
