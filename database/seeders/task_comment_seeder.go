package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskCommentSeeder struct{}

func (s *TaskCommentSeeder) Signature() string {
	return "TaskCommentSeeder"
}

func (s *TaskCommentSeeder) Run() error {
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
	comment := models.TaskComment{
		TaskID:   task.ID,
		AuthorID: user.ID,
		Type:     "comment",
		Content:  "This is a sample comment.",
	}
	facades.Orm().Query().Create(&comment)
	return nil
}
