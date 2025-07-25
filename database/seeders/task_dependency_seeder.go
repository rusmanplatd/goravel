package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskDependencySeeder struct{}

func (s *TaskDependencySeeder) Signature() string {
	return "TaskDependencySeeder"
}

func (s *TaskDependencySeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var tasks []models.Task
	err := facades.Orm().Query().Limit(2).Find(&tasks)
	if err != nil || len(tasks) < 2 {
		return nil
	}
	dependency := models.TaskDependency{
		TaskID:          tasks[0].ID,
		DependentTaskID: tasks[1].ID,
		Type:            "blocks",
		IsActive:        true,
	}
	facades.Orm().Query().Create(&dependency)
	return nil
}
