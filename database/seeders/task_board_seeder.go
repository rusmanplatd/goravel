package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskBoardSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TaskBoardSeeder) Signature() string {
	return "TaskBoardSeeder"
}

// Run executes the seeder logic.
func (s *TaskBoardSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get projects to associate boards with
	var projects []models.Project
	err := facades.Orm().Query().Find(&projects)
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		facades.Log().Warning("No projects found, skipping task board seeding")
		return nil
	}

	// Get users for board creation
	var users []models.User
	err = facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		return err
	}

	// Create sample task boards for each project
	for i, project := range projects {
		// Create different boards based on project type
		var boards []map[string]interface{}

		// Default board for all projects
		boards = append(boards, map[string]interface{}{
			"name":        "Main Board",
			"description": "Main development workflow board",
			"type":        "kanban",
			"color":       "#3B82F6",
			"icon":        "board",
			"is_active":   true,
			"is_default":  true,
			"settings":    `{"columns":["todo","in_progress","review","done"],"filters":{"assignee":"all","priority":"all"}}`,
		})

		// Additional boards based on project type
		if project.Status == "active" {
			boards = append(boards, map[string]interface{}{
				"name":        "Sprint Board",
				"description": "Current sprint tasks and progress",
				"type":        "kanban",
				"color":       "#10B981",
				"icon":        "sprint",
				"is_active":   true,
				"is_default":  false,
				"settings":    `{"columns":["backlog","sprint_ready","in_progress","testing","done"],"filters":{"sprint":"current"}}`,
			})
		}

		if project.Status == "planning" {
			boards = append(boards, map[string]interface{}{
				"name":        "Planning Board",
				"description": "Project planning and requirements",
				"type":        "list",
				"color":       "#F59E0B",
				"icon":        "planning",
				"is_active":   true,
				"is_default":  false,
				"settings":    `{"columns":["ideas","requirements","design","approved"],"filters":{"status":"planning"}}`,
			})
		}

		// Get creator user
		var createdBy string
		if len(users) > 0 {
			createdBy = users[i%len(users)].ID
		}

		for _, boardData := range boards {
			// Check if board already exists for this project
			var existingBoard models.TaskBoard
			err := facades.Orm().Query().Where("name = ? AND project_id = ?", boardData["name"], project.ID).First(&existingBoard)
			if err == nil {
				continue // Board already exists
			}

			board := models.TaskBoard{
				Name:        boardData["name"].(string),
				Description: boardData["description"].(string),
				Type:        boardData["type"].(string),
				Color:       boardData["color"].(string),
				Icon:        boardData["icon"].(string),
				IsActive:    boardData["is_active"].(bool),
				IsDefault:   boardData["is_default"].(bool),
				ProjectID:   project.ID,
				Settings:    boardData["settings"].(string),
				BaseModel: models.BaseModel{
					CreatedBy: &createdBy,
				},
			}

			err = facades.Orm().Query().Create(&board)
			if err != nil {
				facades.Log().Error("Failed to create task board: " + err.Error())
				return err
			}

			facades.Log().Info("Created task board: " + board.Name + " for project: " + project.Name)
		}
	}

	return nil
}
