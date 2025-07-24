package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskBoardColumnSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TaskBoardColumnSeeder) Signature() string {
	return "TaskBoardColumnSeeder"
}

// Run executes the seeder logic.
func (s *TaskBoardColumnSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get task boards to associate columns with
	var boards []models.TaskBoard
	err := facades.Orm().Query().Find(&boards)
	if err != nil {
		return err
	}

	if len(boards) == 0 {
		facades.Log().Warning("No task boards found, skipping task board column seeding")
		return nil
	}

	// Create columns for each board
	for _, board := range boards {
		var columns []map[string]interface{}

		// Create different columns based on board type
		switch board.Type {
		case "kanban":
			if board.Name == "Main Board" {
				columns = []map[string]interface{}{
					{
						"name":          "To Do",
						"description":   "Tasks that need to be started",
						"color":         "#6B7280",
						"position":      1,
						"status_filter": "todo",
						"task_limit":    20,
						"is_active":     true,
					},
					{
						"name":          "In Progress",
						"description":   "Tasks currently being worked on",
						"color":         "#F59E0B",
						"position":      2,
						"status_filter": "in_progress",
						"task_limit":    10,
						"is_active":     true,
					},
					{
						"name":          "Review",
						"description":   "Tasks ready for review",
						"color":         "#8B5CF6",
						"position":      3,
						"status_filter": "review",
						"task_limit":    15,
						"is_active":     true,
					},
					{
						"name":          "Done",
						"description":   "Completed tasks",
						"color":         "#10B981",
						"position":      4,
						"status_filter": "done",
						"task_limit":    50,
						"is_active":     true,
					},
				}
			} else if board.Name == "Sprint Board" {
				columns = []map[string]interface{}{
					{
						"name":          "Backlog",
						"description":   "Tasks in the backlog",
						"color":         "#6B7280",
						"position":      1,
						"status_filter": "todo",
						"task_limit":    30,
						"is_active":     true,
					},
					{
						"name":          "Sprint Ready",
						"description":   "Tasks ready for current sprint",
						"color":         "#3B82F6",
						"position":      2,
						"status_filter": "todo",
						"task_limit":    15,
						"is_active":     true,
					},
					{
						"name":          "In Progress",
						"description":   "Tasks currently being worked on",
						"color":         "#F59E0B",
						"position":      3,
						"status_filter": "in_progress",
						"task_limit":    8,
						"is_active":     true,
					},
					{
						"name":          "Testing",
						"description":   "Tasks in testing phase",
						"color":         "#EF4444",
						"position":      4,
						"status_filter": "testing",
						"task_limit":    12,
						"is_active":     true,
					},
					{
						"name":          "Done",
						"description":   "Completed tasks",
						"color":         "#10B981",
						"position":      5,
						"status_filter": "done",
						"task_limit":    50,
						"is_active":     true,
					},
				}
			}
		case "list":
			columns = []map[string]interface{}{
				{
					"name":          "Ideas",
					"description":   "Initial ideas and concepts",
					"color":         "#6B7280",
					"position":      1,
					"status_filter": "todo",
					"task_limit":    20,
					"is_active":     true,
				},
				{
					"name":          "Requirements",
					"description":   "Requirements gathering and analysis",
					"color":         "#3B82F6",
					"position":      2,
					"status_filter": "in_progress",
					"task_limit":    15,
					"is_active":     true,
				},
				{
					"name":          "Design",
					"description":   "Design and architecture planning",
					"color":         "#F59E0B",
					"position":      3,
					"status_filter": "in_progress",
					"task_limit":    10,
					"is_active":     true,
				},
				{
					"name":          "Approved",
					"description":   "Approved and ready for development",
					"color":         "#10B981",
					"position":      4,
					"status_filter": "done",
					"task_limit":    25,
					"is_active":     true,
				},
			}
		default:
			// Default columns for any other board type
			columns = []map[string]interface{}{
				{
					"name":          "To Do",
					"description":   "Tasks that need to be started",
					"color":         "#6B7280",
					"position":      1,
					"status_filter": "todo",
					"task_limit":    20,
					"is_active":     true,
				},
				{
					"name":          "In Progress",
					"description":   "Tasks currently being worked on",
					"color":         "#F59E0B",
					"position":      2,
					"status_filter": "in_progress",
					"task_limit":    10,
					"is_active":     true,
				},
				{
					"name":          "Done",
					"description":   "Completed tasks",
					"color":         "#10B981",
					"position":      3,
					"status_filter": "done",
					"task_limit":    50,
					"is_active":     true,
				},
			}
		}

		for _, columnData := range columns {
			// Check if column already exists for this board
			var existingColumn models.TaskBoardColumn
			err := facades.Orm().Query().Where("name = ? AND board_id = ?", columnData["name"], board.ID).First(&existingColumn)
			if err == nil {
				continue // Column already exists
			}

			column := models.TaskBoardColumn{
				Name:         columnData["name"].(string),
				Description:  columnData["description"].(string),
				Color:        columnData["color"].(string),
				Position:     columnData["position"].(int),
				StatusFilter: columnData["status_filter"].(string),
				TaskLimit:    columnData["task_limit"].(int),
				IsActive:     columnData["is_active"].(bool),
				BoardID:      board.ID,
			}

			err = facades.Orm().Query().Create(&column)
			if err != nil {
				facades.Log().Error("Failed to create task board column: " + err.Error())
				return err
			}

			facades.Log().Info("Created task board column: " + column.Name + " for board: " + board.Name)
		}
	}

	return nil
}
