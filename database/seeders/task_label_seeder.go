package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskLabelSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *TaskLabelSeeder) Signature() string {
	return "TaskLabelSeeder"
}

// Run executes the seeder logic.
func (s *TaskLabelSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get projects to associate labels with
	var projects []models.Project
	err := facades.Orm().Query().Find(&projects)
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		facades.Log().Warning("No projects found, skipping task label seeding")
		return nil
	}

	// Create sample task labels
	labels := []map[string]interface{}{
		{
			"name":        "Bug",
			"description": "Software bug or defect",
			"color":       "#EF4444",
			"icon":        "bug",
		},
		{
			"name":        "Feature",
			"description": "New feature or enhancement",
			"color":       "#10B981",
			"icon":        "star",
		},
		{
			"name":        "Improvement",
			"description": "Improvement to existing functionality",
			"color":       "#3B82F6",
			"icon":        "arrow-up",
		},
		{
			"name":        "Documentation",
			"description": "Documentation updates",
			"color":       "#8B5CF6",
			"icon":        "book",
		},
		{
			"name":        "Design",
			"description": "Design-related tasks",
			"color":       "#F59E0B",
			"icon":        "palette",
		},
		{
			"name":        "Testing",
			"description": "Testing and quality assurance",
			"color":       "#06B6D4",
			"icon":        "test",
		},
		{
			"name":        "Research",
			"description": "Research and investigation",
			"color":       "#84CC16",
			"icon":        "search",
		},
		{
			"name":        "Refactor",
			"description": "Code refactoring",
			"color":       "#F97316",
			"icon":        "refresh",
		},
		{
			"name":        "Security",
			"description": "Security-related tasks",
			"color":       "#DC2626",
			"icon":        "shield",
		},
		{
			"name":        "Performance",
			"description": "Performance optimization",
			"color":       "#6B7280",
			"icon":        "speed",
		},
		{
			"name":        "Urgent",
			"description": "Urgent tasks requiring immediate attention",
			"color":       "#EF4444",
			"icon":        "alert",
		},
		{
			"name":        "Low Priority",
			"description": "Low priority tasks",
			"color":       "#9CA3AF",
			"icon":        "clock",
		},
	}

	// Create labels for each project
	for _, project := range projects {
		for _, labelData := range labels {
			// Check if label already exists for this project
			var existingLabel models.TaskLabel
			err := facades.Orm().Query().Where("name = ? AND project_id = ?", labelData["name"], project.ID).First(&existingLabel)
			if err == nil {
				continue // Label already exists
			}

			label := models.TaskLabel{
				Name:        labelData["name"].(string),
				Description: labelData["description"].(string),
				Color:       labelData["color"].(string),
				Icon:        labelData["icon"].(string),
				ProjectID:   project.ID,
			}

			err = facades.Orm().Query().Create(&label)
			if err != nil {
				facades.Log().Error("Failed to create task label: " + err.Error())
				return err
			}

			facades.Log().Info("Created task label: " + label.Name + " for project: " + project.Name)
		}
	}

	return nil
}
